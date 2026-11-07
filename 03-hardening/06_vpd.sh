#!/bin/bash
# Row-level control on BANK.CARDS with Virtual Private Database. Redaction only hides what is displayed: an analyst can
# still find a card by testing its value in a WHERE clause (03_redaction.sh shows it). Here an analyst only reaches the
# cards of the region assigned to them, for queries and for changes; anyone without an assignment reaches none.
#
#   SEC_ADMIN     schema-only owner of the policy: nobody logs in as it, and the data owner BANK does not own its own control
#   STAFF_REGION  who may see which region; a change to it is audited
#   MY_ACCOUNTS   view: the accounts of the querying user's own region. A VPD predicate runs with the rights of the user who
#                 issues the statement (ORA-28113 otherwise), and analysts should not read ACCOUNTS or CUSTOMERS. A view
#                 runs with its owner's rights, and returns nothing for someone without an assignment
#   BANK          the application account, exempt in the policy function: it needs every row and is not a person
#   SYS, and any holder of EXEMPT ACCESS POLICY, bypass VPD by design: a limit this script prints, not hides
#
# usage (from the host): ./06_vpd.sh <host> <PDB> <service>     e.g. prm1 SECPDB secpdb_app.rac  |  prm3 PERF perf.rac
#                        ./06_vpd.sh <host> <PDB> remove        takes the policy and its objects away
# Safe to run again. Test users have random passwords and are dropped on any exit; passwords travel on stdin only.
# No card number appears in a statement, because statements on CARDS are audited with their text: the WHERE test compares a
# hash of the card number, which behaves the same way, and the other tests use CARD_ID.
set -eu -o pipefail
H=${1:?host} PDB=${2:?PDB} SVC=${3:?service or remove}
ENV='. ~/.bash_profile >/dev/null 2>&1'
ALREADY='ORA-01920|ORA-00955|ORA-28101|ORA-02260|ORA-01408|ORA-01918|ORA-28102|ORA-46358|ORA-46350|ORA-46357|ORA-01432|ORA-01418|ORA-01919|ORA-00942|ORA-01921'
raw() { { echo "alter session set container = $PDB;"; cat; echo exit; } | ssh -o BatchMode=yes "oracle@$H" "$ENV; sqlplus -s / as sysdba" 2>&1; }
sys() {  # sys [pattern of lines to print], SQL on stdin; stops the script on an error not listed in ALREADY
  local out show=${1:-.}
  out=$(raw | { grep -vE '^$|^Session altered' || true; })
  printf '%s\n' "$out" | { grep -E "$show" || true; } | cut -c1-120
  if printf '%s\n' "$out" | grep -E 'ORA-[0-9]+|SP2-[0-9]+|PLS-[0-9]+' | grep -vE "$ALREADY" | grep -q .; then
    echo "STOP: unexpected error above" >&2; exit 1
  fi
}
as_user() {  # as_user <user> <password>, SQL on stdin; errors are printed, they are part of what is being tested
  { printf 'connect %s/"%s"@//%s.rac:1521/%s\n' "$1" "$2" "$H" "$SVC"; cat; echo exit; } \
    | ssh -o BatchMode=yes "oracle@$H" "$ENV; sqlplus -s -L /nolog" 2>&1 | { grep -vE '^$|^Connected' || true; }
}
gen() { python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Ab12'+''.join(secrets.choice(a) for _ in range(12))+'#9')"; }
drop_test_users() {
  raw <<'SQL' >/dev/null 2>&1 || true
delete from sec_admin.staff_region where username like 'ANALYST\_%' escape '\';
commit;
drop user analyst_north cascade;
drop user analyst_south cascade;
drop user analyst_none cascade;
SQL
}

if [ "$SVC" = remove ]; then
  drop_test_users
  sys <<'SQL'
begin dbms_rls.drop_policy('BANK', 'CARDS', 'CARDS_BY_REGION'); exception when others then if sqlcode != -28102 then raise; end if; end;
/
noaudit policy sec_vpd_admin;
drop audit policy sec_vpd_admin;
drop role card_analyst;
drop user sec_admin cascade;
drop index bank.cards_account_ix;
SQL
  exit 0
fi
trap drop_test_users EXIT
drop_test_users

# Objects. SYS creates them in the SEC_ADMIN schema: the account needs no privilege of its own and cannot log in.
sys 'ORA-|PLS-|Errors|created' <<'SQL'
set feedback on
create user sec_admin no authentication default tablespace bank_data quota 8m on bank_data;
create table sec_admin.staff_region (
  username    varchar2(128) constraint staff_region_pk primary key,
  region      varchar2(10)  not null,
  assigned_by varchar2(128) default sys_context('userenv', 'session_user') not null,
  assigned_at date          default sysdate not null);
-- the owner needs these with GRANT OPTION to expose the view to others
grant select on bank.accounts  to sec_admin with grant option;
grant select on bank.customers to sec_admin with grant option;
grant select on bank.branches  to sec_admin with grant option;
create or replace view sec_admin.my_accounts as
  select a.account_id
  from bank.accounts a
  join bank.customers c on c.customer_id = a.customer_id
  join bank.branches b on b.branch_id = c.branch_id
  join sec_admin.staff_region s on s.region = b.region
  where s.username = sys_context('userenv', 'session_user');
create role card_analyst;
grant select on sec_admin.my_accounts to card_analyst;
create or replace function sec_admin.cards_predicate (p_schema varchar2, p_object varchar2) return varchar2
  authid definer
as
begin
  if sys_context('userenv', 'session_user') = 'BANK' then return null; end if;
  return 'account_id in (select account_id from sec_admin.my_accounts)';
end;
/
show errors function sec_admin.cards_predicate
SQL
# a policy whose function is invalid fails every statement on the table with ORA-28110, for BANK as well: check first
valid=$(sys '^(VALID|INVALID)' <<'SQL'
set heading off feedback off pages 0
select status from dba_objects where owner = 'SEC_ADMIN' and object_name = 'CARDS_PREDICATE';
SQL
)
[ "$valid" = VALID ] || { echo "policy function is $valid, stop"; exit 1; }

# Test users, one card and one account of each region
pn=$(gen) ps=$(gen) po=$(gen)
sys 'ORA-' <<SQL
create user analyst_north identified by "$pn";
create user analyst_south identified by "$ps";
create user analyst_none  identified by "$po";
grant create session to analyst_north, analyst_south, analyst_none;
grant select, update on bank.cards to analyst_north, analyst_south, analyst_none;
grant card_analyst to analyst_north, analyst_south, analyst_none;
-- only so that SET AUTOTRACE can show plans and logical reads; the users are dropped at the end
grant select_catalog_role to analyst_north, analyst_south, analyst_none;
merge into sec_admin.staff_region t using (select 'ANALYST_NORTH' u, 'NORTH' r from dual union all select 'ANALYST_SOUTH', 'SOUTH' from dual) s
  on (t.username = s.u) when not matched then insert (username, region) values (s.u, s.r);
commit;
SQL
sample() {  # sample <region>: card_id, account_id and the SHA-256 of the card number of the region's first card
  sys '^[0-9]+ [0-9]+ [0-9A-F]{64}$' <<SQL
set heading off feedback off pages 0 lines 200
select card_id || ' ' || account_id || ' ' || rawtohex(standard_hash(pan, 'SHA256')) from (
  select k.card_id, k.account_id, k.pan from bank.cards k join bank.accounts a on a.account_id = k.account_id
    join bank.customers c on c.customer_id = a.customer_id join bank.branches b on b.branch_id = c.branch_id
  where b.region = '$1' order by k.card_id) where rownum = 1;
SQL
}
read -r card_n acct_n hash_n <<< "$(sample NORTH)"
read -r card_s acct_s hash_s <<< "$(sample SOUTH)"
[ -n "${hash_n:-}" ] && [ -n "${hash_s:-}" ] || { echo "no sample cards found"; exit 1; }

reach() {  # reach <user> <password>
  as_user "$1" "$2" <<SQL | cut -c1-120
set heading off feedback off pages 0 lines 150
select 'cards visible: ' || count(*) from bank.cards;
select 'test of the value of a NORTH card in WHERE, rows: ' || count(*) from bank.cards where standard_hash(pan, 'SHA256') = hextoraw('$hash_n');
select 'test of the value of a SOUTH card in WHERE, rows: ' || count(*) from bank.cards where standard_hash(pan, 'SHA256') = hextoraw('$hash_s');
SQL
}
cost() {  # cost <user> <password> <label>: plan and logical reads of three typical statements
  as_user "$1" "$2" <<SQL | { grep -E 'consistent gets|TABLE ACCESS|INDEX |HASH JOIN|NESTED LOOPS|ORA-|SP2-|^-- ' || true; } | cut -c1-100
set feedback off lines 120 trimout on termout off
-- each statement once first: the gets of a hard parse are not the cost of the policy
select card_id, status from bank.cards where account_id = $acct_s;
select card_id, status from bank.cards where card_id = $card_s;
select count(*) from bank.cards;
set termout on autotrace traceonly
prompt -- $3: cards of one account
select card_id, status from bank.cards where account_id = $acct_s;
prompt -- $3: one card by id
select card_id, status from bank.cards where card_id = $card_s;
prompt -- $3: count of visible cards
select count(*) from bank.cards;
SQL
}

echo "== before the policy: every analyst reaches every card"
echo "-- ANALYST_NORTH"; reach analyst_north "$pn"
cost analyst_south "$ps" "before"

# Policy and audit
sys 'ORA-|completed|created|succeeded' <<'SQL'
set feedback on
begin
  dbms_rls.add_policy(
    object_schema   => 'BANK', object_name => 'CARDS', policy_name => 'CARDS_BY_REGION',
    function_schema => 'SEC_ADMIN', policy_function => 'CARDS_PREDICATE',
    statement_types => 'SELECT, INSERT, UPDATE, DELETE',
    update_check    => TRUE,                        -- a change cannot move a row out of what the user may see
    policy_type     => dbms_rls.context_sensitive); -- the function runs once per session and context, not per statement
end;
/
create audit policy sec_vpd_admin
  actions insert on sec_admin.staff_region, update on sec_admin.staff_region, delete on sec_admin.staff_region,
          execute on sys.dbms_rls;
audit policy sec_vpd_admin;
SQL

echo "== after the policy"
for u in "analyst_north $pn" "analyst_south $ps" "analyst_none $po"; do set -- $u
  echo "-- ${1^^}"; reach "$1" "$2"
done
cost analyst_south "$ps" "after, no index on CARDS.ACCOUNT_ID"

echo "== ANALYST_NORTH changes a card of another region"
as_user analyst_north "$pn" <<SQL | cut -c1-120
set feedback on
update bank.cards set status = status where card_id = $card_s;
rollback;
SQL
echo "== ANALYST_SOUTH moves one of its own cards to an account of another region (check option)"
as_user analyst_south "$ps" <<SQL | { grep -E 'ORA-|updated' || true; } | cut -c1-120
set feedback on
update bank.cards set account_id = $acct_n where card_id = $card_s;
rollback;
SQL
echo "== who bypasses the policy"
sys 'count:|SYS sees' <<'SQL'
set heading off feedback off pages 0
select 'count: ' || count(*) || ' holders of EXEMPT ACCESS POLICY: ' || listagg(grantee, ', ') within group (order by grantee) from dba_sys_privs where privilege = 'EXEMPT ACCESS POLICY';
select 'SYS sees ' || count(*) || ' cards (known limit: VPD does not apply to SYS)' from bank.cards;
SQL

# The predicate, and the foreign key, need this index
sys 'ORA-|created' <<'SQL'
set feedback on
create index bank.cards_account_ix on bank.cards (account_id) online;
exec dbms_stats.gather_table_stats('BANK', 'CARDS', cascade => true, no_invalidate => false)
SQL
cost analyst_south "$ps" "after, with CARDS_ACCOUNT_IX"

echo "== policy in place"
sys 'CARDS' <<'SQL'
set lines 120 heading off feedback off pages 0
select object_owner || '.' || object_name || ' ' || policy_name || ' ' || policy_type || ' enabled=' || enable from dba_policies where policy_name = 'CARDS_BY_REGION';
SQL
