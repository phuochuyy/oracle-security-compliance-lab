#!/bin/bash
# Data Redaction on BANK.CARDS.PAN (PCI-DSS 3.4.1: show at most the first 6 / last 4 digits).
# Full PAN only for sessions with the role CARD_FULL_VIEW enabled; everybody else sees ************1234.
# Test users: ANALYST2 (SELECT on CARDS), FRAUD_OPS (SELECT + CARD_FULL_VIEW). Both dropped at the end.
# Also shows what redaction does NOT do: the WHERE clause still sees the real value.
# Since VPD (06_vpd.sh) an analyst sees only the cards of their region: both test users get NORTH, so redaction is shown
# on rows the row policy lets through (the first version after VPD saw 0 rows and stopped; see notes/worklog.md).
# With Database Vault on in SECPDB (06-database-vault): the account manager creates and drops the test users, and the
# grants on the realm's CARDS table run inside a change window opened by the Database Vault owner, closed at the end.
# usage (from the host): ./03_redaction.sh
set -eu
. "$(dirname "$0")/../06-database-vault/dv_helpers.sh"
DV=0; dv_on prm1 SECPDB && DV=1
ENV=". ~/.bash_profile >/dev/null 2>&1"
sql() { ssh -o BatchMode=yes oracle@prm1 "$ENV; sqlplus -s / as sysdba" 2>&1 | grep -vE "^$"; }
gen() { python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Ab12'+''.join(secrets.choice(a) for _ in range(12))+'#_')"; }
pa=$(gen) pf=$(gen)
users="create user analyst2 identified by \"$pa\" profile sec_admin_profile;
create user fraud_ops identified by \"$pf\" profile sec_admin_profile;"
if [ $DV = 1 ]; then printf '%s\n' "$users" | dv_users prm1 secpdb.rac | grep -E "ORA-|created" | sed 's/^/account manager: /'; users=""; fi
# connect line on stdin: the password never reaches a command line (the earlier version put it in ssh's and sqlplus's argv)
as() { { printf 'connect %s/"%s"@//prm1.rac:1521/secpdb_app.rac\n' "$1" "$2"; cat; echo exit; } \
  | ssh -o BatchMode=yes oracle@prm1 "$ENV; sqlplus -s -L /nolog" 2>&1 | { grep -vE "^$|^Connected" || true; }; }
cleanup() {  # even when the script stops half-way: region rows, then the change window (its participants must still exist
  set +e     # to be removed), then the test users
  printf 'alter session set container = secpdb;\ndelete from sec_admin.staff_region where username in (%s);\ncommit;\n' "'ANALYST2', 'FRAUD_OPS'" | sql | grep -E "ORA-"
  [ $DV = 1 ] && dv_window prm1 close
  drops="drop user analyst2 cascade;
drop user fraud_ops cascade;"
  if [ $DV = 1 ]; then printf '%s\n' "$drops" | dv_users prm1 secpdb.rac | grep -E "ORA-|dropped" | grep -v ORA-01918 | sed 's/^/account manager: /'
  else printf 'alter session set container = secpdb;\n%s\n' "$drops" | sql | grep -E "ORA-|dropped" | grep -v ORA-01918; fi
}
trap cleanup EXIT
if [ $DV = 1 ]; then
  # under the mandatory realm an object grant alone is not enough: the two test users are realm participants for the test
  dv_window prm1 open "redaction test: test users ANALYST2 and FRAUD_OPS read CARDS" analyst2 fraud_ops
fi

sql <<SQL | grep -E "ORA-|completed|created|succeeded"
alter session set container = secpdb;
-- re-runnable: role and policy are created only the first time (2026-10-29 re-run: ORA-01921, ORA-28069)
declare n number;
begin
  select count(*) into n from dba_roles where role = 'CARD_FULL_VIEW';
  if n = 0 then execute immediate 'create role card_full_view'; end if;
  select count(*) into n from redaction_policies where object_owner = 'BANK' and object_name = 'CARDS';
  if n > 0 then return; end if;
  dbms_redact.add_policy(
    object_schema       => 'BANK',
    object_name         => 'CARDS',
    policy_name         => 'CARDS_PAN_MASK',
    column_name         => 'PAN',
    function_type       => dbms_redact.partial,
    -- 16 digits, no separators: keep the last 4, '*' for positions 1-12
    function_parameters => 'VVVVVVVVVVVVVVVV,VVVVVVVVVVVVVVVV,*,1,12',
    expression          => 'SYS_CONTEXT(''SYS_SESSION_ROLES'', ''CARD_FULL_VIEW'') = ''FALSE''',
    policy_description  => 'PCI-DSS 3.4.1: PAN masked unless CARD_FULL_VIEW is enabled');
end;
/
$users
grant create session to analyst2, fraud_ops;
grant select on bank.cards to analyst2, fraud_ops;
grant card_full_view to fraud_ops;
insert into sec_admin.staff_region (username, region) values ('ANALYST2', 'NORTH');
insert into sec_admin.staff_region (username, region) values ('FRAUD_OPS', 'NORTH');
commit;
SQL

q="set lines 120 feedback off
col pan for a20
select card_id, pan, expiry from bank.cards order by card_id fetch first 3 rows only;"
echo "== ANALYST2 (no role)"; as analyst2 "$pa" <<< "$q"
# FRAUD_OPS gets the full number from the database; this script replaces its middle digits by '#' (not the
# redaction '*') in its own output, so no full PAN ends up in a log or in git, even a synthetic one
echo "== FRAUD_OPS (CARD_FULL_VIEW) — database returns the full PAN, middle digits replaced by # by this script"
as fraud_ops "$pf" <<< "$q" | sed -E 's/\b([0-9]{4})[0-9]{8}([0-9]{4})\b/\1########\2/g'
echo "== ANALYST2: the WHERE clause still uses the real value (redaction is display masking, not access control)"
# the first card the analyst can see (VPD), its real number read by SYS (in the change window when Database Vault is on)
cid=$(as analyst2 "$pa" <<< "set heading off feedback off pages 0
select min(card_id) from bank.cards;" | tr -d ' \t' | grep -E '^[0-9]+$')
real=$(printf "set heading off feedback off\nalter session set container = secpdb;\nselect pan from bank.cards where card_id = $cid;\nexit\n" | sql | grep -E "^[0-9]{16}$")
as analyst2 "$pa" <<< "set feedback off
select count(*) cards_matching_guess from bank.cards where pan like '${real:0:6}%';
select count(*) exact_match from bank.cards where pan = '$real';"
echo "(the guessed values are the BIN of card $cid and the full PAN — run as the analyst, who only sees masks)"

