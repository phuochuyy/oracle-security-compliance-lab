#!/bin/bash
# What Database Vault changes, tested one by one on orcl3 / PERF with the realm and the connect rule enforced.
# Temporary users are created by the account manager and dropped at the end; passwords on stdin only.
# usage (from the host): ./verify.sh
set -u
d=$(cd "$(dirname "$0")/.." && pwd); . "$d/lab.env"; . "$d/../oracle-performance-tuning-lab/lab.env"
ENV='. ~/.bash_profile >/dev/null 2>&1'
gen() { python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Tv1#'+''.join(secrets.choice(a) for _ in range(14))+'_9')"; }
sysq() { { echo "alter session set container = perf;"; echo "set heading off feedback off pages 0 lines 150"; cat; echo exit; } | ssh -o BatchMode=yes oracle@prm3 "$ENV; sqlplus -s / as sysdba" 2>&1 | grep -vE '^$|Session altered|^\*|^ERROR at|Help:' | sed -E 's/(identified by )"[^"]*"/\1"********"/I' | cut -c1-110; }
asu() {  # asu <host> <user> <password>: SQL on stdin, connected to PERF through prm3's listener from <host>
  { printf 'connect %s/"%s"@//prm3.rac:1521/perf.rac\n' "$2" "$3"; echo "set heading off feedback off pages 0 lines 150"; cat; echo exit; } \
    | ssh -o BatchMode=yes "oracle@$1" "$ENV; sqlplus -s -L /nolog" 2>&1 | grep -vE '^$|^Connected|^\*|^ERROR at|Help:' | sed -E 's/(identified by )"[^"]*"/\1"********"/I' | cut -c1-110
}
pa=$(gen)
echo "== 1. SYS reads card and customer data"
sysq <<'SQL'
select 'cards: ' || count(*) from bank.cards;
select 'customers: ' || count(*) from bank.customers;
select 'transactions (not in the realm): ' || count(*) from bank.transactions where rownum <= 10;
SQL
echo "== 2. C##DVOWNER, the security administrator, reads card data"
asu prm3 c##dvowner "$DV_OWNER_PASSWORD" <<'SQL'
select 'cards: ' || count(*) from bank.cards;
SQL
echo "== 3. BANK from an application host (prm3), and from prm1"
asu prm3 bank "$BANK_PASSWORD" <<'SQL'
select 'BANK on prm3, cards: ' || count(*) from bank.cards;
SQL
asu prm1 bank "$BANK_PASSWORD" <<'SQL'
select 'BANK from prm1 got in' from dual;
SQL
echo "== 4. account management: SYS, then C##DVACCTMGR, creates a user"
sysq <<SQL
create user dv_test_sys identified by "$pa";
SQL
asu prm3 c##dvacctmgr "$DV_ACCTMGR_PASSWORD" <<SQL
create user analyst_dv identified by "$pa";
select 'created by the account manager: ' || username from dba_users where username = 'ANALYST_DV';
SQL
echo "== 5. an analyst of the NORTH region: role through the realm, rows through VPD"
sysq <<'SQL'
grant create session to analyst_dv;
grant card_analyst to analyst_dv;
insert into sec_admin.staff_region (username, region) values ('ANALYST_DV', 'NORTH');
commit;
SQL
asu prm3 bank "$BANK_PASSWORD" <<'SQL'
grant select on bank.cards to analyst_dv;
SQL
asu prm3 analyst_dv "$pa" <<'SQL'
select 'analyst sees cards: ' || count(*) from bank.cards;
SQL
echo "== 6. cleanup of the test user, by the account manager"
sysq <<'SQL'
delete from sec_admin.staff_region where username = 'ANALYST_DV';
commit;
SQL
asu prm3 c##dvacctmgr "$DV_ACCTMGR_PASSWORD" <<'SQL'
drop user analyst_dv cascade;
select 'left: ' || count(*) from dba_users where username in ('ANALYST_DV', 'DV_TEST_SYS');
SQL
echo "== 7. realm violations and rule failures in the unified audit trail (last 30 minutes), read by the auditor"
echo "SYS:"; sysq <<'SQL'
select count(*) from unified_audit_trail where rownum = 1;
SQL
echo "SEC_AUDITOR (AUDIT_VIEWER, authorized by the Database Vault owner):"
asu prm3 sec_auditor "$SEC_AUDITOR_PASSWORD" <<'SQL'
select rpad(dbusername, 14) || rpad(nvl(dv_action_name, action_name), 30) || rpad(nvl(dv_rule_set_name, ' '), 14) || dv_return_code || ' ' || count(*)
from unified_audit_trail where event_timestamp > systimestamp - interval '30' minute and (dv_action_name is not null or unified_audit_policies like '%DV_BANK_REALM%')
group by dbusername, nvl(dv_action_name, action_name), dv_rule_set_name, dv_return_code;
SQL
