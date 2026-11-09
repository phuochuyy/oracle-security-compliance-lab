#!/bin/bash
# What Database Vault changes, tested one by one with the realm and the connect rule enforced.
#   DV_REGION=B (default): orcl3 / PERF on prm3; the foreign host is prm1
#   DV_REGION=A          : RAC orcl / SECPDB on prm1; the foreign host is prm3
# Temporary users are created by the account manager and dropped at the end; passwords on stdin only.
# usage (from the host): [DV_REGION=A] ./verify.sh
set -u
d=$(cd "$(dirname "$0")/.." && pwd); . "$d/lab.env"
case ${DV_REGION:-B} in
B) . "$d/../oracle-performance-tuning-lab/lab.env"    # BANK of PERF
   H=prm3 FOREIGN=prm1 PDB=perf SVC=prm3.rac:1521/perf.rac ;;
A) H=prm1 FOREIGN=prm3 PDB=secpdb SVC=prm1.rac:1521/secpdb.rac
   DV_OWNER_PASSWORD=$DV_OWNER_PASSWORD_A DV_ACCTMGR_PASSWORD=$DV_ACCTMGR_PASSWORD_A SEC_AUDITOR_PASSWORD=$SEC_AUDITOR_PASSWORD_A ;;
esac
ENV='. ~/.bash_profile >/dev/null 2>&1'
gen() { python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Tv1#'+''.join(secrets.choice(a) for _ in range(14))+'_9')"; }
sysq() { { echo "alter session set container = $PDB;"; echo "set heading off feedback off pages 0 lines 150"; cat; echo exit; } | ssh -o BatchMode=yes oracle@$H "$ENV; sqlplus -s / as sysdba" 2>&1 | grep -vE '^$|Session altered|^\*|^ERROR at|Help:' | sed -E 's/(identified by )"[^"]*"/\1"********"/I' | cut -c1-110; }
asu() {  # asu <host> <user> <password>: SQL on stdin, connected to the PDB through its node's listener, from <host>
  { printf 'connect %s/"%s"@//%s\n' "$2" "$3" "$SVC"; echo "set heading off feedback off pages 0 lines 150"; cat; echo exit; } \
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
asu $H c##dvowner "$DV_OWNER_PASSWORD" <<'SQL'
select 'cards: ' || count(*) from bank.cards;
SQL
if [ "${DV_REGION:-B}" = B ]; then
echo "== 3. BANK from an application host ($H), and from $FOREIGN"
asu $H bank "$BANK_PASSWORD" <<SQL
select 'BANK on $H, cards: ' || count(*) from bank.cards;
SQL
asu $FOREIGN bank "$BANK_PASSWORD" <<SQL
select 'BANK from $FOREIGN got in' from dual;
SQL
else
# BANK and SEC_ADMIN are schema-only in SECPDB; REPORT_RO's password is in the automation vault. The rule set is tested
# through a temporary account bound to the same rule set by the DV owner, from prm1 and from prm3, then removed.
echo "== 3. the connect rule set 'BANK login', through a temporary account APP_DV, from $H and from $FOREIGN"
sysq <<'SQL'
select 'BANK, SEC_ADMIN authentication: ' || listagg(username || '=' || authentication_type, ', ') within group (order by 1) from dba_users where username in ('BANK', 'SEC_ADMIN');
SQL
asu $H c##dvacctmgr "$DV_ACCTMGR_PASSWORD" <<SQL
create user app_dv identified by "$pa";
SQL
sysq <<'SQL'
grant create session to app_dv;
SQL
asu $H c##dvowner "$DV_OWNER_PASSWORD" <<'SQL'
exec dbms_macadm.create_connect_command_rule(user_name => 'APP_DV', rule_set_name => 'BANK login', enabled => dbms_macutl.g_yes, scope => dbms_macutl.g_scope_local)
SQL
asu $H app_dv "$pa" <<SQL
select 'APP_DV from $H got in' from dual;
SQL
asu $FOREIGN app_dv "$pa" <<SQL
select 'APP_DV from $FOREIGN got in' from dual;
SQL
asu $H c##dvowner "$DV_OWNER_PASSWORD" <<'SQL'
exec dbms_macadm.delete_connect_command_rule(user_name => 'APP_DV', scope => dbms_macutl.g_scope_local)
SQL
asu $H c##dvacctmgr "$DV_ACCTMGR_PASSWORD" <<'SQL'
drop user app_dv cascade;
SQL
fi
echo "== 4. account management: SYS, then C##DVACCTMGR, creates a user"
sysq <<SQL
create user dv_test_sys identified by "$pa";
SQL
asu $H c##dvacctmgr "$DV_ACCTMGR_PASSWORD" <<SQL
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
if [ "${DV_REGION:-B}" = B ]; then
asu $H bank "$BANK_PASSWORD" <<'SQL'
grant select on bank.cards to analyst_dv;
SQL
else   # the realm owner BANK cannot log in here: the grant is planned work, in a change window
"$(dirname "$0")/dv.sh" window open "verify.sh: grant on CARDS to a test analyst" | tail -n 1
sysq <<'SQL'
grant select on bank.cards to analyst_dv;
SQL
"$(dirname "$0")/dv.sh" window close | tail -n 1
fi
asu $H analyst_dv "$pa" <<'SQL'
select 'analyst sees cards: ' || count(*) from bank.cards;
SQL
echo "== 6. cleanup of the test user, by the account manager"
sysq <<'SQL'
delete from sec_admin.staff_region where username = 'ANALYST_DV';
commit;
SQL
asu $H c##dvacctmgr "$DV_ACCTMGR_PASSWORD" <<'SQL'
drop user analyst_dv cascade;
select 'left: ' || count(*) from dba_users where username in ('ANALYST_DV', 'DV_TEST_SYS', 'APP_DV');
SQL
echo "== 7. realm violations and rule failures in the unified audit trail (last 30 minutes), read by the auditor"
echo "SYS:"; sysq <<'SQL'
select count(*) from unified_audit_trail where rownum = 1;
SQL
echo "SEC_AUDITOR (AUDIT_VIEWER, authorized by the Database Vault owner):"
asu $H sec_auditor "$SEC_AUDITOR_PASSWORD" <<'SQL'
select rpad(dbusername, 14) || rpad(nvl(dv_action_name, action_name), 30) || rpad(nvl(dv_rule_set_name, ' '), 14) || dv_return_code || ' ' || count(*)
from unified_audit_trail where event_timestamp > systimestamp - interval '30' minute and (dv_action_name is not null or unified_audit_policies like '%DV_BANK_REALM%')
group by dbusername, nvl(dv_action_name, action_name), dv_rule_set_name, dv_return_code;
SQL
