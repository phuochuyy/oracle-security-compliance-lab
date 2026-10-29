#!/bin/bash
# Privilege Analysis in SECPDB (PCI-DSS 7.2: least privilege, proven by use, not by assumption).
#   start    create + enable a database-wide capture (all users except SYS) in SECPDB
#   work     a reporting workload as REPORT_RO: the three reports the role exists for (branch balances,
#            monthly transaction volume, customers per segment) — no report needs card numbers
#   stop     disable the capture, generate the results, print used vs unused privileges of REPORT_RO
# The capture only records; it grants or revokes nothing. REPORT_RO and its role BANK_READ are defined
# as code in the automation lab (users.yml) — a change of grants belongs there, not in a manual REVOKE.
# A real capture runs for a full business cycle (month end included); this one covers one run of the reports.
# usage (from the host): ./04_privilege_analysis.sh start | work | stop
set -eu
H=$(cd "$(dirname "$0")/.." && pwd)
ENV=". ~/.bash_profile >/dev/null 2>&1"
sql() { ssh -o BatchMode=yes oracle@prm1 "$ENV; sqlplus -s / as sysdba"; }

case $1 in
start)
  sql <<'SQL' | grep -E "completed|ORA-"
alter session set container = secpdb;
begin
  for c in (select name from dba_priv_captures where name = 'SEC_LAB_CAPTURE') loop
    begin dbms_privilege_capture.disable_capture(c.name); exception when others then null; end;
    dbms_privilege_capture.drop_capture(c.name);
  end loop;
  dbms_privilege_capture.create_capture(name => 'SEC_LAB_CAPTURE', type => dbms_privilege_capture.g_database,
                                        description => 'security lab: least privilege of SECPDB users');
  dbms_privilege_capture.enable_capture('SEC_LAB_CAPTURE');
end;
/
SQL
  ;;
work)
  # password of REPORT_RO from the automation lab's vault, sent on stdin
  pw=$(cd ~/work/oracle-dba-automation-cdc/01-ansible && ~/.venvs/dba/bin/ansible-vault view group_vars/all/vault.yml \
       | ~/.venvs/dba/bin/python -c "import sys,yaml; print(yaml.safe_load(sys.stdin)['vault_user_passwords']['report_ro'])")
  # the connect line (with the password) and the reports go on one stdin stream: a pipe plus a heredoc on the
  # same command would let the heredoc win and the password never arrive (first run: ORA-01017)
  { printf 'connect report_ro/"%s"@//prm1.rac:1521/secpdb_app.rac\n' "$pw"; cat <<'SQL'
set lines 120 pages 50 feedback on
prompt == report 1: balances per branch
select b.branch_code, count(*) accounts, round(sum(a.balance)) balance
  from bank.accounts a join bank.customers c on c.customer_id = a.customer_id
  join bank.branches b on b.branch_id = c.branch_id group by b.branch_code order by 3 desc fetch first 5 rows only;
prompt == report 2: transactions per month (last 6)
select to_char(trunc(txn_ts, 'MM'), 'YYYY-MM') month, count(*) txns, round(sum(amount)) amount
  from bank.transactions where txn_ts >= add_months(trunc(sysdate, 'MM'), -6) group by trunc(txn_ts, 'MM') order by 1;
prompt == report 3: customers per segment
select segment, count(*) customers from bank.customers group by segment order by 2 desc;
exit
SQL
  } | ssh -o BatchMode=yes oracle@prm1 "$ENV; sqlplus -s /nolog"
  ;;
stop)
  sql <<'SQL'
set lines 200 pages 80 feedback off
alter session set container = secpdb;
exec dbms_privilege_capture.disable_capture('SEC_LAB_CAPTURE')
exec dbms_privilege_capture.generate_result('SEC_LAB_CAPTURE')
col grantee for a12
col privilege for a40
col via for a12
prompt == used by REPORT_RO (object privileges, through which role)
select distinct o.obj_priv || ' ' || o.object_owner || '.' || o.object_name privilege, o.used_role via
  from dba_used_objprivs o where o.capture = 'SEC_LAB_CAPTURE' and o.username = 'REPORT_RO' order by 1;
prompt == used by REPORT_RO (system privileges)
select distinct sys_priv privilege, used_role via from dba_used_sysprivs
 where capture = 'SEC_LAB_CAPTURE' and username = 'REPORT_RO' order by 1;
prompt == granted to REPORT_RO but not used
select distinct o.obj_priv || ' ' || o.object_owner || '.' || o.object_name privilege, o.rolename via
  from dba_unused_objprivs o where o.capture = 'SEC_LAB_CAPTURE' and o.username = 'REPORT_RO' order by 1;
select distinct sys_priv privilege, rolename via from dba_unused_sysprivs
 where capture = 'SEC_LAB_CAPTURE' and username = 'REPORT_RO' order by 1;
prompt == other users during the capture: privileges used
select username grantee, count(distinct nvl(sys_priv, obj_priv || ' ' || object_owner || '.' || object_name)) used_privs
  from dba_used_privs where capture = 'SEC_LAB_CAPTURE' group by username order by 1;
exit
SQL
  ;;
esac
