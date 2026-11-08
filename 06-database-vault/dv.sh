#!/bin/bash
# Oracle Database Vault on orcl3 (Region B): root and PDB PERF, standby ORCL3_STB. Follows the Database Vault Administrator's
# Guide for Oracle AI Database 26ai: chapter 3 (CDB, backup accounts first) and 11.3 (Data Guard: primary first, then standby).
#
#   check              prerequisites and current state on both sites
#   save-privs         what DBA, SCHEDULER_ADMIN and the Data Pump roles hold now: enabling revokes some, disabling does not give them back
#   accounts           four common accounts: C##DVOWNER, C##DVACCTMGR and their break-glass backups
#   enable-root        broker off, CONFIGURE_DV with the backup accounts, utlrp, ENABLE_DV (regular mode), restart as SYSOPER
#   grant-primary      the backup accounts grant DV_OWNER and DV_ACCTMGR to the everyday accounts
#   enable-pdb         CONFIGURE_DV and ENABLE_DV in PERF, close and open it
#   standby            parameters on the standby, restart, apply; broker back on
#   realm <sim|on|status>   mandatory realm on the card and customer tables: simulation first, then enforced
#   auth               Database Vault authorizations that existing jobs need (audit retention)
#   audit              unified audit of realm violations and of Database Vault configuration changes (after the realm exists)
#   rule <sim|on>      CONNECT command rule: BANK only from the application hosts
#   log                what the simulation recorded
#   disable            DISABLE_DV in PERF and the root, restart primary then standby, privileges put back from save-privs
#
# Passwords: everyday accounts in this repository's lab.env (DV_OWNER_PASSWORD, DV_ACCTMGR_PASSWORD); the backup accounts only in
# a break-glass file outside every repository (~/work/lab/breakglass/orcl3-dv.env, mode 600). All of them travel on stdin.
# usage (from the host): ./dv.sh <step>
set -eu -o pipefail
d=$(cd "$(dirname "$0")/.." && pwd); ENVF=$d/lab.env; BG=$HOME/work/lab/breakglass/orcl3-dv.env
P=prm3 S=stb3 PDB=PERF REALM='BANK customer data'
OUT=$d/06-database-vault/results; mkdir -p "$OUT"
ENV='. ~/.bash_profile >/dev/null 2>&1'
. "$ENVF"; [ -f "$BG" ] && . "$BG"
gen() { python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Dv1#'+''.join(secrets.choice(a) for _ in range(16))+'_9')"; }
put() {  # put <file> <variable>: a new random value, kept in that file only, never printed
  local f=$1 v=$2
  grep -q "^$v=" "$f" 2>/dev/null && return 0
  mkdir -p "$(dirname "$f")"; touch "$f"; chmod 600 "$f"; printf "%s='%s'\n" "$v" "$(gen)" >> "$f"
}
run() {  # run <host> <connect line or empty for "/ as sysdba">: SQL on stdin; prints, stops on an unexpected ORA-
  local h=$1 c=${2:-} out
  if [ -z "$c" ]; then out=$(ssh -o BatchMode=yes "oracle@$h" "$ENV; sqlplus -s / as sysdba" 2>&1)
  else out=$({ printf '%s\n' "$c"; cat; } | ssh -o BatchMode=yes "oracle@$h" "$ENV; sqlplus -s -L /nolog" 2>&1); fi
  printf '%s\n' "$out" | mask | { grep -vE '^$|^Connected|^(Session|System) altered' || true; } | cut -c1-140
  if printf '%s\n' "$out" | grep -E 'ORA-[0-9]+|SP2-[0-9]+|PLS-[0-9]+' | grep -vE "${OK_ERR:-^$}" | grep -q .; then echo "STOP: unexpected error above" >&2; exit 1; fi
}
as() { printf 'connect %s/"%s"@//localhost:1521/%s' "$1" "$2" "$3"; }   # as <user> <password> <service>
dg() { ssh -o BatchMode=yes "oracle@$P" "$ENV; dgmgrl -silent / \"$1\"" 2>&1 | { grep -vE '^$|^Connected' || true; } | cut -c1-110; }
mask() { sed -E 's/(identified by )"[^"]*"/\1"********"/Ig'; }
broker_off() {  # FSFO first: with it on, DISABLE CONFIGURATION is refused (ORA-16654)
  dg "disable fast_start failover" | tail -n 1
  dg "disable configuration" | tail -n 1
  dg "show configuration" | grep -qE 'Configuration Status: *$|DISABLED' || dg "show configuration" | grep -q 'DISABLED' || { echo "broker did not disable: stop"; exit 1; }
  trap 'echo "STOPPED with the Region B broker configuration DISABLED: dgmgrl enable configuration, enable fast_start failover" >&2' EXIT
}
broker_on() {
  dg "enable configuration" | tail -n 1
  for i in $(seq 1 30); do dg "show configuration" | grep -q '^SUCCESS' && break; sleep 10; done
  dg "enable fast_start failover" | tail -n 1
  for i in $(seq 1 30); do dg "show configuration" | grep -q '^SUCCESS' && break; sleep 10; done
  dg "show configuration" | tail -n 2; trap - EXIT
}
dv_status() {  # dv_status <host> <container>: ENABLED / DISABLED for "DV ENABLE STATUS"
  printf "set heading off feedback off pages 0\nselect status from cdb_dv_status s join v\$containers c on c.con_id = s.con_id where c.name = '%s' and s.name = 'DV_ENABLE_STATUS';\nexit\n" "$2" \
    | ssh -o BatchMode=yes "oracle@$1" "$ENV; sqlplus -s / as sysdba" | tr -d ' \t' | grep -E '^[A-Z]+$' | head -n 1
}
apply_caught_up() {  # the standby has applied everything the primary has generated so far
  for i in $(seq 1 30); do dg "show database 'ORCL3_STB'" | grep -q 'Apply Lag: *0 seconds' && return 0; sleep 10; done
  echo "standby apply did not catch up: stop"; exit 1
}
showtrans() { "$d/../oracle-ha-dr-failover-lab/tests/gg.sh" $P GG_B "send extract extb, showtrans" | tail -n 1 | cut -c1-60; }

case ${1:?step} in
check)
  for h in $P $S; do
    echo "== $h"
    run $h <<'SQL'
set lines 140 pages 50 feedback off
col name for a32
col value for a20
select db_unique_name, database_role, open_mode from v$database;
select name, value from v$parameter where name in ('os_roles', 'remote_os_roles', 'remote_login_passwordfile', 'sql92_security') order by 1;
col description for a30
select c.name con, s.name, s.status from cdb_dv_status s join v$containers c on c.con_id = s.con_id where c.name in ('CDB$ROOT', 'PERF') order by 1, 2;
SQL
  done
  dg "show configuration" | tail -n 3
  ;;
save-privs)
  run $P <<SQL | tee "$OUT/privs-before-dv.txt"
set lines 140 pages 1000 feedback off heading off
select 'CON ' || con_id || ' ' || grantee || ' ' || privilege || ' ' || admin_option from cdb_sys_privs
 where grantee in ('DBA', 'SCHEDULER_ADMIN', 'IMP_FULL_DATABASE', 'EXP_FULL_DATABASE', 'DATAPUMP_IMP_FULL_DATABASE', 'DATAPUMP_EXP_FULL_DATABASE')
   and con_id in (1, (select con_id from v\$containers where name = 'PERF')) order by 1;
SQL
  echo "saved $(grep -c '^CON' "$OUT/privs-before-dv.txt") privileges"
  ;;
accounts)
  put "$ENVF" DV_OWNER_PASSWORD; put "$ENVF" DV_ACCTMGR_PASSWORD; put "$BG" DV_OWNER_BACKUP_PASSWORD; put "$BG" DV_ACCTMGR_BACKUP_PASSWORD
  . "$ENVF"; . "$BG"
  OK_ERR='ORA-02379' run $P <<SQL
create profile c##dv_profile limit failed_login_attempts 5 password_lock_time 1 password_life_time 90 password_grace_time 5 password_reuse_max 20 password_reuse_time 365 password_verify_function ora12c_strong_verify_function sessions_per_user 5 inactive_account_time 120 container = all;
-- break-glass accounts: no inactivity lock, or the only way back in would lock itself (assessment ACCEPT U10)
create profile c##dv_breakglass_profile limit failed_login_attempts 5 password_lock_time 1 password_life_time 90 password_grace_time 5 password_reuse_max 20 password_reuse_time 365 password_verify_function ora12c_strong_verify_function sessions_per_user 2 inactive_account_time unlimited container = all;
declare
  procedure mk(u varchar2, p varchar2) is n number;
  begin
    select count(*) into n from dba_users where username = upper(u);
    if n = 0 then
      execute immediate 'create user ' || u || ' identified by "' || p || '" profile c##dv_profile container = all';
      execute immediate 'grant create session, set container to ' || u || ' container = all';
    end if;
  end;
begin
  mk('c##dvowner', '$DV_OWNER_PASSWORD');
  mk('c##dvacctmgr', '$DV_ACCTMGR_PASSWORD');
  mk('c##dvowner_backup', '$DV_OWNER_BACKUP_PASSWORD');
  mk('c##dvacctmgr_backup', '$DV_ACCTMGR_BACKUP_PASSWORD');
end;
/
alter user c##dvowner_backup profile c##dv_breakglass_profile container = all;
alter user c##dvacctmgr_backup profile c##dv_breakglass_profile container = all;
set lines 120 feedback off
select username, account_status, profile from dba_users where username like 'C##DV%' order by 1;
SQL
  stat -c '%a %n' "$BG"
  ;;
enable-root)
  [ "$(dv_status $P CDB\$ROOT)" = TRUE ] && { echo "already enabled in the root"; exit 0; }
  showtrans
  broker_off
  run $P <<'SQL'
begin
  configure_dv(dvowner_uname => 'c##dvowner_backup', dvacctmgr_uname => 'c##dvacctmgr_backup', force_local_dvowner => false);
end;
/
@?/rdbms/admin/utlrp.sql
SQL
  run $P "$(as c##dvowner_backup "$DV_OWNER_BACKUP_PASSWORD" orcl3.rac)" <<'SQL'
exec dbms_macadm.enable_dv
SQL
  echo "restart as SYSOPER"
  ssh -o BatchMode=yes "oracle@$P" "$ENV; printf 'shutdown immediate\nstartup\nexit\n' | sqlplus -s / as sysoper" | tail -n 4
  run $P <<'SQL'
set lines 120 feedback off
select con_id, name, status from cdb_dv_status where con_id = 1;
SQL
  echo "broker stays disabled until the standby step"; trap - EXIT
  ;;
grant-primary)
  run $P "$(as c##dvowner_backup "$DV_OWNER_BACKUP_PASSWORD" orcl3.rac)" <<'SQL'
grant dv_owner to c##dvowner with admin option container = all;
SQL
  run $P "$(as c##dvacctmgr_backup "$DV_ACCTMGR_BACKUP_PASSWORD" orcl3.rac)" <<'SQL'
grant dv_acctmgr to c##dvacctmgr with admin option container = all;
SQL
  run $P <<'SQL'
set lines 120 feedback off
select grantee, granted_role, admin_option, common from dba_role_privs where granted_role in ('DV_OWNER', 'DV_ACCTMGR') order by 2, 1;
SQL
  ;;
enable-pdb)
  [ "$(dv_status $P $PDB)" = TRUE ] && { echo "already enabled in $PDB"; exit 0; }
  run $P <<SQL
alter session set container = $PDB;
begin
  configure_dv(dvowner_uname => 'c##dvowner_backup', dvacctmgr_uname => 'c##dvacctmgr_backup', force_local_dvowner => false);
end;
/
SQL
  run $P "$(as c##dvowner_backup "$DV_OWNER_BACKUP_PASSWORD" perf.rac)" <<'SQL'
exec dbms_macadm.enable_dv
SQL
  run $P <<SQL
alter pluggable database $PDB close immediate;
alter pluggable database $PDB open;
set lines 120 feedback off
select c.name con, s.name, s.status from cdb_dv_status s join v\$containers c on c.con_id = s.con_id where c.name in ('CDB\$ROOT', 'PERF') order by 1, 2;
SQL
  ;;
standby)
  run $S <<'SQL'
set lines 120 feedback off
col name for a30
col value for a20
select name, value from v$parameter where name in ('os_roles', 'remote_os_roles', 'remote_login_passwordfile', 'sql92_security') order by 1;
SQL
  # the parameters already have the values chapter 11.3 asks for on both sites (assessment checks them); restart so the
  # standby picks up the Database Vault dictionary that redo has brought
  dg "enable configuration" | tail -n 1
  apply_caught_up
  ssh -o BatchMode=yes "root@$S" 'systemctl restart oracle-db'
  broker_on
  run $S <<'SQL'
set lines 120 feedback off
select c.name con, s.name, s.status from cdb_dv_status s join v$containers c on c.con_id = s.con_id where c.name in ('CDB$ROOT', 'PERF') order by 1, 2;
SQL
  ;;
realm)
  mode=${2:?sim, on or status}
  case $mode in sim) en=DBMS_MACUTL.G_SIMULATION ;; on) en=DBMS_MACUTL.G_YES ;; esac
  if [ "$mode" = status ]; then
    run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" perf.rac)" <<'SQL'
set lines 140 pages 40 feedback off
col name for a26
col object_name for a16
col grantee for a14
select name, enabled, realm_type from dba_dv_realm where name = 'BANK customer data';
select owner, object_name from dba_dv_realm_object where realm_name = 'BANK customer data';
select grantee, auth_options from dba_dv_realm_auth where realm_name = 'BANK customer data';
SQL
    exit 0
  fi
  OK_ERR='ORA-47240|ORA-47280|ORA-47260|ORA-06512' run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" perf.rac)" <<SQL
begin
  begin
    dbms_macadm.create_realm(realm_name => '$REALM', description => 'Card numbers and customer identity: the application only',
      enabled => $en, audit_options => null, realm_type => dbms_macadm.mandatory_realm);
  exception when others then
    if sqlcode != -47240 then raise; end if;   -- ORA-47240, exists: change its mode only
    dbms_macadm.update_realm(realm_name => '$REALM', description => 'Card numbers and customer identity: the application only',
      enabled => $en, audit_options => null, realm_type => dbms_macadm.mandatory_realm);
  end;
end;
/
exec dbms_macadm.add_object_to_realm('$REALM', 'BANK', 'CARDS', 'TABLE')
exec dbms_macadm.add_object_to_realm('$REALM', 'BANK', 'CUSTOMERS', 'TABLE')
exec dbms_macadm.add_object_to_realm('$REALM', 'BANK', 'ACCOUNTS', 'TABLE')
-- BANK owns the data and is its application account: realm owner, so it can also grant access to others in the realm.
-- SEC_ADMIN reads the region view built on these tables.
exec dbms_macadm.add_auth_to_realm('$REALM', 'BANK', null, dbms_macutl.g_realm_auth_owner)
exec dbms_macadm.add_auth_to_realm('$REALM', 'SEC_ADMIN', null, dbms_macutl.g_realm_auth_participant)
-- analysts reach cards through their role, and VPD then limits them to their region
exec dbms_macadm.add_auth_to_realm('$REALM', 'CARD_ANALYST', null, dbms_macutl.g_realm_auth_participant)
set lines 120 feedback off
select name, enabled, realm_type from dba_dv_realm where name = '$REALM';
SQL
  ;;
auth)
  # The audit retention job (04-auditing/02_retention.sh) runs as AUDIT_MGR in PERF with the AUDIT_ADMIN role: with Database
  # Vault on, that role needs a Database Vault authorization or the job fails. (orcl3 has no root retention job.)
  run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" perf.rac)" <<'SQL'
exec dbms_macadm.authorize_audit_admin('AUDIT_MGR')
set lines 120 feedback off
col grantee for a20
select * from dba_dv_audit_admin_auth;
SQL
  ;;
audit)
  # Realm violations and every Database Vault configuration change, in the unified trail and so in syslog too (S4).
  # Creating a policy needs an authorized audit administrator: SYS is authorized for these statements only, then not again.
  OK_ERR='ORA-47897|ORA-06512' run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" perf.rac)" <<'SQL'
exec dbms_macadm.authorize_audit_admin('SYS')
SQL
  OK_ERR='ORA-46358|ORA-46350' run $P <<SQL
alter session set container = $PDB;
create audit policy dv_bank_realm actions component = dv realm violation on "$REALM";
audit policy dv_bank_realm;
create audit policy dv_bank_login actions component = dv rule set failure on "BANK login";
audit policy dv_bank_login;
audit policy ora_dv_schema_changes;
set lines 120 feedback off
select policy_name, enabled_option from audit_unified_enabled_policies where policy_name in ('DV_BANK_REALM', 'DV_BANK_LOGIN', 'ORA_DV_SCHEMA_CHANGES');
SQL
  run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" perf.rac)" <<'SQL'
exec dbms_macadm.unauthorize_audit_admin('SYS')
SQL
  ;;
rule)
  # A leaked BANK password from anywhere else is refused at login: BANK may connect only from the database hosts of
  # Region B (the application runs there in this lab) and through bequeath. Simulation first, like the realm.
  mode=${2:?sim or on}; case $mode in sim) en=DBMS_MACUTL.G_SIMULATION ;; on) en=DBMS_MACUTL.G_YES ;; esac
  OK_ERR='ORA-47320|ORA-47100|ORA-47340|ORA-06512' run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" perf.rac)" <<SQL
begin
  begin
    dbms_macadm.create_rule('BANK from application hosts',
      'sys_context(''userenv'', ''ip_address'') is null or sys_context(''userenv'', ''ip_address'') in (''127.0.0.1'', ''192.168.106.10'', ''192.168.107.10'')');
  exception when others then if sqlcode != -47320 then raise; end if; end;   -- ORA-47320: exists
  begin
    dbms_macadm.create_rule_set(rule_set_name => 'BANK login', description => 'BANK only from the application hosts',
      enabled => dbms_macutl.g_yes, eval_options => dbms_macutl.g_ruleset_eval_all, audit_options => null,
      fail_options => dbms_macutl.g_ruleset_fail_show, fail_message => 'BANK may only connect from an application host',
      fail_code => 20461, handler_options => dbms_macutl.g_ruleset_handler_off, handler => null, is_static => false);
    dbms_macadm.add_rule_to_rule_set('BANK login', 'BANK from application hosts');
  exception when others then if sqlcode != -47340 then raise; end if; end;
end;
/
begin
  dbms_macadm.create_connect_command_rule(user_name => 'BANK', rule_set_name => 'BANK login', enabled => $en, scope => dbms_macutl.g_scope_local);
exception when others then
  if sqlcode != -47100 then raise; end if;   -- ORA-47100: exists
  dbms_macadm.update_connect_command_rule(user_name => 'BANK', rule_set_name => 'BANK login', enabled => $en, scope => dbms_macutl.g_scope_local);
end;
/
set lines 120 feedback off
col command for a10
col object_owner for a10
select command, object_owner, rule_set_name, enabled from dba_dv_command_rule where command = 'CONNECT';
SQL
  ;;
log)
  run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" perf.rac)" <<'SQL' | tee "$OUT/simulation-log.txt"
set lines 160 pages 200 feedback off
col username for a14
col command for a12
col object for a24
col violation_type for a22
col count for 99999
select username, command, object_owner || '.' || object_name object, violation_type, count(*) count
from dba_dv_simulation_log group by username, command, object_owner, object_name, violation_type order by 5 desc;
SQL
  ;;
disable)
  showtrans
  broker_off
  run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" perf.rac)" <<'SQL'
exec dbms_macadm.disable_dv
SQL
  run $P <<SQL
alter pluggable database $PDB close immediate;
alter pluggable database $PDB open;
SQL
  run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" orcl3.rac)" <<'SQL'
exec dbms_macadm.disable_dv
SQL
  ssh -o BatchMode=yes "oracle@$P" "$ENV; printf 'shutdown immediate\nstartup\nexit\n' | sqlplus -s / as sysoper" | tail -n 2
  dg "enable configuration" | tail -n 1
  apply_caught_up
  ssh -o BatchMode=yes "root@$S" 'systemctl restart oracle-db'
  broker_on
  echo "privileges to give back: compare $OUT/privs-before-dv.txt with the current list (save-privs again, diff)"
  ;;
*) echo "unknown step"; exit 2 ;;
esac
