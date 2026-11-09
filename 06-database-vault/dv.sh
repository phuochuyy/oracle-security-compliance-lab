#!/bin/bash
# Oracle Database Vault, both regions. Follows the Database Vault Administrator's Guide for Oracle AI Database 26ai: chapter 3
# (CDB, backup accounts first; 3.2.5 for RAC) and 11.3 (Data Guard: primary first, then standby).
#   DV_REGION=B (default): orcl3 on prm3, PDB PERF, standby ORCL3_STB on stb3
#   DV_REGION=A          : RAC orcl (prm1, prm2), PDB SECPDB, RAC standby orcl_stb (stb1, stb2); restarts through srvctl
#
#   check              prerequisites and current state on both sites
#   save-privs         what DBA, SCHEDULER_ADMIN and the Data Pump roles hold now: enabling revokes some, disabling does not give them back
#   accounts           four common accounts: C##DVOWNER, C##DVACCTMGR and their break-glass backups
#   enable-root        broker off, CONFIGURE_DV with the backup accounts, utlrp, ENABLE_DV (regular mode), restart (B: as SYSOPER,
#                      A: srvctl, every instance)
#   grant-primary      the backup accounts grant DV_OWNER and DV_ACCTMGR to the everyday accounts
#   enable-pdb         CONFIGURE_DV and ENABLE_DV in the PDB, close and open it on every instance
#   standby            parameters on the standby, restart, apply; broker back on
#   realm <sim|on|status>   mandatory realm on the card and customer tables: simulation first, then enforced
#   auth               Database Vault authorizations that existing jobs need (audit retention)
#   auditor            SEC_AUDITOR in the PDB (created by the account manager): AUDIT_VIEWER, authorized to read the trail
#   audit              unified audit of realm violations and of Database Vault configuration changes (after the realm exists)
#   rule <sim|on>      CONNECT command rule: the accounts that log in to the realm's data only from the application hosts
#   window <open|close> <reason>   change window: the DV owner makes SYS a realm owner for planned work (grants, test
#                      users' access, the plaintext check), then takes it back; both changes are in the audit trail
#   log                what the simulation recorded
#   disable            DISABLE_DV in the PDB and the root, restart primary then standby, privileges put back from save-privs
#
# Passwords: everyday accounts in this repository's lab.env (DV_OWNER_PASSWORD, DV_ACCTMGR_PASSWORD, SEC_AUDITOR_PASSWORD; with
# the suffix _A for Region A); the backup accounts only in a break-glass file per database outside every repository
# (~/work/lab/breakglass/orcl3-dv.env, orcl-dv.env, mode 600). All of them travel on stdin.
# usage (from the host): [DV_REGION=A] ./dv.sh <step>
set -eu -o pipefail
d=$(cd "$(dirname "$0")/.." && pwd); ENVF=$d/lab.env; REALM='BANK customer data'
case ${DV_REGION:-B} in
B) P=prm3 S=stb3 PDB=PERF DB=orcl3 SDB=orcl3_stb STBU=ORCL3_STB HOSTC=localhost ROOT_SVC=orcl3.rac PDB_SVC=perf.rac
   GGD=GG_B EXT=extb SFX= BG=$HOME/work/lab/breakglass/orcl3-dv.env OUT=$d/06-database-vault/results INST=
   CONNECT_USERS="BANK" EXTRA_AUTH=""                                                   # BANK is the application account
   APP_IPS="'127.0.0.1', '192.168.106.10', '192.168.107.10'" ;;                      # prm3, stb3
A) P=prm1 S=stb1 PDB=SECPDB DB=orcl SDB=orcl_stb STBU=ORCL_STB HOSTC=prm1.rac ROOT_SVC=orcl.rac PDB_SVC=secpdb.rac
   GGD=GG_A EXT=exta SFX=_A BG=$HOME/work/lab/breakglass/orcl-dv.env OUT=$d/06-database-vault/results/region-a INST=' instances = all'
   # BANK and SEC_ADMIN are schema-only accounts here (no authentication): REPORT_RO is the account that logs in, through role
   # BANK_READ (ACCOUNTS, CUSTOMERS; no grant on CARDS). The connect rule covers both, in case BANK ever gets a password.
   CONNECT_USERS="BANK REPORT_RO" EXTRA_AUTH="BANK_READ"
   APP_IPS="${DV_APP_IPS_A:-}" ;;                    # needed by the rule step only
*) echo "DV_REGION is A or B"; exit 2 ;;
esac
mkdir -p "$OUT"
ENV='. ~/.bash_profile >/dev/null 2>&1'
. "$ENVF"; [ -f "$BG" ] && . "$BG"
# the everyday passwords of this region (Region A keeps its own, suffixed _A, in the same lab.env); reloaded after every
# read of lab.env, which would otherwise bring back Region B's values under the plain names
load_pw() { . "$ENVF"; [ -f "$BG" ] && . "$BG"
  eval "DV_OWNER_PASSWORD=\${DV_OWNER_PASSWORD$SFX:-}; DV_ACCTMGR_PASSWORD=\${DV_ACCTMGR_PASSWORD$SFX:-}; SEC_AUDITOR_PASSWORD=\${SEC_AUDITOR_PASSWORD$SFX:-}"; }
load_pw
need() { local v; for v in "$@"; do [ -n "${!v:-}" ] || { echo "$v is empty for region ${DV_REGION:-B}: stop before any change"; exit 1; }; done; }
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
as() { printf 'connect %s/"%s"@//%s:1521/%s' "$1" "$2" "$HOSTC" "$3"; }   # as <user> <password> <service>
dg() { ssh -o BatchMode=yes "oracle@$P" "$ENV; dgmgrl -silent / \"$1\"" 2>&1 | { grep -vE '^$|^Connected' || true; } | cut -c1-110; }
mask() { sed -E 's/(identified by )"[^"]*"/\1"********"/Ig'; }
broker_off() {  # FSFO first: with it on, DISABLE CONFIGURATION is refused (ORA-16654)
  trap 'echo "STOPPED: the broker configuration of $DB may be DISABLED and FSFO off: dgmgrl enable configuration, enable fast_start failover; srvctl status database" >&2' EXIT
  dg "disable fast_start failover" | tail -n 1
  dg "disable configuration" | tail -n 1
  local c; c=$(dg "show configuration")
  printf '%s\n' "$c" | grep -qE '^ *DISABLED' && printf '%s\n' "$c" | grep -qE 'Fast-Start Failover: *Disabled' || { printf '%s\n' "$c"; echo "broker did not disable: stop"; exit 1; }
}
broker_enable() {  # the broker may not answer yet right after a restart (ORA-16525): retry
  # dgmgrl -silent prints nothing on success: the configuration status tells
  local i; for i in $(seq 1 18); do dg "enable configuration" >/dev/null; dg "show configuration" | grep -qE '^(SUCCESS|WARNING)' && return 0; sleep 10; done
  echo "enable configuration did not succeed: stop"; exit 1
}
broker_on() {
  broker_enable
  for i in $(seq 1 30); do dg "show configuration" | grep -q '^SUCCESS' && break; sleep 10; done
  dg "enable fast_start failover" | tail -n 1
  for i in $(seq 1 30); do dg "show configuration" | grep -q '^SUCCESS' && break; sleep 10; done
  local c; c=$(dg "show configuration"); printf '%s\n' "$c" | tail -n 2
  printf '%s\n' "$c" | grep -q '^SUCCESS' && printf '%s\n' "$c" | grep -qE 'Fast-Start Failover: *Enabled' || { echo "broker not back to SUCCESS with FSFO: stop"; exit 1; }
  trap - EXIT
}
roles_ok() {  # the script's primary and standby hosts still have those roles (Region A has failed over before)
  local r1 r2 q="set heading off feedback off pages 0
select database_role from v\$database;
exit"
  r1=$(printf '%s\n' "$q" | ssh -o BatchMode=yes "oracle@$P" "$ENV; sqlplus -s / as sysdba" | tr -d '\t' | sed 's/ *$//' | grep -m1 -E '[A-Z]')
  r2=$(printf '%s\n' "$q" | ssh -o BatchMode=yes "oracle@$S" "$ENV; sqlplus -s / as sysdba" | tr -d '\t' | sed 's/ *$//' | grep -m1 -E '[A-Z]')
  [ "$r1" = PRIMARY ] && [ "$r2" = "PHYSICAL STANDBY" ] || { echo "$P is '$r1', $S is '$r2': expected PRIMARY / PHYSICAL STANDBY, stop"; exit 1; }
}
dv_status() {  # dv_status <host> <container>: TRUE / FALSE for DV_ENABLE_STATUS
  printf "set heading off feedback off pages 0\nselect status from cdb_dv_status s join v\$containers c on c.con_id = s.con_id where c.name = '%s' and s.name = 'DV_ENABLE_STATUS';\nexit\n" "$2" \
    | ssh -o BatchMode=yes "oracle@$1" "$ENV; sqlplus -s / as sysdba" | tr -d ' \t' | grep -E '^[A-Z]+$' | head -n 1
}
apply_caught_up() {  # the standby has applied everything the primary has generated so far
  local i; for i in $(seq 1 30); do dg "show database '$STBU'" | grep -q 'Apply Lag: *0 seconds' && return 0; sleep 10; done
  echo "standby apply did not catch up: stop"; exit 1
}
showtrans() {  # before the primary stops: no open transaction in the Extract (lab-safety), restart point shown
  local t; t=$("$d/../oracle-ha-dr-failover-lab/tests/gg.sh" $P $GGD "send extract $EXT, showtrans" | tail -n 1)
  echo "$GGD $EXT: $t" | cut -c1-80
  printf '%s' "$t" | grep -q 'No transactions found' || { echo "open transactions in $EXT: stop"; exit 1; }
  local pdb=GGREPL; [ "$DB" = orcl ] && pdb=ORCLPDB2
  printf "set heading off feedback off pages 0\nalter session set container = $pdb;\nselect capture_name || ' required_checkpoint_scn ' || required_checkpoint_scn || ' ' || status from dba_capture;\nexit\n" \
    | ssh -o BatchMode=yes "oracle@$P" "$ENV; sqlplus -s / as sysdba" | grep -v '^$'
}
restart_primary() {  # B: one instance, as SYSOPER (the guide's step). A: every instance of the RAC through Clusterware
  if [ "$DB" = orcl3 ]; then ssh -o BatchMode=yes "oracle@$P" "$ENV; printf 'shutdown immediate\nstartup\nexit\n' | sqlplus -s / as sysoper" | tail -n 4
  else rac_restart $P $DB; gg_a_back; fi
}
restart_standby() {
  if [ "$DB" = orcl3 ]; then ssh -o BatchMode=yes "root@$S" 'systemctl restart oracle-db'
  else rac_restart $S $SDB; fi
}
rac_restart() {  # rac_restart <host> <db>: every instance stopped (-force: DBFS, XAG GG_A and ogg_pathsync depend on the
  # database), then the instance of every active cluster node started again (nodes switched off stay off)
  ssh -o BatchMode=yes "oracle@$1" "$ENV; srvctl stop database -db $2 -stopoption immediate -force" || { echo "srvctl stop failed: stop"; exit 1; }
  local n; for n in $(ssh -o BatchMode=yes "oracle@$1" "$ENV; /u01/app/23.26.0/grid/bin/olsnodes -s" | awk '$2 == "Active" {print $1}'); do
    ssh -o BatchMode=yes "oracle@$1" "$ENV; srvctl start instance -db $2 -node $n" || { echo "instance of $2 on $n did not start: stop"; exit 1; }
  done
  ssh -o BatchMode=yes "oracle@$1" "$ENV; srvctl status database -db $2 -verbose"
}
gg_a_back() {  # GoldenGate of Region A after the primary restarted: service ogg_a, DBFS and XAG up, processes running
  local i
  ssh -o BatchMode=yes "oracle@$P" "$ENV; srvctl start service -db $DB -service ogg_a" 2>&1 | grep -vE 'already running|^$|PRCC-1014|PRCR-1120|CRS-5702' || true
  for i in $(seq 1 30); do
    ssh -o BatchMode=yes "oracle@$P" "$ENV; crsctl stat res xag.GG_A.goldengate" 2>/dev/null | grep -q 'STATE=ONLINE' && break; sleep 10; done
  "$d/../oracle-ha-dr-failover-lab/tests/gg.sh" $P GG_A "info all" | awk '$1 == "EXTRACT" || $1 == "REPLICAT"'
  for i in $("$d/../oracle-ha-dr-failover-lab/tests/gg.sh" $P GG_A "info all" | awk '($1 == "EXTRACT" || $1 == "REPLICAT") && $2 == "ABENDED" {print $1 ":" $3}'); do
    echo "GG_A ${i#*:} ABENDED -> start"; "$d/../oracle-ha-dr-failover-lab/tests/gg.sh" $P GG_A "start ${i%%:*} ${i#*:}" | tail -n 1
  done
}

case ${1:?step} in
check)
  for h in $P $S; do
    echo "== $h"
    run $h <<SQL
set lines 140 pages 50 feedback off
col name for a32
col value for a20
select db_unique_name, database_role, open_mode from v\$database;
select name, value from v\$parameter where name in ('os_roles', 'remote_os_roles', 'remote_login_passwordfile', 'sql92_security') order by 1;
col description for a30
select c.name con, s.name, s.status from cdb_dv_status s join v\$containers c on c.con_id = s.con_id where c.name in ('CDB\$ROOT', '$PDB') order by 1, 2;
SQL
  done
  dg "show configuration" | tail -n 3
  ;;
save-privs)
  [ -s "$OUT/privs-before-dv.txt" ] && [ "${FORCE_SAVE:-0}" != 1 ] && { echo "$OUT/privs-before-dv.txt exists (evidence from before Database Vault): FORCE_SAVE=1 to take it again"; exit 1; }
  run $P <<SQL | tee "$OUT/privs-before-dv.txt"
set lines 140 pages 1000 feedback off heading off
select 'CON ' || con_id || ' ' || grantee || ' ' || privilege || ' ' || admin_option from cdb_sys_privs
 where grantee in ('DBA', 'SCHEDULER_ADMIN', 'IMP_FULL_DATABASE', 'EXP_FULL_DATABASE', 'DATAPUMP_IMP_FULL_DATABASE', 'DATAPUMP_EXP_FULL_DATABASE')
   and con_id in (1, (select con_id from v\$containers where name = '$PDB')) order by 1;
SQL
  echo "saved $(grep -c '^CON' "$OUT/privs-before-dv.txt") privileges"
  ;;
accounts)
  put "$ENVF" DV_OWNER_PASSWORD$SFX; put "$ENVF" DV_ACCTMGR_PASSWORD$SFX; put "$BG" DV_OWNER_BACKUP_PASSWORD; put "$BG" DV_ACCTMGR_BACKUP_PASSWORD
  load_pw; need DV_OWNER_PASSWORD DV_ACCTMGR_PASSWORD DV_OWNER_BACKUP_PASSWORD DV_ACCTMGR_BACKUP_PASSWORD
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
  need DV_OWNER_BACKUP_PASSWORD DV_ACCTMGR_BACKUP_PASSWORD
  roles_ok
  showtrans
  broker_off
  run $P <<'SQL'
begin
  configure_dv(dvowner_uname => 'c##dvowner_backup', dvacctmgr_uname => 'c##dvacctmgr_backup', force_local_dvowner => false);
end;
/
@?/rdbms/admin/utlrp.sql
SQL
  run $P "$(as c##dvowner_backup "$DV_OWNER_BACKUP_PASSWORD" $ROOT_SVC)" <<'SQL'
exec dbms_macadm.enable_dv
SQL
  echo "restart the primary"
  restart_primary
  run $P <<'SQL'
set lines 120 feedback off
select con_id, name, status from cdb_dv_status where con_id = 1;
SQL
  echo "broker stays disabled until the standby step"; trap - EXIT
  ;;
grant-primary)
  run $P "$(as c##dvowner_backup "$DV_OWNER_BACKUP_PASSWORD" $ROOT_SVC)" <<'SQL'
grant dv_owner to c##dvowner with admin option container = all;
SQL
  run $P "$(as c##dvacctmgr_backup "$DV_ACCTMGR_BACKUP_PASSWORD" $ROOT_SVC)" <<'SQL'
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
  run $P "$(as c##dvowner_backup "$DV_OWNER_BACKUP_PASSWORD" $PDB_SVC)" <<'SQL'
exec dbms_macadm.enable_dv
SQL
  run $P <<SQL
alter pluggable database $PDB close immediate$INST;
alter pluggable database $PDB open$INST;
set lines 120 feedback off
select c.name con, s.name, s.status from cdb_dv_status s join v\$containers c on c.con_id = s.con_id where c.name in ('CDB\$ROOT', '$PDB') order by 1, 2;
SQL
  [ "$DB" = orcl ] && ssh -o BatchMode=yes "oracle@$P" "$ENV; srvctl start service -db $DB -pdb $PDB" 2>&1 | grep -vE '^$|PRCC-1014|PRCR-1120|already running' || true   # PDB services stay down after close/open
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
  broker_enable
  apply_caught_up
  restart_standby
  broker_on
  run $S <<SQL
set lines 120 feedback off
select c.name con, s.name, s.status from cdb_dv_status s join v\$containers c on c.con_id = s.con_id where c.name in ('CDB\$ROOT', '$PDB') order by 1, 2;
SQL
  ;;
realm)
  mode=${2:?sim, on or status}
  case $mode in sim) en=DBMS_MACUTL.G_SIMULATION ;; on) en=DBMS_MACUTL.G_YES ;; esac
  if [ "$mode" = status ]; then
    run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $PDB_SVC)" <<'SQL'
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
  OK_ERR='ORA-47240|ORA-47280|ORA-47260|ORA-06512' run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $PDB_SVC)" <<SQL
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
$(for a in $EXTRA_AUTH; do echo "exec dbms_macadm.add_auth_to_realm('$REALM', '$a', null, dbms_macutl.g_realm_auth_participant)"; done)
set lines 120 feedback off
select name, enabled, realm_type from dba_dv_realm where name = '$REALM';
SQL
  ;;
auth)
  # The audit retention job (04-auditing/02_retention.sh) runs as AUDIT_MGR in PERF with the AUDIT_ADMIN role: with Database
  # Vault on, that role needs a Database Vault authorization or the job fails. Region A also has a root job (C##AUDIT_MGR).
  OK_ERR='ORA-47897|ORA-06512' run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $PDB_SVC)" <<'SQL'
exec dbms_macadm.authorize_audit_admin('AUDIT_MGR')
set lines 120 feedback off
col grantee for a20
select * from dba_dv_audit_admin_auth;
SQL
  if [ "$DB" = orcl ]; then
    OK_ERR='ORA-47897|ORA-06512' run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $ROOT_SVC)" <<'SQL'
exec dbms_macadm.authorize_audit_admin('C##AUDIT_MGR')
SQL
  fi
  ;;
auditor)
  # SYS cannot read the unified trail once Database Vault is on: a separate auditor, created by the account manager
  put "$ENVF" SEC_AUDITOR_PASSWORD$SFX; load_pw; need SEC_AUDITOR_PASSWORD DV_OWNER_PASSWORD DV_ACCTMGR_PASSWORD
  OK_ERR='ORA-01920' run $P "$(as c##dvacctmgr "$DV_ACCTMGR_PASSWORD" $PDB_SVC)" <<SQL
create user sec_auditor identified by "$SEC_AUDITOR_PASSWORD" profile sec_admin_profile;
SQL
  OK_ERR='ORA-01920' run $P <<SQL
alter session set container = $PDB;
grant create session, audit_viewer to sec_auditor;
SQL
  OK_ERR='ORA-47897|ORA-06512' run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $PDB_SVC)" <<'SQL'
exec dbms_macadm.authorize_audit_viewer('SEC_AUDITOR')
SQL
  ;;
audit)
  # Realm violations and every Database Vault configuration change, in the unified trail and so in syslog too (S4).
  # Creating a policy needs an authorized audit administrator: SYS is authorized for these statements only, then not again.
  OK_ERR='ORA-47897|ORA-06512' run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $PDB_SVC)" <<'SQL'
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
  run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $PDB_SVC)" <<'SQL'
exec dbms_macadm.unauthorize_audit_admin('SYS')
SQL
  ;;
rule)
  # A leaked BANK password from anywhere else is refused at login: BANK may connect only from the database hosts of
  # its own region (the application runs there in this lab) and through bequeath. Simulation first, like the realm.
  mode=${2:?sim or on}; case $mode in sim) en=DBMS_MACUTL.G_SIMULATION ;; on) en=DBMS_MACUTL.G_YES ;; esac
  printf '%s' "$APP_IPS" | grep -qE "^'[0-9.]+'(, *'[0-9.]+')*$" || { echo "application hosts must look like '1.2.3.4', '5.6.7.8' (Region A: DV_APP_IPS_A)"; exit 2; }
  CCR_SQL=""; for u in $CONNECT_USERS; do CCR_SQL+="begin
  dbms_macadm.create_connect_command_rule(user_name => '$u', rule_set_name => 'BANK login', enabled => $en, scope => dbms_macutl.g_scope_local);
exception when others then
  if sqlcode != -47100 then raise; end if;   -- ORA-47100: exists
  dbms_macadm.update_connect_command_rule(user_name => '$u', rule_set_name => 'BANK login', enabled => $en, scope => dbms_macutl.g_scope_local);
end;
/
"; done
  OK_ERR='ORA-47320|ORA-47100|ORA-47340|ORA-06512' run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $PDB_SVC)" <<SQL
begin
  begin
    dbms_macadm.create_rule('BANK from application hosts',
      'sys_context(''userenv'', ''ip_address'') is null or sys_context(''userenv'', ''ip_address'') in ($(printf '%s' "$APP_IPS" | sed "s/'/''/g"))');
  exception when others then
    if sqlcode != -47320 then raise; end if;   -- ORA-47320: exists, keep its expression up to date with the host list
    dbms_macadm.update_rule('BANK from application hosts',
      'sys_context(''userenv'', ''ip_address'') is null or sys_context(''userenv'', ''ip_address'') in ($(printf '%s' "$APP_IPS" | sed "s/'/''/g"))');
  end;
  begin
    dbms_macadm.create_rule_set(rule_set_name => 'BANK login', description => 'BANK only from the application hosts',
      enabled => dbms_macutl.g_yes, eval_options => dbms_macutl.g_ruleset_eval_all, audit_options => null,
      fail_options => dbms_macutl.g_ruleset_fail_show, fail_message => 'BANK may only connect from an application host',
      fail_code => 20461, handler_options => dbms_macutl.g_ruleset_handler_off, handler => null, is_static => false);
    dbms_macadm.add_rule_to_rule_set('BANK login', 'BANK from application hosts');
  exception when others then if sqlcode != -47340 then raise; end if; end;
end;
/
$CCR_SQL
set lines 120 feedback off
col command for a10
col object_owner for a10
select command, object_owner, rule_set_name, enabled from dba_dv_command_rule where command = 'CONNECT';
SQL
  ;;
window)
  # window open <reason> [test user ...]: SYS becomes realm owner, the named test users participants, for planned work only.
  # window close: every authorization the window added is removed (kept in a state file), then checked.
  need DV_OWNER_PASSWORD
  act=${2:?open or close}; why=${3:-}; ST=$OUT/.window-open
  auths() { run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $PDB_SVC)" <<SQL
set heading off feedback off pages 0
select 'realm authorizations: ' || listagg(grantee || '=' || auth_options, ', ') within group (order by grantee) from dba_dv_realm_auth where realm_name = '$REALM';
SQL
  }
  case $act in
  open)  [ -n "$why" ] || { echo "window open needs a reason"; exit 2; }
         [ -e "$ST" ] && { echo "a change window is already open ($(head -n 1 "$ST")): close it first"; exit 1; }
         shift 3 || true; who="SYS $*"
         sql=""; for g in SYS "$@"; do o=dbms_macutl.g_realm_auth_participant; [ "$g" = SYS ] && o=dbms_macutl.g_realm_auth_owner
           sql+="exec dbms_macadm.add_auth_to_realm(realm_name => '$REALM', grantee => upper('$g'), rule_set_name => null, auth_options => $o)"$'\n'; done
         { echo "$why"; echo "$who"; } > "$ST"
         OK_ERR='ORA-47260|ORA-06512' run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $PDB_SVC)" <<< "$sql"
         echo "change window OPEN $(date '+%F %T'): $why (realm authorizations added: $who)" | tee -a "$OUT/change-windows.txt" ;;
  close) [ -e "$ST" ] || echo "no window state file: removing SYS only"
         who=$( [ -e "$ST" ] && sed -n 2p "$ST" || echo SYS )
         sql=""; for g in $who; do sql+="exec dbms_macadm.delete_auth_from_realm(realm_name => '$REALM', grantee => upper('$g'))"$'\n'; done
         OK_ERR='ORA-47261|ORA-06512' run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $PDB_SVC)" <<< "$sql"
         left=$(auths)
         for g in $who; do printf '%s' "$left" | grep -qiE "[ ,]${g}=" && { echo "WINDOW STILL OPEN: $g is still authorized in the realm" >&2; exit 1; }; done
         rm -f "$ST"; echo "change window CLOSED $(date '+%F %T')" | tee -a "$OUT/change-windows.txt" ;;
  esac
  auths
  ;;
log)
  run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $PDB_SVC)" <<'SQL' | tee "$OUT/simulation-log.txt"
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
  need DV_OWNER_PASSWORD
  roles_ok
  showtrans
  broker_off
  run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $PDB_SVC)" <<'SQL'
exec dbms_macadm.disable_dv
SQL
  run $P <<SQL
alter pluggable database $PDB close immediate$INST;
alter pluggable database $PDB open$INST;
SQL
  run $P "$(as c##dvowner "$DV_OWNER_PASSWORD" $ROOT_SVC)" <<'SQL'
exec dbms_macadm.disable_dv
SQL
  [ "$DB" = orcl ] && ssh -o BatchMode=yes "oracle@$P" "$ENV; srvctl start service -db $DB -pdb $PDB" 2>&1 | grep -vE '^$|PRCC-1014|PRCR-1120|already running' || true   # PDB services stay down after close/open
  restart_primary
  broker_enable
  apply_caught_up
  restart_standby
  broker_on
  echo "privileges to give back: compare $OUT/privs-before-dv.txt with the current list (save-privs again, diff)"
  ;;
*) echo "unknown step"; exit 2 ;;
esac
