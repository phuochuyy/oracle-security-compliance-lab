#!/bin/bash
# Region B (orcl3 on prm3, standby stb3): the same baseline as Region A, in the same order, with what differs here.
# Differences: BANK logs in (workloads and drills use it), GoldenGate runs in GGREPL (more sessions than a person),
# RCAT is the recovery catalog of the RAC, SQLT lives in PERF. NNE is installed by labctl sync_node (vm-nne.sh).
#   tde        DRILLPDB.BANK_DATA online to AES256 (card-like data found in clear; the redo carries it to the standby)
#   params     GLOBAL_NAMES, SEC_PROTOCOL_ERROR_TRACE_ACTION on one site: <host>, default prm3 (dynamic; standby: run it there too)
#   profiles   service and admin profiles, in every container, assigned to every account
#   privs      direct grants to the owners found in DBA_DEPENDENCIES first, then EXECUTE revoked from PUBLIC; invalid objects before/after
#   audit      the policies of 04-auditing/01_policies.sh, in the root and every PDB
#   redaction  CARDS.PAN masked in PERF and DRILLPDB
# usage (from the host): ./05_region_b.sh tde | params [host] | profiles | privs | audit | redaction
# Safe to run again: ORA errors meaning "already there" are ignored, any other ORA stops the script.
set -eu -o pipefail
ENV=". ~/.bash_profile >/dev/null 2>&1"
H=${H:-prm3}
ALREADY='ORA-02379|ORA-46358|ORA-46350|ORA-00955|ORA-01921'   # profile, audit policy (exists, already enabled), object, role
sql() {
  local out
  out=$(ssh -o BatchMode=yes oracle@${1:-$H} "$ENV; sqlplus -s / as sysdba" 2>&1 | { grep -vE '^$' || true; })
  printf '%s\n' "$out"
  if printf '%s\n' "$out" | grep -E 'ORA-[0-9]+|SP2-[0-9]+' | grep -vE "$ALREADY" | grep -q .; then echo "STOP: unexpected error above" >&2; exit 1; fi
}
PDBS="PERF GGREPL DRILLPDB RCAT"
PKGS="utl_tcp utl_smtp utl_mail utl_http httpuritype utl_inaddr dbms_ldap utl_file dbms_advisor"
invalid() { printf "set heading off feedback off\nalter session set container = %s;\nselect '%s invalid objects: ' || count(*) from dba_objects where status = 'INVALID';\nexit\n" "$1" "$1" | sql | grep invalid; }

case ${1:?mode} in
tde)
  sql <<'SQL'
alter session set container = drillpdb;
select name from v$datafile where ts# = (select ts# from v$tablespace where name = 'BANK_DATA');
alter tablespace bank_data encryption online using 'AES256' encrypt;
select tablespace_name, encrypted from dba_tablespaces where tablespace_name = 'BANK_DATA';
select name from v$datafile where ts# = (select ts# from v$tablespace where name = 'BANK_DATA');
SQL
  ;;
params)
  h=${2:-$H}
  sql "$h" <<'SQL'
alter system set global_names = true scope = both;
alter system set sec_protocol_error_trace_action = log scope = both;
select name, value from v$parameter where name in ('global_names', 'sec_protocol_error_trace_action');
SQL
  ;;
profiles)
  sql <<'SQL'
set serveroutput on
create profile c##svc_profile limit
  failed_login_attempts 5 password_lock_time 1 password_life_time unlimited password_grace_time 5
  password_reuse_max 20 password_reuse_time 365 password_verify_function ora12c_strong_verify_function
  sessions_per_user 10 inactive_account_time 120 container = all;
alter user c##dgadmin profile c##svc_profile container = all;
alter user c##mon profile c##svc_profile container = all;
alter user c##dbzuser profile c##svc_profile container = all;
SQL
  for p in $PDBS; do
    { cat <<SQL
alter session set container = $p;
create profile sec_admin_profile limit
  failed_login_attempts 5 password_lock_time 1 password_life_time 90 password_grace_time 5
  password_reuse_max 20 password_reuse_time 365 password_verify_function ora12c_strong_verify_function
  sessions_per_user 10 inactive_account_time 120;
create profile sec_svc_profile limit
  failed_login_attempts 5 password_lock_time 1 password_life_time unlimited password_grace_time 5
  password_reuse_max 20 password_reuse_time 365 password_verify_function ora12c_strong_verify_function
  sessions_per_user 10 inactive_account_time 120;
alter user pdbadmin profile sec_admin_profile;
SQL
      case $p in
        PERF)     cat <<'SQL'
-- parallel query slaves count against SESSIONS_PER_USER: case 7 runs 4 sessions at DOP 2
create profile perf_svc_profile limit
  failed_login_attempts 5 password_lock_time 1 password_life_time unlimited password_grace_time 5
  password_reuse_max 20 password_reuse_time 365 password_verify_function ora12c_strong_verify_function
  sessions_per_user 40 inactive_account_time 120;
alter user bank profile perf_svc_profile;
SQL
                  echo "alter user sqltxplain profile sec_svc_profile;"; echo "alter user sqltxadmin profile sec_svc_profile;" ;;
        DRILLPDB) echo "alter user bank profile sec_svc_profile;" ;;
        RCAT)     echo "alter user rco profile sec_svc_profile;" ;;
        GGREPL)   cat <<'SQL'
-- GGADMIN holds 8 sessions at rest (parallel Replicat, integrated Extract), so the limit of 10 would stop GoldenGate
create profile gg_svc_profile limit
  failed_login_attempts 5 password_lock_time 1 password_life_time unlimited password_grace_time 5
  password_reuse_max 20 password_reuse_time 365 password_verify_function ora12c_strong_verify_function
  sessions_per_user 40 inactive_account_time 120;
alter user ggadmin profile gg_svc_profile;
alter user app profile sec_svc_profile;
alter user cdc_writer profile sec_svc_profile;
alter user dbfs_user profile sec_svc_profile;
SQL
          ;;
      esac
      echo "select username, profile, account_status from dba_users where oracle_maintained = 'N' order by 1;"
    } | sql
  done
  ;;
privs)
  for c in 'CDB$ROOT' $PDBS; do invalid "$c"; done
  for c in 'CDB$ROOT' $PDBS; do
    # Direct grants first: Oracle components as in Region A, then the owners DBA_DEPENDENCIES shows here
    { printf "alter session set container = %s;\ngrant execute on sys.utl_http to ctxsys, gsmadmin_internal, mdsys;\ngrant execute on sys.httpuritype to ctxsys;\ngrant execute on sys.utl_tcp to gsmadmin_internal, mdsys;\n" "$c"
      case $c in
        PERF) echo "grant execute on sys.utl_file to sqltxadmin, audit_mgr;"; echo "grant execute on sys.dbms_advisor to sqltxadmin;" ;;
        RCAT) echo "grant execute on sys.utl_http to rco;" ;;
      esac
      echo exit; } | sql > /dev/null || { echo "$c: direct grants failed, nothing revoked here" >&2; continue; }
    for p in $PKGS; do
      printf "alter session set container = %s;\nrevoke execute on sys.%s from public;\nexit\n" "$c" "$p" | ALREADY='ORA-01927|ORA-04042' sql >/dev/null
    done
    printf "alter session set container = %s;\nexec utl_recomp.recomp_serial()\nexit\n" "$c" | sql >/dev/null
    invalid "$c"
    printf "set lines 200 pages 50\nalter session set container = %s;\nselect owner, object_type, object_name from dba_objects where status = 'INVALID' order by 1;\nexit\n" "$c" | sql | grep -v 'no rows' || true
  done
  ;;
audit)
  sql <<'SQL'
create audit policy c##sec_changes
  actions grant, revoke,
          create synonym, alter synonym, drop synonym,
          create procedure, alter procedure, drop procedure, create function, alter function, drop function,
          create package, alter package, drop package, create package body, drop package body,
          create trigger, alter trigger, drop trigger
  container = all;
audit policy c##sec_changes;
create audit policy c##sec_logon_success actions logon, logoff
  when 'SYS_CONTEXT(''USERENV'', ''AUTHENTICATED_IDENTITY'') <> ''C##DGADMIN'' OR SYS_CONTEXT(''USERENV'', ''HOST'') <> ''obs-r2.rac'''
  evaluate per session container = all;
audit policy c##sec_logon_success whenever successful;
audit policy ora_all_toplevel_actions by sys;
SQL
  for p in $PDBS; do
    { cat <<SQL
alter session set container = $p;
create audit policy sec_logon_success actions logon, logoff
  when 'SYS_CONTEXT(''USERENV'', ''AUTHENTICATED_IDENTITY'') <> ''C##DGADMIN'' OR SYS_CONTEXT(''USERENV'', ''HOST'') <> ''obs-r2.rac'''
  evaluate per session;
audit policy sec_logon_success whenever successful;
create audit policy sec_changes
  actions grant, revoke,
          create synonym, alter synonym, drop synonym,
          create procedure, alter procedure, drop procedure, create function, alter function, drop function,
          create package, alter package, drop package, create package body, drop package body,
          create trigger, alter trigger, drop trigger;
audit policy sec_changes;
SQL
      case $p in PERF|DRILLPDB) cat <<'SQL'
create audit policy sec_cards_access
  actions select on bank.cards, insert on bank.cards, update on bank.cards, delete on bank.cards;
audit policy sec_cards_access;
SQL
      ;; esac
      echo "select policy_name, entity_name, success, failure from audit_unified_enabled_policies where policy_name like '%SEC_%' order by 1;"
    } | sql
  done
  ;;
redaction)
  for p in PERF DRILLPDB; do
    sql <<SQL
set serveroutput on
alter session set container = $p;
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
    function_parameters => 'VVVVVVVVVVVVVVVV,VVVVVVVVVVVVVVVV,*,1,12',
    expression          => 'SYS_CONTEXT(''SYS_SESSION_ROLES'', ''CARD_FULL_VIEW'') = ''FALSE''',
    policy_description  => 'PCI-DSS 3.4.1: PAN masked unless CARD_FULL_VIEW is enabled');
end;
/
select object_name, column_name, function_type from redaction_columns where object_owner = 'BANK';
SQL
  done
  ;;
*) echo "unknown mode"; exit 2 ;;
esac
