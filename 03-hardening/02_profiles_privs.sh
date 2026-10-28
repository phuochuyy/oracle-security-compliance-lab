#!/bin/bash
# Profiles, schema-only owner and PUBLIC grants (CDB$ROOT and SECPDB of the RAC primary).
#   - C##SVC_PROFILE (common) for wallet-based service accounts (C##DGADMIN, the observer): CIS limits
#     except password expiry (an expired password in a wallet = FSFO without observer)
#   - SEC_ADMIN_PROFILE in SECPDB for people (PDBADMIN): all CIS limits, ORA12C_STRONG_VERIFY_FUNCTION
#   - BANK becomes a schema-only account (NO AUTHENTICATION): the data owner cannot log in at all
#   - EXECUTE revoked from PUBLIC on network and file packages, in both containers; invalid objects
#     counted before/after (an object that relied on the PUBLIC grant becomes invalid)
# usage (from the host): ./02_profiles_privs.sh
set -eu
ENV=". ~/.bash_profile >/dev/null 2>&1"
sql() { ssh -o BatchMode=yes oracle@prm1 "$ENV; sqlplus -s / as sysdba" 2>&1 | grep -vE "^$"; }
PKGS="utl_tcp utl_smtp utl_mail utl_http httpuritype utl_inaddr dbms_ldap utl_file dbms_advisor"
invalid() { printf "set heading off feedback off\nalter session set container = %s;\nselect '%s invalid objects: ' || count(*) from dba_objects where status = 'INVALID';\nexit\n" "$1" "$1" | sql | grep invalid; }

for c in 'CDB$ROOT' SECPDB; do invalid $c; done

sql <<'SQL'
whenever sqlerror exit failure
create profile c##svc_profile limit
  failed_login_attempts 5 password_lock_time 1 password_life_time unlimited password_grace_time 5
  password_reuse_max 20 password_reuse_time 365 password_verify_function ora12c_strong_verify_function
  sessions_per_user 10 inactive_account_time 120 container = all;
alter user c##dgadmin profile c##svc_profile container = all;
alter session set container = secpdb;
create profile sec_admin_profile limit
  failed_login_attempts 5 password_lock_time 1 password_life_time 90 password_grace_time 5
  password_reuse_max 20 password_reuse_time 365 password_verify_function ora12c_strong_verify_function
  sessions_per_user 10 inactive_account_time 120;
alter user pdbadmin profile sec_admin_profile;
alter user bank no authentication;
select username, profile, authentication_type, account_status from dba_users
 where oracle_maintained = 'N' order by username;
SQL

for c in 'CDB$ROOT' SECPDB; do
  for p in $PKGS; do
    printf "alter session set container = %s;\nrevoke execute on sys.%s from public;\nexit\n" "$c" "$p" | sql \
      | grep -E "ORA-" | sed "s/^/$c $p: /" || true
  done
  # first run: 11 invalid objects in CDB$ROOT, 3 in SECPDB — Oracle Text (CTXSYS, incl. DBMS_VECTOR_CHAIN),
  # GSM (GSMADMIN_INTERNAL, incl. the database LOGOFF trigger GSMLOGOFF) and MDSYS used the PUBLIC grant.
  # Remedy: a direct grant to exactly those owners (found in DBA_DEPENDENCIES of the invalid objects)
  printf "alter session set container = %s;
grant execute on sys.utl_http to ctxsys, gsmadmin_internal, mdsys;
grant execute on sys.httpuritype to ctxsys;
grant execute on sys.utl_tcp to gsmadmin_internal, mdsys;
exit\n" "$c" | sql | grep -E "ORA-" || true
  # recompile what became invalid (objects with a direct grant come back VALID)
  printf "alter session set container = %s;\nexec utl_recomp.recomp_serial()\nexit\n" "$c" | sql >/dev/null
  invalid $c
  printf "set lines 200 pages 50\nalter session set container = %s;\nselect owner, object_type, object_name from dba_objects where status = 'INVALID' order by 1, 3;\nexit\n" "$c" | sql | grep -v "Session altered"
done
