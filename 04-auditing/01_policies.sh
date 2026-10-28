#!/bin/bash
# Unified Auditing policies for the gaps of the assessment baseline (A03, A05, A07, A08, P01, C02).
#   apply    common policy C##SEC_CHANGES (grants, synonyms, code/trigger DDL) for all users, logon/logoff
#            successes (ORA_LOGIN_LOGOUT had failures only), SYS top-level statements, and in SECPDB an
#            object policy on BANK.CARDS (PCI-DSS 10.2.1.1: every access to cardholder data)
#   test     a scenario in SECPDB: analyst user created, granted SELECT on CARDS, reads it, creates a
#            procedure, gets revoked — then the audit records of that user
#   volume   audit records per policy in the last hour (sizing the trail before any purge job)
# usage (from the host): ./01_policies.sh apply | test | volume
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
. "$REPO/lab.env"
: "${SECPDB_ADMIN_PASSWORD:?}"
ENV=". ~/.bash_profile >/dev/null 2>&1"
sql() { ssh -o BatchMode=yes oracle@prm1 "$ENV; sqlplus -s / as sysdba" 2>&1 | grep -vE "^$"; }

case ${1:?mode} in
apply)
  sql <<'SQL'
-- common policy: the name needs the C## prefix (ORA-65095 without it)
create audit policy c##sec_changes
  actions grant, revoke,
          create synonym, alter synonym, drop synonym,
          create procedure, alter procedure, drop procedure, create function, alter function, drop function,
          create package, alter package, drop package, create package body, drop package body,
          create trigger, alter trigger, drop trigger
  container = all;
audit policy c##sec_changes;
-- predefined, enabled WHENEVER NOT SUCCESSFUL by default: a plain AUDIT POLICY on top of that did not
-- change it — disable first, then enable for successes and failures
noaudit policy ora_login_logout;
audit policy ora_login_logout;
-- unified equivalent of AUDIT_SYS_OPERATIONS
audit policy ora_all_toplevel_actions by sys;
alter session set container = secpdb;
-- enabling ORA_LOGIN_LOGOUT in the root does not change it in the PDBs
noaudit policy ora_login_logout;
audit policy ora_login_logout;
-- the common policy enabled in the root did not audit DDL of LOCAL users in this PDB (tested: a
-- procedure created by a local user left no record) -> the same actions as a local policy here
create audit policy sec_changes
  actions grant, revoke,
          create synonym, alter synonym, drop synonym,
          create procedure, alter procedure, drop procedure, create function, alter function, drop function,
          create package, alter package, drop package, create package body, drop package body,
          create trigger, alter trigger, drop trigger;
audit policy sec_changes;
-- "ON <object>" belongs to each action: "actions select, insert, update, delete on bank.cards" (my first
-- version) audits SELECT/INSERT/UPDATE on EVERY object and only DELETE on CARDS
create audit policy sec_cards_access
  actions select on bank.cards, insert on bank.cards, update on bank.cards, delete on bank.cards;
audit policy sec_cards_access;
alter session set container = cdb$root;
set lines 200
col policy_name for a32
col entity_name for a12
select policy_name, entity_name, success, failure from audit_unified_enabled_policies order by 1;
SQL
  ;;

test)
  pw=$(python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Ab12'+''.join(secrets.choice(a) for _ in range(12))+'#_')")
  sql <<SQL | grep -E "ORA-|created|succeeded|altered"
alter session set container = secpdb;
create user analyst1 identified by "$pw" profile sec_admin_profile;
grant create session, create procedure to analyst1;
grant select on bank.cards to analyst1;
SQL
  ssh -o BatchMode=yes oracle@prm1 "$ENV; sqlplus -s -L 'analyst1/\"$pw\"@//prm1.rac:1521/secpdb_app.rac'" <<'SQL' | grep -vE "^$"
set feedback on
select count(*) from bank.cards;
create procedure p_test as begin null; end;
/
drop procedure p_test;
SQL
  sql <<'SQL' | grep -E "ORA-|succeeded|dropped"
alter session set container = secpdb;
revoke select on bank.cards from analyst1;
drop user analyst1 cascade;
SQL
  sql <<'SQL'
set lines 220 pages 100
col event_time for a8
col dbusername for a9
col action_name for a17
col object for a18
col policies for a40
alter session set container = secpdb;
select to_char(event_timestamp, 'HH24:MI:SS') event_time, dbusername, action_name,
       object_schema || '.' || object_name object, return_code rc, unified_audit_policies policies
  from unified_audit_trail
 where event_timestamp > systimestamp - interval '5' minute
   and (dbusername = 'ANALYST1' or object_name = 'ANALYST1' or target_user = 'ANALYST1')
 order by event_timestamp;
SQL
  ;;

volume)
  sql <<'SQL'
set lines 200 pages 100
col policy for a40
select con_id, regexp_substr(unified_audit_policies, '[^,]+') policy, count(*) records_last_hour
  from cdb_unified_audit_trail
 where event_timestamp > systimestamp - interval '1' hour
 group by con_id, regexp_substr(unified_audit_policies, '[^,]+') order by 1, 3 desc;
SQL
  ;;
esac
