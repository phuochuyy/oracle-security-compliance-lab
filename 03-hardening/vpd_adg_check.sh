#!/bin/bash
# Does the VPD policy also hold on the Active Data Guard standby? The policy, the function and the region table travel with
# redo; the test user is created on the primary and dropped at the end. Read-only queries only on the standby.
# With Database Vault on in SECPDB: the account manager creates and drops the test user, the grant on CARDS runs in a change window.
# usage (from the host): ./vpd_adg_check.sh <primary host> <standby host> <PDB service on the standby>   e.g. prm1 stb1 secpdb.rac
set -eu -o pipefail
P=${1:?primary} S=${2:?standby} SVC=${3:?service}
. "$(dirname "$0")/../06-database-vault/dv_helpers.sh"
DV=0; dv_on "$P" SECPDB && DV=1
ENV='. ~/.bash_profile >/dev/null 2>&1; export ORACLE_SID=$(pgrep -a -f "[o]ra_pmon_" | sed "s/.*ora_pmon_//" | head -n 1)'
pw=$(python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Ab12'+''.join(secrets.choice(a) for _ in range(12))+'#9')")
sys() { { echo "alter session set container = secpdb;"; cat; echo exit; } | ssh -o BatchMode=yes "oracle@$P" "$ENV; sqlplus -s / as sysdba" 2>&1 | { grep -E 'ORA-' || true; }; }
drop() { set +e
  sys <<'SQL'
delete from sec_admin.staff_region where username = 'ANALYST_ADG';
commit;
SQL
  if [ $DV = 1 ]; then echo "drop user analyst_adg cascade;" | dv_users "$P" secpdb.rac | grep -E 'ORA-' | grep -v ORA-01918; dv_window "$P" close
  else echo "drop user analyst_adg cascade;" | sys; fi
  return 0
}
trap drop EXIT
mk="create user analyst_adg identified by \"$pw\";"
if [ $DV = 1 ]; then dv_window "$P" open "VPD check on the standby: grant on CARDS to its test user"; printf '%s\n' "$mk" | dv_users "$P" secpdb.rac | { grep -E 'ORA-' || true; }; mk=""; fi
sys <<SQL
$mk
grant create session to analyst_adg;
grant select on bank.cards to analyst_adg;
grant card_analyst to analyst_adg;
insert into sec_admin.staff_region (username, region) values ('ANALYST_ADG', 'NORTH');
commit;
SQL
sleep 10   # redo apply
for h in "$P" "$S"; do
  out=$({ printf 'connect analyst_adg/"%s"@//%s.rac:1521/%s\n' "$pw" "$h" "$SVC"; printf "set heading off feedback off pages 0\nselect 'database role: ' || sys_context('userenv', 'database_role') from dual;\nselect 'cards visible: ' || count(*) from bank.cards;\nexit\n"; } \
    | ssh -o BatchMode=yes "oracle@$P" "$ENV; sqlplus -s -L /nolog" 2>&1 | grep -vE '^$|^Connected')
  echo "$h: $(printf '%s' "$out" | tr '\n' ' ' | cut -c1-110)"
done
