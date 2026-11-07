#!/bin/bash
# Does the VPD policy also hold on the Active Data Guard standby? The policy, the function and the region table travel with
# redo; the test user is created on the primary and dropped at the end. Read-only queries only on the standby.
# usage (from the host): ./vpd_adg_check.sh <primary host> <standby host> <PDB service on the standby>   e.g. prm1 stb1 secpdb.rac
set -eu -o pipefail
P=${1:?primary} S=${2:?standby} SVC=${3:?service}
ENV='. ~/.bash_profile >/dev/null 2>&1; export ORACLE_SID=$(pgrep -a -f "[o]ra_pmon_" | sed "s/.*ora_pmon_//" | head -n 1)'
pw=$(python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Ab12'+''.join(secrets.choice(a) for _ in range(12))+'#9')")
sys() { { echo "alter session set container = secpdb;"; cat; echo exit; } | ssh -o BatchMode=yes "oracle@$P" "$ENV; sqlplus -s / as sysdba" 2>&1 | { grep -E 'ORA-' || true; }; }
drop() { sys <<'SQL'
delete from sec_admin.staff_region where username = 'ANALYST_ADG';
commit;
drop user analyst_adg cascade;
SQL
}
trap drop EXIT
sys <<SQL
create user analyst_adg identified by "$pw";
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
