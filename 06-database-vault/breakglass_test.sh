#!/bin/bash
# The break-glass procedure of the Database Vault guide, tested: the everyday owner C##DVOWNER is lost (role taken away,
# password forgotten); the backup owner and the account manager bring it back. Nobody else could: SYS cannot grant DV_OWNER.
#   1. C##DVOWNER_BACKUP revokes DV_OWNER from C##DVOWNER
#   2. C##DVACCTMGR sets a new password for C##DVOWNER
#   3. C##DVOWNER_BACKUP grants DV_OWNER back, with admin option
#   4. C##DVOWNER logs in with the new password and reads the realm
# The new password replaces the old one in lab.env and is never printed.
# usage (from the host): [DV_REGION=A] ./breakglass_test.sh     B (default): orcl3 on prm3;  A: RAC orcl on prm1
set -eu -o pipefail
d=$(cd "$(dirname "$0")/.." && pwd); ENVF=$d/lab.env
case ${DV_REGION:-B} in
B) H=prm3 HC=localhost ROOT=orcl3.rac PDBS=perf.rac SFX= BG=$HOME/work/lab/breakglass/orcl3-dv.env ;;
A) H=prm1 HC=prm1.rac  ROOT=orcl.rac  PDBS=secpdb.rac SFX=_A BG=$HOME/work/lab/breakglass/orcl-dv.env ;;
esac
. "$ENVF"; . "$BG"; eval "DV_ACCTMGR_PASSWORD=\${DV_ACCTMGR_PASSWORD$SFX}"
ENV='. ~/.bash_profile >/dev/null 2>&1'
asu() { { printf 'connect %s/"%s"@//%s:1521/%s\n' "$1" "$2" "$HC" "$3"; echo "set heading off feedback off pages 0 lines 150"; cat; echo exit; } \
  | ssh -o BatchMode=yes oracle@$H "$ENV; sqlplus -s -L /nolog" 2>&1 | { grep -vE '^$|^Connected' || true; } | sed -E 's/(identified by )"[^"]*"/\1"********"/I' | cut -c1-110; }
new=$(python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Dv2#'+''.join(secrets.choice(a) for _ in range(16))+'_8')")
echo "== 0. SYS tries to give DV_OWNER (it cannot)"
printf 'grant dv_owner to c##dvowner container = all;\nexit\n' | ssh -o BatchMode=yes oracle@$H "$ENV; sqlplus -s / as sysdba" | grep -E 'ORA-' | head -n 1
echo "== 1. backup owner takes DV_OWNER from the everyday owner"
asu c##dvowner_backup "$DV_OWNER_BACKUP_PASSWORD" $ROOT <<'SQL'
revoke dv_owner from c##dvowner container = all;
select 'C##DVOWNER holds DV_OWNER: ' || count(*) from dba_role_privs where grantee = 'C##DVOWNER' and granted_role = 'DV_OWNER';
SQL
echo "== 2. account manager resets the everyday owner's password"
# the new value is saved before it is set: the first version of this test did it the other way round, stopped in
# between, and the everyday owner was left with a password nobody had (results/breakglass-test.txt)
python3 - "$ENVF" "$new" "$SFX" <<'PY'
import sys, re
p, v = sys.argv[1], sys.argv[2]
s = open(p).read()
name = "DV_OWNER_PASSWORD" + sys.argv[3]
s, n = re.subn(r"^" + name + r"=.*$", name + "='" + v + "'", s, flags=re.M)
if n != 1: sys.exit(name + " not found once in lab.env: stop before changing the password")
open(p, "w").write(s)
PY
asu c##dvacctmgr "$DV_ACCTMGR_PASSWORD" $ROOT <<SQL
alter user c##dvowner identified by "$new" container = all;
select 'password reset for: ' || username || ' ' || account_status from dba_users where username = 'C##DVOWNER';
SQL
echo "== 3. backup owner gives DV_OWNER back"
# a grant across every PDB can fail for want of a parallel server (ORA-65048 / ORA-12850, Region B first run): tried again
for i in 1 2 3; do
  r=$(asu c##dvowner_backup "$DV_OWNER_BACKUP_PASSWORD" $ROOT <<'SQL'
grant dv_owner to c##dvowner with admin option container = all;
select 'C##DVOWNER holds DV_OWNER: ' || count(*) from dba_role_privs where grantee = 'C##DVOWNER' and granted_role = 'DV_OWNER';
SQL
)
  printf '%s\n' "$r" | grep -E 'ORA-|holds'; printf '%s' "$r" | grep -q 'holds DV_OWNER: 1' && break; sleep 10
done
echo "== 4. the everyday owner is back"
asu c##dvowner "$new" $PDBS <<'SQL'
select 'C##DVOWNER sees realm: ' || name || ', enforced=' || enabled from dba_dv_realm where name = 'BANK customer data';
SQL
