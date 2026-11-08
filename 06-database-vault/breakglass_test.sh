#!/bin/bash
# The break-glass procedure of the Database Vault guide, tested: the everyday owner C##DVOWNER is lost (role taken away,
# password forgotten); the backup owner and the account manager bring it back. Nobody else could: SYS cannot grant DV_OWNER.
#   1. C##DVOWNER_BACKUP revokes DV_OWNER from C##DVOWNER
#   2. C##DVACCTMGR sets a new password for C##DVOWNER
#   3. C##DVOWNER_BACKUP grants DV_OWNER back, with admin option
#   4. C##DVOWNER logs in with the new password and reads the realm
# The new password replaces the old one in lab.env and is never printed. usage (from the host): ./breakglass_test.sh
set -eu -o pipefail
d=$(cd "$(dirname "$0")/.." && pwd); ENVF=$d/lab.env; BG=$HOME/work/lab/breakglass/orcl3-dv.env
. "$ENVF"; . "$BG"
ENV='. ~/.bash_profile >/dev/null 2>&1'
asu() { { printf 'connect %s/"%s"@//localhost:1521/%s\n' "$1" "$2" "$3"; echo "set heading off feedback off pages 0 lines 150"; cat; echo exit; } \
  | ssh -o BatchMode=yes oracle@prm3 "$ENV; sqlplus -s -L /nolog" 2>&1 | { grep -vE '^$|^Connected' || true; } | sed -E 's/(identified by )"[^"]*"/\1"********"/I' | cut -c1-110; }
new=$(python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Dv2#'+''.join(secrets.choice(a) for _ in range(16))+'_8')")
echo "== 0. SYS tries to give DV_OWNER (it cannot)"
printf 'grant dv_owner to c##dvowner container = all;\nexit\n' | ssh -o BatchMode=yes oracle@prm3 "$ENV; sqlplus -s / as sysdba" | grep -E 'ORA-' | head -n 1
echo "== 1. backup owner takes DV_OWNER from the everyday owner"
asu c##dvowner_backup "$DV_OWNER_BACKUP_PASSWORD" orcl3.rac <<'SQL'
revoke dv_owner from c##dvowner container = all;
select 'C##DVOWNER holds DV_OWNER: ' || count(*) from dba_role_privs where grantee = 'C##DVOWNER' and granted_role = 'DV_OWNER';
SQL
echo "== 2. account manager resets the everyday owner's password"
# the new value is saved before it is set: the first version of this test did it the other way round, stopped in
# between, and the everyday owner was left with a password nobody had (results/breakglass-test.txt)
python3 - "$ENVF" "$new" <<'PY'
import sys, re
p, v = sys.argv[1], sys.argv[2]
s = open(p).read()
s = re.sub(r"^DV_OWNER_PASSWORD=.*$", "DV_OWNER_PASSWORD='" + v + "'", s, flags=re.M)
open(p, "w").write(s)
PY
asu c##dvacctmgr "$DV_ACCTMGR_PASSWORD" orcl3.rac <<SQL
alter user c##dvowner identified by "$new" container = all;
select 'password reset for: ' || username || ' ' || account_status from dba_users where username = 'C##DVOWNER';
SQL
echo "== 3. backup owner gives DV_OWNER back"
asu c##dvowner_backup "$DV_OWNER_BACKUP_PASSWORD" orcl3.rac <<'SQL'
grant dv_owner to c##dvowner with admin option container = all;
SQL
echo "== 4. the everyday owner is back"
asu c##dvowner "$new" perf.rac <<'SQL'
select 'C##DVOWNER sees realm: ' || name || ', enforced=' || enabled from dba_dv_realm where name = 'BANK customer data';
SQL
