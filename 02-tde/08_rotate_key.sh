#!/bin/bash
# New master key for one PDB of Region B (orcl3), without stopping redo apply on a key it does not have.
#   1. check the sites agree     2. apply off on the standby     3. SET KEY WITH BACKUP on the primary
#   4. keystore to the standby and off the host, same bytes     5. standby re-reads it     6. apply on, lag 0, check again
# Without step 2 there is a window in which apply can reach the new key first (ORA-28374; 03_standby_keys.sh rotate).
# The key is set by C##KEYADMIN with SYSKM (03-hardening/07_admin_roles.sh), not SYS: that account can manage keys, not read data.
# Keystore password from TDE_KEYSTORE_PASSWORD_ORCL3 in the performance repository's lab.env, on stdin only.
# usage (from the host): ./08_rotate_key.sh <primary host> <standby host> <PDB> <tag>     e.g. prm3 stb3 DRILLPDB rotate_2026q4
set -eu -o pipefail
P=${1:?primary host} S=${2:?standby host} PDB=${3:?PDB} TAG=${4:?tag}
d=$(cd "$(dirname "$0")" && pwd)
. "$d/../../oracle-performance-tuning-lab/lab.env"; : "${TDE_KEYSTORE_PASSWORD_ORCL3:?}"
. "$d/../lab.env"; : "${KEYADMIN_PASSWORD_B:?run 03-hardening/07_admin_roles.sh first}"
ESCROW=${ESCROW:-$HOME/work/lab/keystore-backup/orcl3}
ENV='. ~/.bash_profile >/dev/null 2>&1'
WALLET=/u01/app/oracle/admin/orcl3/wallet/tde
say() { echo "$(date +%T) $*"; }
sq() { ssh -o BatchMode=yes "oracle@$1" "$ENV; sqlplus -s / as sysdba" 2>&1 | { grep -vE '^$' || true; }; }
dg() { ssh -o BatchMode=yes "oracle@$P" "$ENV; dgmgrl -silent / \"$1\"" 2>&1 | { grep -vE '^$|^Connected' || true; } | cut -c1-100; }
uname() { printf "set heading off feedback off pages 0\nselect db_unique_name from v\$database;\nexit\n" | sq "$S" | head -n 1; }
md5() { ssh -o BatchMode=yes "oracle@$1" "cd $WALLET && md5sum ewallet.p12 cwallet.sso"; }

"$d/07_key_check.sh" "$P" "$S" || { say "sites disagree before the change: stop"; exit 1; }
stb=$(uname)
say "apply off on $stb"; dg "edit database '$stb' set state='APPLY-OFF'"
dg "show database '$stb'" | grep -q 'Intended State: *APPLY-OFF' || { say "broker did not take APPLY-OFF: stop, nothing changed"; exit 1; }
trap 'say "stopped midway: apply is still off on $stb. Finish by hand: copy the keystore, then APPLY-ON"' ERR

say "SET KEY in $PDB, tag $TAG"
out=$(ssh -o BatchMode=yes "oracle@$P" "$ENV; sqlplus -s -L /nolog" 2>&1 <<SQL
whenever sqlerror exit failure
connect c##keyadmin/"$KEYADMIN_PASSWORD_B"@//localhost:1521/${PDB,,}.rac as syskm
administer key management set key using tag '$TAG' force keystore identified by "$TDE_KEYSTORE_PASSWORD_ORCL3" with backup using '$TAG';
select tag, to_char(creation_time, 'YYYY-MM-DD HH24:MI') created from v\$encryption_keys where tag = '$TAG';
exit
SQL
) || { printf '%s\n' "$out" | grep -E 'ORA-' | head -n 3; exit 1; }
printf '%s\n' "$out" | grep -E "$TAG" | cut -c1-80

say "keystore to $S and off the host"
t=$(mktemp -d); trap 'rm -rf "$t"' EXIT
scp -q "oracle@$P:$WALLET/ewallet.p12" "oracle@$P:$WALLET/cwallet.sso" "$t/"
scp -q "$t/ewallet.p12" "$t/cwallet.sso" "oracle@$S:$WALLET/"
mkdir -p "$ESCROW"; install -m 600 "$t/ewallet.p12" "$ESCROW/ewallet.p12"
[ "$(md5 "$P")" = "$(md5 "$S")" ] && say "same bytes on both sites" || { say "keystores differ after the copy: stop"; exit 1; }

# the standby holds the old auto-login keystore open: closing it makes the next access read the new file
sq "$S" <<'SQL' | { grep -E 'ORA-' || true; }
administer key management set keystore close container = all;
exit
SQL
"$d/07_key_check.sh" "$P" "$S" || { say "standby does not see the new key: apply stays off"; exit 1; }
say "apply on"; dg "edit database '$stb' set state='APPLY-ON'"
for i in $(seq 1 30); do
  st=$(dg "show database '$stb'")
  grep -q 'Apply Lag: *0 seconds' <<< "$st" && break; sleep 5
done
grep -E 'Apply Lag|Intended State|ORA-' <<< "$st" | tr -s ' ' | cut -c1-90
printf "set heading off feedback off pages 0\nselect process || ' ' || status from v\$managed_standby where process like 'MRP%%';\nexit\n" | sq "$S"
say "done"
