#!/bin/bash
# Security assessment of a primary database — the lab's replacement for DBSAT,
# which needs a My Oracle Support contract (see README). Checks grouped like the CIS Oracle Database
# Benchmark sections; SQL checks in checks.sql, network/listener file checks here.
# Output: results/<label>.txt, one line per check, and a summary.
# usage (from the host): ./assess.sh <label>                 RAC primary orcl: CDB$ROOT + SECPDB
#        ASSESS_DB=orcl3 ./assess.sh <label>                  Region B primary on prm3: CDB$ROOT + its PDBs
set -eu
label=${1:?label}
dir=$(cd "$(dirname "$0")" && pwd); out=$dir/results/$label.txt; mkdir -p "$dir/results"
ASSESS_DB=${ASSESS_DB:-orcl}
case $ASSESS_DB in
  orcl)  H=${ASSESS_HOST:-prm1}; CONTAINERS='CDB$ROOT SECPDB' ;;
  orcl3) H=${ASSESS_HOST:-prm3}; CONTAINERS='CDB$ROOT PERF GGREPL DRILLPDB RCAT' ;;
  *) echo "unknown database $ASSESS_DB"; exit 2 ;;
esac
ENV=". ~/.bash_profile >/dev/null 2>&1"
DBH=/u01/app/oracle/product/23.26.0/dbhome_1 GH=/u01/app/23.26.0/grid
# no Grid Infrastructure on orcl3: its listener runs from the database home
[ "$ASSESS_DB" = orcl ] && LSN=$GH/network/admin/listener.ora || LSN=$DBH/network/admin/listener.ora

ssh -o BatchMode=yes oracle@$H "cat > /tmp/checks.sql" < "$dir/checks.sql"
# A failing check block would otherwise lose the whole container and still report 0 FAIL: stop instead.
res=""
for c in $CONTAINERS; do
  o=$(ssh -o BatchMode=yes oracle@$H "$ENV; sqlplus -s / as sysdba @/tmp/checks.sql '$c'")
  if printf '%s\n' "$o" | grep -qE '^(ORA-|SP2-|ERROR at)'; then printf '%s\n' "$o" | grep -E '^(ORA-|SP2-)' | head -n 5; echo "assessment failed in $c" >&2; exit 1; fi
  printf '%s\n' "$o" | grep -qE '^[A-Z][0-9]{2}\|' || { echo "no results from $c" >&2; exit 1; }
  res+=$(printf '%s\n' "$o" | grep -E '^[A-Z][0-9]{2}\|')$'\n'
done
res=${res%$'\n'}
ssh -o BatchMode=yes oracle@$H "rm -f /tmp/checks.sql"

# network: the database server processes read $DBH/network/admin/sqlnet.ora (no TNS_ADMIN in srvctl env)
net() {   # net <id> <title> <file> <regex that must match>
  local v
  v=$(ssh -o BatchMode=yes oracle@$H "grep -hiE '^[[:space:]]*$4' $3 2>/dev/null | head -n 1" || true)
  [ -n "$v" ] && st=PASS || st=FAIL
  echo "$1|6 network|$H|$st|$2|${v:-not set in $(basename $3) ($(ssh -o BatchMode=yes oracle@$H "test -f $3 && echo exists || echo file missing"))}"
}
res+=$'\n'$(net N01 "server requires network encryption" $DBH/network/admin/sqlnet.ora "SQLNET.ENCRYPTION_SERVER *= *REQUIRED")
res+=$'\n'$(net N02 "server requires integrity checksums" $DBH/network/admin/sqlnet.ora "SQLNET.CRYPTO_CHECKSUM_SERVER *= *REQUIRED")
res+=$'\n'$(net N03 "allowed logon version >= 12a" $DBH/network/admin/sqlnet.ora "SQLNET.ALLOWED_LOGON_VERSION_SERVER *= *(12a|1[3-9]|2[0-9])")
res+=$'\n'$(net N04 "listener admin restrictions on" $LSN "ADMIN_RESTRICTIONS_LISTENER *= *ON")
[ "$ASSESS_DB" = orcl3 ] && res+=$'\n'$(net N05 "listener allows only listed machines" $DBH/network/admin/sqlnet.ora "TCP.VALIDNODE_CHECKING *= *YES")

{
  echo "# assessment '$label' — $(date '+%F %T') — $ASSESS_DB on $H: $CONTAINERS"
  echo "# id|section|container|status|check|detail"
  echo "$res"
  echo "#"
  echo "# summary: $(echo "$res" | cut -d'|' -f4 | sort | uniq -c | awk '{printf "%s %s  ", $2, $1}')"
  for s in "2 params" "3 users" "4 privs" "5 audit" "6 network" "PCI"; do
    echo "#   $s: $(echo "$res" | awk -F'|' -v s="$s" 'index($2, s) == 1 {print $4}' | sort | uniq -c | awk '{printf "%s %s  ", $2, $1}')"
  done
} > "$out"
column -t -s'|' -o' | ' < <(grep -v '^#' "$out") | cut -c1-200
grep '^# *summary\|^#   ' "$out"
