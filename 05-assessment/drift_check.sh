#!/bin/bash
# Has the security baseline drifted since it was last accepted? Runs the assessment, compares check by check (id, container,
# status: the detail column changes by itself), and reports only what changed, so the output means something when it appears.
# Also compares master key IDs across the sites (02-tde/07_key_check.sh). Results stay off the repository, in ~/work/lab/drift.
# A region whose primary is off is skipped and says so: a check that did not run must not look like a check that passed.
#   baseline   accept the current state of the regions that are up
#   check      compare; exit code = number of differences + key problems + regions with no baseline
# usage (from the host): ./drift_check.sh baseline | check
set -u
d=$(cd "$(dirname "$0")" && pwd); S=${DRIFT_DIR:-$HOME/work/lab/drift}; mkdir -p "$S"
mode=${1:?baseline or check}; now=$(date '+%F %H%M%S'); bad=0
up() { virsh -c qemu:///system domstate "$1" 2>/dev/null | grep -q running; }
role() { printf "set heading off feedback off pages 0\nselect database_role from v\$database;\nexit\n" | ssh -o BatchMode=yes -o ConnectTimeout=5 "oracle@$1" '. ~/.bash_profile >/dev/null 2>&1; export ORACLE_SID=$(pgrep -a -f ora_pmon_ | sed "s/.*ora_pmon_//" | head -n 1); sqlplus -s / as sysdba' 2>/dev/null | head -n 1; }
report() { echo "$1"; logger -t lab-drift -p user.warning "$1" 2>/dev/null || true; }
for x in "orcl prm1 stb1" "orcl3 prm3 stb3"; do
  set -- $x; db=$1; p=""
  for h in "$2" "$3"; do up "$h" && [ "$(role "$h")" = PRIMARY ] && p=$h; done
  [ -n "$p" ] || { echo "$db: primary is off, not checked"; continue; }
  o=$(ASSESS_DB=$db ASSESS_HOST=$p ASSESS_RESULTS=$S "$d/assess.sh" "$db-$mode" 2>&1) || { report "$db: assessment did not finish: $(printf '%s\n' "$o" | tail -n 1 | cut -c1-100)"; bad=$((bad + 1)); continue; }
  new=$S/$db-$mode.txt; cur=$(grep -v '^#' "$new" | awk -F'|' '{print $1"|"$3"|"$4"|"$5}' | sort)
  if [ "$mode" = baseline ]; then
    printf '%s\n' "$cur" > "$S/$db.baseline"; echo "$db: baseline accepted, $(wc -l < "$S/$db.baseline") checks"
  else
    if [ ! -s "$S/$db.baseline" ]; then report "$db: no baseline"; bad=$((bad + 1)); else
      diffs=$(diff <(cat "$S/$db.baseline") <(printf '%s\n' "$cur") | grep -E '^[<>]')
      if [ -n "$diffs" ]; then
        report "$db: baseline drift, $(printf '%s\n' "$diffs" | wc -l) lines"
        printf '%s\n' "$diffs" | sed 's/^</was:/; s/^>/now:/' | cut -c1-120
        bad=$((bad + $(printf '%s\n' "$diffs" | grep -c '^>')))
      else echo "$db: no drift, $(printf '%s\n' "$cur" | wc -l) checks, $(printf '%s\n' "$cur" | grep -c '|FAIL|') FAIL"; fi
    fi
    if up "$2" && up "$3"; then s=$2; [ "$p" = "$2" ] && s=$3
      k=$("$d/../02-tde/07_key_check.sh" "$p" "$s" 2>&1); rc=$?
      if [ "$rc" != 0 ]; then report "$db: master keys differ between sites"; printf '%s\n' "$k" | grep CRIT | cut -c1-110; bad=$((bad + 1)); else echo "$db: master keys match on $p and $s"; fi
    else echo "$db: standby is off, key IDs not compared"; fi
  fi
done
echo "$now $mode differences=$bad" >> "$S/history.log"
exit "$bad"
