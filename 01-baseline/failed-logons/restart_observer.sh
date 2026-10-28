#!/bin/bash
# Restart a region's observer. Waits for the old observer process to exit first: start_observer.sh
# exits early if it still sees one (my first restart started nothing because of that).
# The pattern is anchored to the dgmgrl binary path: unanchored, `pgrep -f` also matched this script's
# own `bash -c` command line (it contains "dgmgrl" and "START OBSERVER") — the second restart failed so.
# Region A's start_observer.sh had the same unanchored pattern: fixed in place (backup .bak) first.
# usage (from the host): ./restart_observer.sh [B | A]
set -eu
case ${1:-B} in
  B) OBS=obs-r2 NAME=obs-r2 DB=orcl3 ;;
  A) OBS=obs-r1 NAME=obs-r1 DB=orcl ;;
esac
ssh -o BatchMode=yes oracle@$OBS "f=~/observer/start_observer.sh
grep -q 'pgrep -if \"dgmgrl.\*start observer\"' \$f && { cp -p \$f \$f.bak; sed -i 's#pgrep -if \"dgmgrl.\*start observer\"#pgrep -f \"^/[^ ]*/dgmgrl .*START OBSERVER\"#' \$f; }
grep pgrep \$f"
ssh -o BatchMode=yes oracle@$OBS ". ~/.bash_profile >/dev/null 2>&1
dgmgrl -silent /@$DB 'stop observer $NAME' >/dev/null 2>&1 || true
for i in \$(seq 1 30); do pgrep -f '^/[^ ]*/dgmgrl .*START OBSERVER' >/dev/null || break; sleep 2; done
~/observer/start_observer.sh
sleep 5; pgrep -af '^/[^ ]*/dgmgrl .*START OBSERVER' | cut -c1-80"
