#!/bin/bash
# Restart the Region B observer. Waits for the old observer process to exit first: start_observer.sh
# exits early if it still sees one (my first restart started nothing because of that).
# The pattern is anchored to the dgmgrl binary path: unanchored, `pgrep -f` also matched this script's
# own `bash -c` command line (it contains "dgmgrl" and "START OBSERVER") — the second restart failed so.
set -eu
ssh -o BatchMode=yes oracle@obs-r2 '. ~/.bash_profile >/dev/null 2>&1
dgmgrl -silent /@orcl3 "stop observer obs-r2" >/dev/null 2>&1 || true
for i in $(seq 1 30); do pgrep -f "^/[^ ]*/dgmgrl .*START OBSERVER" >/dev/null || break; sleep 2; done
~/observer/start_observer.sh
sleep 5; pgrep -af "^/[^ ]*/dgmgrl .*START OBSERVER" | cut -c1-80'
