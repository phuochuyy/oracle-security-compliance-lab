#!/bin/bash
# Listener-level allow list in Region B: a machine that is not on the list is refused before it can even try a password.
#   apply <host>   adds valid-nodes-b.ora to the database home's sqlnet.ora and restarts the listener
#   test           who gets through: this host (not invited) and the machines that have to
# Existing sessions, including redo transport, are not affected by a listener restart; new ones wait about a second.
# usage (from the host): ./08_valid_nodes.sh apply prm3 | apply stb3 | test
set -eu -o pipefail
d=$(cd "$(dirname "$0")" && pwd)
ENV='. ~/.bash_profile >/dev/null 2>&1'
case ${1:?apply or test} in
apply)
  H=${2:?host}
  scp -q "$d/valid-nodes-b.ora" "oracle@$H:/tmp/valid-nodes-b.ora"
  ssh -o BatchMode=yes "oracle@$H" 'bash -s' <<'REMOTE'
. ~/.bash_profile >/dev/null 2>&1
f=$ORACLE_HOME/network/admin/sqlnet.ora
grep -q '^TCP.VALIDNODE_CHECKING' "$f" || { cp -p "$f" "$f.bak_$(date +%Y%m%d_%H%M)"; cat /tmp/valid-nodes-b.ora >> "$f"; }
rm -f /tmp/valid-nodes-b.ora
lsnrctl stop >/dev/null; lsnrctl start | grep -E 'TNS-|completed successfully' | cut -c1-90
printf 'alter system register;\nexit\n' | sqlplus -s / as sysdba | grep -E 'ORA-' || true
REMOTE
  ;;
test)
  declare -A IP=([prm3]=192.168.106.10 [stb3]=192.168.107.10)   # the host does not resolve *.rac
  for t in prm3 stb3; do
    for src in prm1 obs-r2 prm3 stb3; do
      virsh -c qemu:///system domstate "$src" 2>/dev/null | grep -q running || continue
      echo "$src -> $t: $(ssh -o BatchMode=yes "oracle@$src" "$ENV; tnsping '(DESCRIPTION=(ADDRESS=(PROTOCOL=TCP)(HOST=$t.rac)(PORT=1521)))'" 2>&1 | tail -n 1 | cut -c1-70)"
    done
    # this host is not invited
    echo "KVM host -> $t: $(LD_LIBRARY_PATH=$HOME/work/tools/instantclient_23_26 "$HOME/work/tools/venvs/dba/bin/python" -I - "${IP[$t]}" <<'PY' 2>&1 | tail -n 1 | cut -c1-110
import oracledb, os, sys
oracledb.init_oracle_client(lib_dir=os.path.expanduser("~/work/tools/instantclient_23_26"))
try:
    oracledb.connect(user="nobody", password="not-a-password", dsn=f"{sys.argv[1]}:1521/perf.rac")
except oracledb.Error as e:
    print(str(e).split("\n")[0])
PY
)"
  done
  ;;
esac
