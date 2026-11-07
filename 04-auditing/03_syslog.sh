#!/bin/bash
# Send Unified Audit records to syslog, and from there off the machine (PCI-DSS 10.3.3).
#   host      rsyslog on the VM: local file + forward to the KVM host (the VM's default gateway), with a disk queue
#   database  UNIFIED_AUDIT_SYSTEMLOG = LOCAL0.INFO in the root and the given PDBs. It can only be set in the spfile: it
#             takes effect when the instance restarts, or when a PDB is closed and opened
#   off       parameter back to empty in those containers
# Syslog gets a summary per record (who, action, object, return code, PDB), not the SQL text; the full record stays in AUDSYS.
# usage (from the host): ./03_syslog.sh host <vm> | database <vm> "<PDB> <PDB>" | off <vm> "<PDB> <PDB>"
set -eu -o pipefail
d=$(cd "$(dirname "$0")" && pwd)
mode=${1:?host, database or off} H=${2:?vm} PDBS=${3:-}
sq() {
  local out
  out=$(ssh -o BatchMode=yes "oracle@$H" '. ~/.bash_profile >/dev/null 2>&1; sqlplus -s / as sysdba' 2>&1)
  printf '%s\n' "$out" | { grep -vE '^$|altered|^Session' || true; } | cut -c1-110
  if printf '%s\n' "$out" | grep -qE 'ORA-[0-9]+'; then echo "STOP: error above" >&2; exit 1; fi
}
param() {  # param <value>
  { printf "alter system set unified_audit_systemlog = '%s' scope = spfile;\n" "$1"
    for p in $PDBS; do printf "alter session set container = %s;\nalter system set unified_audit_systemlog = '%s' scope = spfile;\n" "$p" "$1"; done
    echo "set lines 120 pages 20 feedback off"; echo "alter session set container = cdb\$root;"
    echo "col name for a26"; echo "col value for a14"
    echo "col sid for a10"
    echo "select con_id, name, value from v\$system_parameter where name = 'unified_audit_systemlog' order by 1;"
    echo "select con_id, value spfile_value from v\$spparameter where name = 'unified_audit_systemlog' order by 1;"
    echo exit; } | sq
}
case $mode in
host)
  ssh -o BatchMode=yes "root@$H" 'ip route | awk "/^default/{print \$3; exit}"' > /tmp/gw.$$; gw=$(cat /tmp/gw.$$); rm -f /tmp/gw.$$
  [ -n "$gw" ] || { echo "no default gateway on $H"; exit 1; }
  sed "s/@RECEIVER@/$gw/" "$d/syslog/oracle-audit-forward.conf.tmpl" | ssh -o BatchMode=yes "root@$H" 'cat > /etc/rsyslog.d/10-oracle-audit.conf'
  scp -q "$d/syslog/oracle-audit.logrotate" "root@$H:/etc/logrotate.d/oracle-audit"
  # The local syslog path has rate limits, and they drop audit records with no message (results/r7-syslog-cost.txt)
  ssh -o BatchMode=yes "root@$H" 'bash -s' <<'REMOTE'
grep -q 'Ratelimit.Interval' /etc/rsyslog.conf || sed -i 's/^module(load="imjournal" */module(load="imjournal" Ratelimit.Interval="0" /' /etc/rsyslog.conf
mkdir -p /etc/systemd/journald.conf.d
printf '[Journal]\nRateLimitIntervalSec=0\n' > /etc/systemd/journald.conf.d/oracle-audit.conf
systemctl restart systemd-journald
REMOTE
  ssh -o BatchMode=yes "root@$H" 'rsyslogd -N1 2>&1 | tail -n 1; systemctl restart rsyslog; systemctl is-active rsyslog; (exec 3<>/dev/tcp/'"$gw"'/5514 && echo "receiver '"$gw"':5514 reachable") 2>&1 | tail -n 1'
  ;;
database) param 'LOCAL0.INFO' ;;
off) param '' ;;
*) echo "unknown mode"; exit 2 ;;
esac
