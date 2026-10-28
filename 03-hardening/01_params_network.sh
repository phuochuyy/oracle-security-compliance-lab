#!/bin/bash
# Parameters + network hardening on the RAC primary (prm1) and its standby (stb1).
#   apply   GLOBAL_NAMES, SEC_PROTOCOL_ERROR_TRACE_ACTION (dynamic, both sites); sqlnet.ora in the database
#           home: native encryption AES256 + SHA256 checksums REQUIRED, logon version 12a; listener
#           ADMIN_RESTRICTIONS. Existing files are kept as *.bak_<date>.
#   verify  encryption of TCP sessions from V$SESSION_CONNECT_INFO: a new test connection, and every
#           current TCP session grouped by program (sessions opened before the change stay unencrypted)
# prm2/stb2 are not running in this lab scenario: the same files have to go there before they start.
# usage (from the host): ./01_params_network.sh apply | verify
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
. "$REPO/lab.env"
: "${BANK_PASSWORD:?}"
ENV=". ~/.bash_profile >/dev/null 2>&1"
DBH=/u01/app/oracle/product/23.26.0/dbhome_1 GH=/u01/app/23.26.0/grid
sql() { ssh -o BatchMode=yes oracle@$1 "$ENV; sqlplus -s / as sysdba" 2>&1 | grep -vE "^$"; }

case ${1:?mode} in
apply)
  for h in prm1 stb1; do
    echo "== $h"
    sql $h <<'SQL'
alter system set global_names = true scope = both sid = '*';
alter system set sec_protocol_error_trace_action = log scope = both sid = '*';
SQL
    ssh -o BatchMode=yes oracle@$h "f=$DBH/network/admin/sqlnet.ora; [ -f \$f ] && cp -p \$f \$f.bak_\$(date +%Y%m%d)
cat > \$f <<'EOF'
# Server side (incoming connections, also redo transport and broker connections from the other site)
SQLNET.ENCRYPTION_SERVER = REQUIRED
SQLNET.ENCRYPTION_TYPES_SERVER = (AES256)
SQLNET.CRYPTO_CHECKSUM_SERVER = REQUIRED
SQLNET.CRYPTO_CHECKSUM_TYPES_SERVER = (SHA256)
# only 12c password verifiers (no 10G/11G hashes accepted)
SQLNET.ALLOWED_LOGON_VERSION_SERVER = 12a
NAMES.DIRECTORY_PATH = (TNSNAMES, EZCONNECT)
EOF
cat \$f | grep -v '^#'"
    ssh -o BatchMode=yes grid@$h "$ENV; f=$GH/network/admin/listener.ora
grep -q '^ADMIN_RESTRICTIONS_LISTENER' \$f || { cp -p \$f \$f.bak_\$(date +%Y%m%d); echo 'ADMIN_RESTRICTIONS_LISTENER=ON' >> \$f; }
lsnrctl reload LISTENER | grep -E 'completed|TNS-'; grep ADMIN_RESTRICTIONS \$f"
  done ;;

verify)
  echo "== new TCP connection (BANK via the listener to service secpdb_app)"
  printf 'set heading off feedback off\nselect network_service_banner from v$session_connect_info where sid = sys_context(%s, %s);\nexit\n' "'userenv'" "'sid'" \
    | ssh -o BatchMode=yes oracle@prm1 "$ENV; sqlplus -s -L 'bank/\"$BANK_PASSWORD\"@//prm1.rac:1521/secpdb_app.rac'" | grep -vE "^$" || true
  for h in prm1 stb1; do
    echo "== $h: TCP sessions by program — encrypted (AES256) / checksummed (SHA256) / total"
    sql $h <<'SQL'
set lines 200 pages 100
col program for a40
select nvl(regexp_replace(s.program, '\(.*\)', ''), '?') program,
       count(distinct case when i.network_service_banner like 'AES256 Encryption service adapter%' then s.sid || ',' || s.serial# end) aes256,
       count(distinct case when i.network_service_banner like 'SHA256 Crypto-checksumming%' then s.sid || ',' || s.serial# end) sha256,
       count(distinct s.sid || ',' || s.serial#) total
  from v$session s join v$session_connect_info i on i.sid = s.sid and i.serial# = s.serial#
 where i.network_service_banner like 'TCP/IP NT Protocol Adapter%' or s.sid in
       (select sid from v$session_connect_info where network_service_banner like 'TCP/IP%')
 group by regexp_replace(s.program, '\(.*\)', '') order by total desc;
SQL
  done ;;
esac
