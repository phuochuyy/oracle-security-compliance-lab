#!/bin/bash
# Encrypt the tablespace behind DBFS, online. GoldenGate keeps its deployment on DBFS, including the master key wallet of
# the trail encryption (cwallet.sso, auto-login), so an unencrypted DBFS_TS left the key to the trails readable in a datafile.
#   check <host> <file>      does a known string show in a datafile on this file system? (file system sites only)
#   encrypt <host> <PDB> [tablespace]   online to AES256; DBFS and GoldenGate stay up, the standby follows through redo
# The conversion writes a new copy of the file, then removes the old one: it needs free space of about the file size on
# both sites, and redo of about what is used. usage (from the host): ./09_encrypt_dbfs.sh encrypt prm3 GGREPL DBFS_TS
set -eu -o pipefail
mode=${1:?check or encrypt} H=${2:?host}
sq() { ssh -o BatchMode=yes "oracle@$H" '. ~/.bash_profile >/dev/null 2>&1; export ORACLE_SID=$(pgrep -a -f "[o]ra_pmon_" | sed "s/.*ora_pmon_//" | head -n 1); sqlplus -s / as sysdba' 2>&1 | { grep -vE '^$|^Session altered' || true; } | cut -c1-120; }
case $mode in
encrypt)
  PDB=${3:?PDB} T=${4:-DBFS_TS}
  f=$({ printf "set heading off feedback off pages 0 lines 300\nalter session set container = %s;\nselect file_name from dba_data_files where tablespace_name = '%s';\nexit\n" "$PDB" "$T"; } | sq | grep -E '^[/+]' | head -n 1)
  [ -n "$f" ] || { echo "no datafile for $T in $PDB"; exit 1; }
  # a file outside ASM and OMF needs a new name; ASM and OMF name it themselves
  conv=""; case $f in /*/o1_mf_*|+*) ;; /*) b=$(basename "$f"); conv="file_name_convert = ('$b', '${b%.dbf}_enc.dbf')" ;; esac
  t0=$(date +%s)
  { printf "alter session set container = %s;\nalter tablespace %s encryption online using 'AES256' encrypt %s;\nset lines 120 pages 20 feedback off\ncol tablespace_name for a14\ncol file_name for a70\nselect t.tablespace_name, t.encrypted, f.file_name from dba_tablespaces t join dba_data_files f on f.tablespace_name = t.tablespace_name where t.tablespace_name = '%s';\nexit\n" "$PDB" "$T" "$conv" "$T"; } | sq
  echo "elapsed $(( $(date +%s) - t0 )) s"
  ;;
check)
  F=${3:?file}; shift 3
  for s in "$@"; do echo "$s: $(ssh -o BatchMode=yes "oracle@$H" "grep -a -c -F '$s' '$F' || true") matching lines in $(basename "$F")"; done
  ;;
*) echo "unknown mode"; exit 2 ;;
esac
