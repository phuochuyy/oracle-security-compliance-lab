#!/bin/bash
# TDE and GoldenGate Active-Active (GG_A: orcl/ORCLPDB2 on the RAC, GG_B: orcl3/GGREPL on prm3).
# Test table APP.CARD_EVENTS with card-like numbers, created on both sides (DDL is not replicated).
#   setup         create the table on both sides + Auto-CDR
#   write <n>     5 rows at each site with marker PANs 4111<n>0000xxxxxx, wait until both sides have all
#   trail <n>     count marker PANs of round <n> in the trail files on both deployments (local + received)
#   encrypt       TDE on ORCLPDB2's APP_DATA (online)
#   encrypttrail  ENCRYPTTRAIL AES256 for EXTA and EXTB, new trail file
#   cleanup       stop Replicats after they passed the last change, drop the table on both sides, start them
# usage (from the host): ./06_goldengate.sh <mode> [n]
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
. "$REPO/lab.env"
: "${OGG_ADMIN_PASSWORD:?}"
mode=${1:?mode}; n=${2:-1}
ENV=". ~/.bash_profile >/dev/null 2>&1"
sqlpdb() { ssh -o BatchMode=yes oracle@$1 "$ENV; sqlplus -s / as sysdba" < <(printf 'set feedback on lines 200\nalter session set container = %s;\n%s\nexit\n' "$2" "$3") | grep -vE "^$|Session altered"; }
val() { sqlpdb $1 $2 "set heading off feedback off pages 0
$3" | tr -d ' \t'; }
ggc() {   # ggc <host> <deployment> <command>...
  local h=$1 d=$2; shift 2
  { printf 'CONNECT http://localhost:9100 DEPLOYMENT %s AS oggadmin PASSWORD %s\n' "$d" "$OGG_ADMIN_PASSWORD"; printf '%s\n' "$@"; } \
    | ssh -o BatchMode=yes oracle@$h "cat > /tmp/gg.oby; /u01/app/gg/bin/adminclient -O /tmp/gg.oby 2>&1; rm -f /tmp/gg.oby" \
    | grep -vE "^$|^OGG \(not connected\)|Copyright|^Oracle GoldenGate|^Linux|^Operating|^Version" | sed "s/$OGG_ADMIN_PASSWORD/********/g"
}
A="prm1 orclpdb2" B="prm3 ggrepl"

case $mode in
setup)
  for s in "$A" "$B"; do
    read -r h p <<< "$s"
    sqlpdb $h $p "create table app.card_events (
  site varchar2(4) not null, seq number not null, pan varchar2(19) not null, amount number(18,2) not null,
  created timestamp default systimestamp not null, constraint card_events_pk primary key (site, seq));
exec dbms_goldengate_adm.add_auto_cdr('APP', 'CARD_EVENTS')
select tablespace_name from dba_tables where owner = 'APP' and table_name = 'CARD_EVENTS';"
  done ;;

write)
  for s in "A $A" "B $B"; do
    read -r site h p <<< "$s"
    sqlpdb $h $p "insert into app.card_events (site, seq, pan, amount)
  select '$site', $n * 100 + level, '4111' || lpad($n, 2, '0') || '0000' || lpad(level, 6, '0'), level * 10
  from dual connect by level <= 5;
commit;" | grep -E "rows created|ORA-"
  done
  for i in $(seq 1 24); do
    a=$(val prm1 orclpdb2 "select count(*) from app.card_events where seq between $n * 100 + 1 and $n * 100 + 5;")
    b=$(val prm3 ggrepl "select count(*) from app.card_events where seq between $n * 100 + 1 and $n * 100 + 5;")
    [ "$a" = 10 ] && [ "$b" = 10 ] && break; sleep 5
  done
  echo "round $n after $(( i * 5 )) s: orcl/ORCLPDB2 has $a of 10 rows, orcl3/GGREPL has $b of 10" ;;

trail)
  for s in "prm1 GG_A" "prm3 GG_B"; do
    read -r h d <<< "$s"
    ssh -o BatchMode=yes oracle@$h "cd /mnt/dbfs/ogg/$d/var/lib/data
      for t in ea eb; do f=\$(ls -t \$t* | head -n 1)
        printf '%-5s %-14s %-6s PAN hits=%s\n' $d \$f \$( [ \${t#e} = \$(echo $d | tr A-Z a-z | cut -c4) ] && echo local || echo recvd ) \$(cat \$t* | grep -a -o '4111$(printf %02d $n)0000[0-9]\{6\}' | wc -l)
      done"
  done ;;

encrypt)
  sqlpdb prm1 orclpdb2 "set timing on
alter tablespace app_data encryption online using 'AES256' encrypt;
select tablespace_name, encrypted from dba_tablespaces where tablespace_name = 'APP_DATA';" ;;

encrypttrail)
  for s in "prm1 GG_A EXTA" "prm3 GG_B EXTB"; do
    read -r h d e <<< "$s"
    prm=/mnt/dbfs/ogg/$d/etc/conf/ogg/$(echo $e | tr A-Z a-z).prm
    ssh -o BatchMode=yes oracle@$h "grep -q '^ENCRYPTTRAIL' $prm || { cp -p $prm $prm.bak_noencrypt; sed -i 's/^EXTTRAIL \(.*\)/ENCRYPTTRAIL AES256\nEXTTRAIL \1/' $prm; }; grep -B1 '^EXTTRAIL' $prm"
    ggc $h $d "STOP EXTRACT $e" >/dev/null
    for i in $(seq 1 30); do ggc $h $d "INFO EXTRACT $e" | grep -q "Status STOPPED" && break; sleep 2; done
    # the open trail file was written without encryption: start a new one
    ggc $h $d "ALTER EXTRACT $e, ETROLLOVER" "START EXTRACT $e" | grep -E "OGG-|ERROR|rolled|started" || true
  done
  sleep 10
  ggc prm1 GG_A "INFO ALL"; ggc prm3 GG_B "INFO ALL" ;;

cleanup)
  # memory rule from the HA/DR lab: stop the load, let both Replicats read past the last change, STOP them,
  # drop the table, START them — dropping while the trail still has rows makes REPA/REPB abend (OGG-00199)
  sleep 20
  ggc prm1 GG_A "STOP REPLICAT REPA" >/dev/null; ggc prm3 GG_B "STOP REPLICAT REPB" >/dev/null
  for s in "$A" "$B"; do read -r h p <<< "$s"; sqlpdb $h $p "exec dbms_goldengate_adm.remove_auto_cdr('APP', 'CARD_EVENTS')
drop table app.card_events purge;"; done
  ggc prm1 GG_A "START REPLICAT REPA" >/dev/null; ggc prm3 GG_B "START REPLICAT REPB" >/dev/null
  sleep 10; ggc prm1 GG_A "INFO ALL"; ggc prm3 GG_B "INFO ALL" ;;
esac
