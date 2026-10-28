#!/bin/bash
# Online encryption of SECPDB's BANK_DATA (AES256) on the RAC primary, while an application keeps reading
# and writing. Shows what the standby does with it (redo apply converts the standby's file too).
# Writer: UPDATE ... SET balance = balance (real DML and redo, BANKDB checksums unchanged).
# rekey: new tablespace key (AES256), the datafile is rewritten online the same way — key rotation
# usage (from the host): ./02_encrypt_online.sh [encrypt | rekey]
set -eu
action=${1:-encrypt}
dir=$(cd "$(dirname "$0")" && pwd)
case $action in encrypt) out=$dir/results/05-encrypt-online.log ;; rekey) out=$dir/results/06-rekey-online.log ;; *) exit 1 ;; esac
: > "$out"
ENV=". ~/.bash_profile >/dev/null 2>&1"
PRM=prm1 STB=stb1
say() { echo "$(date +%T) $*" | tee -a "$out"; }
sql() { ssh -o BatchMode=yes oracle@$1 "$ENV; sqlplus -s / as sysdba" 2>&1 | grep -vE "^$" | tee -a "$out"; }
ts_state() {
  for h in $PRM $STB; do
    echo "-- $h" | tee -a "$out"
    sql $h <<'SQL'
set lines 200 pages 50 feedback off
col tablespace_name for a10
col status for a10
col encryptionalg for a8
col file_name for a70
alter session set container = secpdb;
select t.tablespace_name, t.encrypted, e.encryptionalg, e.status
  from dba_tablespaces t left join v$encrypted_tablespaces e on e.ts# = (select ts# from v$tablespace where name = t.tablespace_name)
 where t.tablespace_name = 'BANK_DATA';
select name file_name from v$datafile where ts# = (select ts# from v$tablespace where name = 'BANK_DATA');
SQL
  done
}

say "before"; ts_state

# application load: 1 reader + 1 writer for 90 s, errors counted (not stopped on)
load() {
  ssh -o BatchMode=yes oracle@$PRM "$ENV; sqlplus -s / as sysdba" <<SQL
set feedback off
alter session set container = secpdb;
-- after the container switch: set before it, DBMS_OUTPUT stays disabled in the PDB (no output at all)
set serveroutput on
declare
  n pls_integer := 0; err pls_integer := 0; c number; last_err varchar2(200);
  t0 date := sysdate;
begin
  while sysdate < t0 + 90/86400 loop
    begin
      if '$1' = 'reader' then
        select count(*) into c from bank.cards where pan like '9%';
        select sum(balance) into c from bank.accounts;
      else
        update bank.accounts set balance = balance where account_id = mod(n, 30000) + 1;
        commit;
      end if;
      n := n + 1;
    exception when others then err := err + 1; last_err := sqlerrm;
    end;
    dbms_session.sleep(0.05);
  end loop;
  dbms_output.put_line('$1: ' || n || ' ok, ' || err || ' errors ' || last_err);
end;
/
SQL
}
load reader > "$dir/results/.reader" & r=$!
load writer > "$dir/results/.writer" & w=$!
sleep 10

say "ALTER TABLESPACE bank_data ENCRYPTION ONLINE USING 'AES256' ${action^^}"
t0=$(date +%s.%N)
sql $PRM <<SQL
set timing on
alter session set container = secpdb;
alter tablespace bank_data encryption online using 'AES256' $action;
SQL
say "conversion took $(printf '%.0f' "$(echo "$(date +%s.%N) - $t0" | bc)") s on the primary"

wait $r $w
say "application during the conversion:"; cat "$dir/results/.reader" "$dir/results/.writer" | grep -vE "^$" | tee -a "$out"
rm -f "$dir/results/.reader" "$dir/results/.writer"

# the standby converts its copy while applying the redo
for i in $(seq 1 30); do
  e=$(printf "set heading off feedback off\nalter session set container = secpdb;\nselect encrypted from dba_tablespaces where tablespace_name = 'BANK_DATA';\nexit\n" \
      | ssh -o BatchMode=yes oracle@$STB "$ENV; sqlplus -s / as sysdba" | grep -oE "YES|NO" | head -n 1)
  [ "$e" = YES ] && break; sleep 5
done
say "after (standby BANK_DATA encrypted=$e)"; ts_state
sql $STB <<'SQL'
set lines 200 feedback off
select name, value from v$dataguard_stats where name in ('transport lag', 'apply lag');
SQL
