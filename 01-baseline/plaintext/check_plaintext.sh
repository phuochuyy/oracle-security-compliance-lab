#!/bin/bash
# Is card data readable outside the database? Greps a real PAN from BANK.CARDS in:
#   1. the BANK_DATA datafile on the primary and on the standby (copied out of ASM)
#   2. an archived redo log that contains a freshly inserted test card
#   3. an uncompressed RMAN backup piece of BANK_DATA
# Prints one line per file: hits = how many times the PAN appears in the raw bytes.
# Run before and after TDE with the same script. Temporary copies are deleted at the end.
# usage (from the host): ./check_plaintext.sh <label>   e.g. before | after
set -eu
label=${1:?label}
dir=$(cd "$(dirname "$0")" && pwd); out=$dir/$label.txt; : > "$out"
ENV=". ~/.bash_profile >/dev/null 2>&1"
T=/tmp/plain
val() { printf "set heading off feedback off pages 0 lines 300\n%s\nexit\n" "$2" \
        | ssh -o BatchMode=yes oracle@$1 "$ENV; sqlplus -s / as sysdba" | grep -vE "^$" | sed 's/[[:space:]]*$//'; }
hits() {   # hits <host> <asm file or path> <what>
  local h=$1 f=$2 what=$3 n
  if [[ $f == +* ]]; then
    ssh -o BatchMode=yes grid@$h "$ENV; mkdir -p $T; chmod 777 $T; asmcmd cp '$f' $T/f.dbf >/dev/null"
    f=$T/f.dbf
  fi
  n=$(ssh -o BatchMode=yes root@$h "grep -a -o '$PAN' '$f' | wc -l; rm -f $T/f.dbf")
  printf "%-6s %-42s hits=%s\n" "$h" "$what" "$n" | tee -a "$out"
}

PAN=$(val prm1 "alter session set container=secpdb;
select pan from bank.cards where card_id = 1;")
echo "PAN of card 1: ${PAN:0:4}********${PAN: -4} (full value only used for the grep)" | tee -a "$out"
val prm1 "select 'TDE: ' || listagg(tablespace_name || '=' || encrypted, ' ') from cdb_tablespaces
          where con_id = (select con_id from v\$pdbs where name = 'SECPDB') and tablespace_name = 'BANK_DATA';" | tee -a "$out"

# 1. datafiles (checkpoint first so the blocks are on disk)
val prm1 "alter system checkpoint global;" >/dev/null
q="select d.name from v\$datafile d join v\$tablespace t on t.ts# = d.ts# and t.con_id = d.con_id
    where t.name = 'BANK_DATA' and d.con_id = (select con_id from v\$pdbs where name = 'SECPDB');"
hits prm1 "$(val prm1 "$q")" "BANK_DATA datafile (primary)"
hits stb1 "$(val stb1 "$q")" "BANK_DATA datafile (standby)"

# 2. redo: insert a test card with the same PAN pattern, archive the log, grep it, delete the card
PAN=4999$(date +%s)99
val prm1 "alter session set container=secpdb;
insert into bank.cards values (999999, 1, '$PAN', '12/30', 'ACTIVE', sysdate);
commit;" >/dev/null
val prm1 "alter system archive log current;" >/dev/null
# current incarnation only: the RESETLOGS of the backup drills left older logs with higher sequence numbers
arc=$(val prm1 "select name from (select name from v\$archived_log where dest_id = 1 and thread# = 1
       and resetlogs_change# = (select resetlogs_change# from v\$database)
       order by sequence# desc) where rownum = 1;")
hits prm1 "$arc" "archived log with a new test card"
val prm1 "alter session set container=secpdb;
delete bank.cards where card_id = 999999;
commit;" >/dev/null

# 3. RMAN backup piece, uncompressed (AS BACKUPSET overrides the configured COMPRESSED BACKUPSET)
PAN=$(val prm1 "alter session set container=secpdb;
select pan from bank.cards where card_id = 1;")
ssh -o BatchMode=yes root@prm1 "mkdir -p $T; chmod 777 $T"
ssh -o BatchMode=yes oracle@prm1 "$ENV; rman target / nocatalog" >/dev/null <<RMAN
backup as backupset tablespace secpdb:bank_data format '$T/bk_%U' tag plaintext_test;
RMAN
piece=$(ssh -o BatchMode=yes oracle@prm1 "ls $T/bk_* | head -n 1")
hits prm1 "$piece" "RMAN backup piece (uncompressed)"
ssh -o BatchMode=yes oracle@prm1 "$ENV; rman target / nocatalog" >/dev/null <<RMAN
delete noprompt backup tag plaintext_test;
RMAN
ssh -o BatchMode=yes root@prm1 "rm -rf $T"; ssh -o BatchMode=yes root@stb1 "rm -rf $T"
