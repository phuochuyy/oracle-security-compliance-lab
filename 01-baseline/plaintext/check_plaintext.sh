#!/bin/bash
# Is card data readable outside the database? Greps a real PAN from BANK.CARDS in:
#   1. the BANK_DATA datafile on the primary and on the standby (copied out of ASM)
#   2. an archived redo log that contains a freshly inserted test card
#   3. an uncompressed RMAN backup piece of BANK_DATA
# Prints one line per file: hits = how many times the PAN appears in the raw bytes.
# Run before and after TDE with the same script. Temporary copies are deleted at the end.
# usage (from the host): ./check_plaintext.sh <label>   RAC primary, SECPDB, with the standby's copy
#   PLAIN_HOST=prm3 PLAIN_STB= PLAIN_PDB=DRILLPDB ./check_plaintext.sh <label>   other primary; empty PLAIN_STB skips the standby
set -eu
label=${1:?label}
dir=$(cd "$(dirname "$0")" && pwd); out=$dir/$label.txt; : > "$out"
ENV=". ~/.bash_profile >/dev/null 2>&1"
T=/tmp/plain
P=${PLAIN_HOST:-prm1} S=${PLAIN_STB-stb1} PDB=${PLAIN_PDB:-SECPDB}
# Database Vault (06-database-vault): when it is on in the PDB, reading and inserting a card as SYS needs a change window
. "$dir/../../06-database-vault/dv_helpers.sh"
if dv_on "$P" "$PDB"; then
  case "$(dv_region "$P"):$PDB" in A:SECPDB|B:PERF) ;; *) echo "Database Vault is on in $PDB, but dv.sh opens windows for SECPDB / PERF only: stop"; exit 1 ;; esac
  # test card removed (if the script stopped after inserting it) before the window closes
  trap 'printf "alter session set container=$PDB;\ndelete bank.cards where card_id = 999999;\ncommit;\nexit\n" | ssh -o BatchMode=yes oracle@$P "$ENV; sqlplus -s / as sysdba" >/dev/null; dv_window "$P" close' EXIT
  dv_window "$P" open "plaintext check on $PDB: SYS reads one card and inserts, then deletes, a test card"
fi
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

PAN=$(val $P "alter session set container=$PDB;
select pan from bank.cards where card_id = 1;")
echo "PAN of card 1: ${PAN:0:4}********${PAN: -4} (full value only used for the grep)" | tee -a "$out"
val $P "select 'TDE: ' || listagg(tablespace_name || '=' || encrypted, ' ') from cdb_tablespaces
          where con_id = (select con_id from v\$pdbs where name = '$PDB') and tablespace_name = 'BANK_DATA';" | tee -a "$out"

# 1. datafiles (checkpoint first so the blocks are on disk)
val $P "alter system checkpoint global;" >/dev/null
q="select d.name from v\$datafile d join v\$tablespace t on t.ts# = d.ts# and t.con_id = d.con_id
    where t.name = 'BANK_DATA' and d.con_id = (select con_id from v\$pdbs where name = '$PDB');"
hits $P "$(val $P "$q")" "BANK_DATA datafile (primary)"
[ -z "$S" ] || hits $S "$(val $S "$q")" "BANK_DATA datafile (standby)"

# 2. redo: insert a test card with the same PAN pattern, archive the log, grep it, delete the card
PAN=4999$(date +%s)99
val $P "alter session set container=$PDB;
insert into bank.cards values (999999, 1, '$PAN', '12/30', 'ACTIVE', sysdate);
commit;" >/dev/null
val $P "alter system archive log current;" >/dev/null
# current incarnation only: the RESETLOGS of the backup drills left older logs with higher sequence numbers
arc=$(val $P "select name from (select name from v\$archived_log where dest_id = 1 and thread# = 1
       and resetlogs_change# = (select resetlogs_change# from v\$database)
       order by sequence# desc) where rownum = 1;")
hits $P "$arc" "archived log with a new test card"
val $P "alter session set container=$PDB;
delete bank.cards where card_id = 999999;
commit;" >/dev/null

# 3. RMAN backup piece, uncompressed (AS BACKUPSET overrides the configured COMPRESSED BACKUPSET)
PAN=$(val $P "alter session set container=$PDB;
select pan from bank.cards where card_id = 1;")
ssh -o BatchMode=yes root@$P "mkdir -p $T; chmod 777 $T"
ssh -o BatchMode=yes oracle@$P "$ENV; rman target / nocatalog" >/dev/null <<RMAN
# RMAN's own encryption is switched off for this piece: with it on, a 0 here would say nothing about TDE
set encryption off for all tablespaces;
backup as backupset tablespace $PDB:bank_data format '$T/bk_%U' tag plaintext_test;
RMAN
piece=$(ssh -o BatchMode=yes oracle@$P "ls $T/bk_* | head -n 1")
hits $P "$piece" "RMAN backup piece (uncompressed)"
ssh -o BatchMode=yes oracle@$P "$ENV; rman target / nocatalog" >/dev/null <<RMAN
delete noprompt backup tag plaintext_test;
RMAN
ssh -o BatchMode=yes root@$P "rm -rf $T"; [ -z "$S" ] || ssh -o BatchMode=yes root@$S "rm -rf $T"
