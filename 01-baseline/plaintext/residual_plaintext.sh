#!/bin/bash
# What TDE does NOT fix: copies written before the encryption. Greps the PAN of card 1 in every archived
# log of the current incarnation still in the primary's FRA (SECPDB was loaded with logging, so the load's
# redo holds every card number in clear).
# usage (from the host): ./residual_plaintext.sh
set -eu
dir=$(cd "$(dirname "$0")" && pwd); out=$dir/residual.txt; : > "$out"
ENV=". ~/.bash_profile >/dev/null 2>&1"
val() { printf "set heading off feedback off pages 0 lines 300\n%s\nexit\n" "$1" \
        | ssh -o BatchMode=yes oracle@prm1 "$ENV; sqlplus -s / as sysdba" | grep -vE "^$" | sed 's/[[:space:]]*$//'; }
PAN=$(val "alter session set container=secpdb;
select pan from bank.cards where card_id = 1;")
echo "PAN of card 1: ${PAN:0:4}********${PAN: -4}" | tee -a "$out"
ssh -o BatchMode=yes root@prm1 "mkdir -p /tmp/res; chmod 777 /tmp/res"
# ssh -n: without it the first ssh reads the rest of the loop's input and only one log is checked
while read -r seq first f; do
  ssh -n -o BatchMode=yes grid@prm1 "$ENV; asmcmd cp '$f' /tmp/res/a.arc >/dev/null"
  n=$(ssh -n -o BatchMode=yes root@prm1 "grep -a -o '$PAN' /tmp/res/a.arc | wc -l; rm -f /tmp/res/a.arc")
  [ "$n" -gt 0 ] && printf "seq %-4s first change %s  hits=%s\n" "$seq" "$first" "$n" | tee -a "$out"
done < <(val "select sequence# || ' ' || to_char(first_time, 'HH24:MI:SS') || ' ' || name from v\$archived_log
  where dest_id = 1 and thread# = 1 and deleted = 'NO' and name is not null
    and resetlogs_change# = (select resetlogs_change# from v\$database) order by sequence#;")
ssh -o BatchMode=yes root@prm1 "rm -rf /tmp/res"
echo "archived logs checked: $(val "select count(*) from v\$archived_log where dest_id = 1 and thread# = 1 and deleted = 'NO' and name is not null and resetlogs_change# = (select resetlogs_change# from v\$database);")" | tee -a "$out"
