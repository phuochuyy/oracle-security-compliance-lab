#!/bin/bash
# What does sending audit records to syslog add? The same audited statement in a loop, with UNIFIED_AUDIT_SYSTEMLOG empty and set,
# alternating so that a slow period of the host does not fall on one side only.
# It closes and opens the PDB between runs, so no workload may be using it.
# usage (from the host): ./04_syslog_cost.sh <vm> <PDB> <service> <statements per run> <rounds>    e.g. prm3 PERF perf.rac 10000 3
set -eu -o pipefail
H=${1:?vm} PDB=${2:?PDB} SVC=${3:?service} N=${4:?statements} ROUNDS=${5:?rounds}
d=$(cd "$(dirname "$0")" && pwd)
. "$d/../../oracle-performance-tuning-lab/lab.env"; : "${BANK_PASSWORD:?}"
ENV='. ~/.bash_profile >/dev/null 2>&1'
one() {  # one run: elapsed centiseconds on the first line of output
  { printf 'connect bank/"%s"@//localhost:1521/%s\n' "$BANK_PASSWORD" "$SVC"; cat <<SQL
set serveroutput on feedback off
declare
  v varchar2(10); t0 number := dbms_utility.get_time;
begin
  for i in 1 .. $N loop
    select status into v from bank.cards where card_id = mod(i, 1000) + 1;
  end loop;
  dbms_output.put_line('cs=' || (dbms_utility.get_time - t0));
end;
/
exit
SQL
  } | ssh -o BatchMode=yes "oracle@$H" "$ENV; sqlplus -s -L /nolog" 2>&1 | grep -E 'cs=|ORA-' | sed 's/cs=//'
}
count() { printf "set heading off feedback off pages 0\nalter session set container = %s;\nselect count(*) from unified_audit_trail where dbusername = 'BANK' and action_name = 'SELECT' and object_name = 'CARDS';\nexit\n" "$PDB" | ssh -o BatchMode=yes "oracle@$H" "$ENV; sqlplus -s / as sysdba" | grep -E '^[[:space:]]*[0-9]+[[:space:]]*$' | tr -d ' \t'; }
# the parameter only changes in the spfile: a PDB takes it when it is closed and opened
setp() { printf "alter session set container = %s;\nalter system set unified_audit_systemlog = '%s' scope = spfile;\nalter pluggable database close immediate;\nalter pluggable database open;\nexit\n" "$PDB" "$1" | ssh -o BatchMode=yes "oracle@$H" "$ENV; sqlplus -s / as sysdba" | { grep -E 'ORA-' || true; }; }
setp ''; base=$(count); one >/dev/null; c1=$(count)
echo "audit records per run: $(( c1 - base )) for $N statements"
for r in $(seq 1 "$ROUNDS"); do
  # the first run after opening the PDB has a cold cache: only the second is compared
  setp ''; one >/dev/null; a=$(one); setp 'LOCAL0.INFO'; one >/dev/null; b=$(one)
  echo "round $r: syslog off ${a} cs, syslog on ${b} cs"
done
setp 'LOCAL0.INFO'
