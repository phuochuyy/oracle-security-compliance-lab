#!/bin/bash
# Switchover orcl -> orcl_stb and back with TDE on. Checked on each new primary: keystore open without a
# password (auto-login), SECPDB open read write, BANKDB checksums, a write to the encrypted table, GG_A.
# Broker commands as C##DGADMIN (SYSDG only, see 01-baseline/failed-logons), password on stdin.
# usage (from the host): ./04_switchover.sh [log name]
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
. "$REPO/lab.env"
: "${DGADMIN_PASSWORD_A:?}"
dir=$(cd "$(dirname "$0")" && pwd); out=$dir/results/${1:-08-switchover}.log; : > "$out"
ENV=". ~/.bash_profile >/dev/null 2>&1"
G=/u01/app/23.26.0/grid/bin
say() { echo "$(date +%T) $*" | tee -a "$out"; }
dgm() { printf 'connect c##dgadmin/"%s"@orcl\n' "$DGADMIN_PASSWORD_A" | cat - <(printf '%s;\n' "$@") \
        | ssh -o BatchMode=yes oracle@prm1 "$ENV; dgmgrl -silent" 2>&1 | sed "s/$DGADMIN_PASSWORD_A/********/g" \
        | grep -vE "^$|^Connected" | tee -a "$out"; }
sql() { ssh -o BatchMode=yes oracle@$1 "$ENV; sqlplus -s / as sysdba" 2>&1 | grep -vE "^$" | tee -a "$out"; }

check() {   # check <host> of the new primary
  local h=$1
  say "new primary $h:"
  sql $h <<'SQL'
set lines 200 pages 50 feedback off
col db for a10
col wallet for a20
col secpdb for a12
select db_unique_name db, database_role,
       (select status || '/' || wallet_type from v$encryption_wallet where con_id = 1) wallet,
       (select open_mode from v$pdbs where name = 'SECPDB') secpdb from v$database;
SQL
  if ! printf "set heading off\nselect open_mode from v\$pdbs where name = 'SECPDB';\nexit\n" | ssh -o BatchMode=yes oracle@$h "$ENV; sqlplus -s / as sysdba" | grep -q "READ WRITE"; then
    say "SECPDB not READ WRITE -> open it"
    printf "alter pluggable database all open;\nexit\n" | sql $h
  fi
  ssh -o BatchMode=yes oracle@$h "$ENV; cd ~/bankdb; sqlplus -s / as sysdba @03_verify.sql SECPDB" \
    | tr -s ' \t' ' ' | grep -E "^[A-Z]{5,} [0-9]" | tee -a "$out"   # tabs first, then grep
  sql $h <<'SQL'
set feedback on
alter session set container = secpdb;
insert into bank.cards values (999998, 1, '4999000011112222', '12/30', 'ACTIVE', sysdate);
delete bank.cards where card_id = 999998;
commit;
SQL
  for i in $(seq 1 36); do
    g=$(ssh -o BatchMode=yes root@$h "$G/agctl status goldengate GG_A" 2>&1 || true)
    echo "$g" | grep -q "running on" && break; sleep 5
  done
  say "GG_A: $g"
}

dgm "show configuration"
for to in orcl_stb orcl; do
  [ $to = orcl_stb ] && h=stb1 || h=prm1
  # first attempt: the switchback sent 1 s after the switchover waited ~5 min in the broker (the new standby
  # had just been restarted) — wait until the broker says the target is ready
  for i in $(seq 1 60); do dgm "validate database $to" | grep -q "Ready for Switchover: *Yes" && break; sleep 10; done
  say "SWITCHOVER TO $to"
  t0=$(date +%s)
  dgm "switchover to $to"
  say "switchover command returned after $(( $(date +%s) - t0 )) s"
  check $h
  say "$to primary with GG_A after $(( $(date +%s) - t0 )) s"
  dgm "show configuration"
done
