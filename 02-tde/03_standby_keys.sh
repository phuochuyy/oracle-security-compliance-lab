#!/bin/bash
# Drills: the standby's keystore after TDE is on.
#   rotate   new master key for SECPDB on the primary, keystore NOT copied to the standby, then DML on
#            the encrypted table — what does redo apply do? Then copy the keystore and time the recovery.
#   lost     standby keystore deleted + standby restarted; restore from the off-host copy (.p12 only, so
#            the auto-login keystore has to be recreated on the standby with the password)
# usage (from the host): ./03_standby_keys.sh rotate | lost
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
. "$REPO/lab.env"
: "${TDE_KEYSTORE_PASSWORD:?}"
mode=${1:?mode}
dir=$(cd "$(dirname "$0")" && pwd); out=$dir/results/07-standby-$mode.log; : > "$out"
PRM=prm1 STB=stb1
ESCROW=${ESCROW:-$HOME/oracle-lab/keystore-backup/orcl}
ENV=". ~/.bash_profile >/dev/null 2>&1"
ALERT=/u01/app/oracle/diag/rdbms/orcl_stb/orcl_stb1/trace/alert_orcl_stb1.log
mask() { sed "s/$(printf '%s' "$TDE_KEYSTORE_PASSWORD" | sed 's/[]\/$*.^[]/\\&/g')/********/g"; }
say() { echo "$(date +%T) $*" | tee -a "$out"; }
sql() { ssh -o BatchMode=yes oracle@$1 "$ENV; sqlplus -s / as sysdba" 2>&1 | mask | grep -vE "^$" | tee -a "$out"; }
pw() { printf '"%s"' "$TDE_KEYSTORE_PASSWORD"; }
ts() { date +%s; }
stb_state() {
  sql $STB <<'SQL'
set lines 200 pages 50 feedback off
col value for a20
col wallet for a22
select (select status || '/' || wallet_type from v$encryption_wallet where con_id = 1) wallet,
       (select count(*) from v$encryption_keys) keys,
       (select status from v$managed_standby where process = 'MRP0') mrp,
       (select value from v$dataguard_stats where name = 'apply lag') apply_lag
  from dual;
SQL
}
dml() {   # real change on the encrypted table, checksums unchanged
  sql $PRM <<'SQL' >/dev/null
alter session set container = secpdb;
update bank.cards set status = status where card_id <= 1000;
commit;
alter system archive log current;
SQL
}
alert_new() { ssh -o BatchMode=yes oracle@$STB "tail -n +$1 $ALERT | grep -E 'ORA-|MRP0.*(terminat|stop|start)|Recovery of|keystore|wallet' | sort -u | head -n 12" | tee -a "$out"; }
alert_len() { ssh -o BatchMode=yes oracle@$STB "wc -l < $ALERT"; }
lag_zero() {  # wait until apply lag is 0 (or give up after $1 s)
  for i in $(seq 1 $(( $1 / 5 ))); do
    l=$(printf "set heading off feedback off\nselect value from v\$dataguard_stats where name = 'apply lag';\nexit\n" \
        | ssh -o BatchMode=yes oracle@$STB "$ENV; sqlplus -s / as sysdba" | grep -oE "\+[0-9 :]+" | head -n 1)
    [ "$l" = "+00 00:00:00" ] && return 0; sleep 5
  done; return 1
}

case $mode in
rotate)
  say "standby before:"; stb_state
  a=$(alert_len)
  say "SET KEY for SECPDB on the primary — keystore not copied"
  sql $PRM <<SQL
alter session set container = secpdb;
administer key management set key using tag 'rotate_drill' force keystore identified by $(pw) with backup using 'rotate_drill';
SQL
  dml; say "DML on BANK.CARDS, log archived"
  sleep 30
  say "standby 30 s later:"; stb_state
  say "standby alert log since the rotation:"; alert_new "$a"
  t0=$(ts)
  say "copy the keystore to the standby (01_keystore.sh escrow)"
  "$dir/01_keystore.sh" escrow | tee -a "$out"
  # MRP may have stopped on the missing key: start it again through the broker
  printf "edit database orcl_stb set state='APPLY-ON';\n" | ssh -o BatchMode=yes oracle@$PRM "$ENV; dgmgrl -silent /" | tail -n 1 | tee -a "$out"
  lag_zero 300 && say "apply lag 0 — $(( $(ts) - t0 )) s after starting the copy" || say "apply lag NOT 0 after 300 s"
  stb_state ;;

lost)
  say "standby before:"; stb_state
  say "delete the standby's keystore files and restart the standby"
  ssh -o BatchMode=yes grid@$STB "$ENV; for f in \$(asmcmd ls +DATA/ORCL_STB/tde); do asmcmd rm -f +DATA/ORCL_STB/tde/\$f; done; asmcmd ls +DATA/ORCL_STB/tde | wc -l"
  ssh -o BatchMode=yes oracle@$STB "$ENV; srvctl stop database -db orcl_stb -stopoption immediate; srvctl start database -db orcl_stb"
  a=$(alert_len)
  sql $STB <<'SQL'
alter pluggable database all open read only;
SQL
  dml; say "DML on BANK.CARDS, log archived"
  sleep 30
  say "standby without keystore:"; stb_state
  sql $STB <<'SQL'
alter session set container = secpdb;
select count(*) from bank.cards;
SQL
  say "standby alert log:"; alert_new "$a"
  t0=$(ts)
  say "restore: off-host ewallet.p12 -> standby ASM, open with the password, recreate auto-login"
  ssh -o BatchMode=yes root@$STB "rm -rf /tmp/ks; mkdir -m 700 /tmp/ks"
  ssh -o BatchMode=yes root@$STB "cat > /tmp/ks/ewallet.p12; chown -R grid /tmp/ks" < "$ESCROW/ewallet.p12"
  ssh -o BatchMode=yes grid@$STB "$ENV; asmcmd cp /tmp/ks/ewallet.p12 +DATA/ORCL_STB/tde/ewallet.p12 >/dev/null"
  ssh -o BatchMode=yes root@$STB "rm -rf /tmp/ks"
  sql $STB <<SQL
administer key management set keystore open identified by $(pw) container = all;
administer key management create auto_login keystore from keystore identified by $(pw);
SQL
  printf "edit database orcl_stb set state='APPLY-ON';\n" | ssh -o BatchMode=yes oracle@$PRM "$ENV; dgmgrl -silent /" | tail -n 1 | tee -a "$out"
  lag_zero 300 && say "apply lag 0 — $(( $(ts) - t0 )) s after starting the restore" || say "apply lag NOT 0 after 300 s"
  stb_state
  sql $STB <<'SQL'
alter session set container = secpdb;
select count(*) from bank.cards;
SQL
  ;;
esac
