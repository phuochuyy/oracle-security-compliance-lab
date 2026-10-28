#!/bin/bash
# TDE keystore for the RAC primary orcl and its standby orcl_stb (united mode: one keystore per CDB,
# a master key per PDB). The keystore lives in ASM so every RAC instance opens the same one.
#   params   WALLET_ROOT (static: database restart, standby first) + TDE_CONFIGURATION, both sites
#   create   keystore, master keys for all PDBs, auto-login, backup copy off the database host
#   standby  copy the keystore to the standby (it does not travel with redo)
#   status   V$ENCRYPTION_WALLET on both sites
# Keystore password from lab.env (TDE_KEYSTORE_PASSWORD), sent on stdin.
# usage (from the host): ./01_keystore.sh params | create | standby | status
set -eu
REPO=$(cd "$(dirname "$0")/.." && pwd)
. "$REPO/lab.env"
: "${TDE_KEYSTORE_PASSWORD:?}"
PRM=prm1 STB=stb1
ESCROW=${ESCROW:-$HOME/oracle-lab/keystore-backup/orcl}   # off-host copy, outside every git repo
ENV=". ~/.bash_profile >/dev/null 2>&1"
G=/u01/app/23.26.0/grid/bin
sql() { ssh -o BatchMode=yes oracle@$1 "$ENV; sqlplus -s / as sysdba"; }
dgm() { printf '%s;\n' "$@" | ssh -o BatchMode=yes oracle@$PRM "$ENV; dgmgrl -silent /" | grep -vE "^$"; }
pw() { printf '"%s"' "$TDE_KEYSTORE_PASSWORD"; }

status() {
  for h in $PRM $STB; do
    echo "== $h"
    sql $h <<'SQL'
set lines 200 pages 50
col pdb for a10
col wrl_parameter for a28
col status for a20
col wallet_type for a10
col keystore_mode for a8
select p.name pdb, w.wrl_parameter, w.status, w.wallet_type, w.keystore_mode
  from v$encryption_wallet w left join v$containers p on p.con_id = w.con_id order by w.con_id;
select p.name pdb, count(k.key_id) master_keys, max(k.creation_time) last_key
  from v$containers p left join v$encryption_keys k on k.con_id = p.con_id group by p.name order by 1;
exit
SQL
  done
}

case ${1:?mode} in
params)
  # FSFO off for the restarts (a clean shutdown should not fail over, but the observer would report it),
  # GG_A off: its Extract runs on the primary
  dgm "disable fast_start failover"
  ssh -o BatchMode=yes root@$PRM "$G/agctl stop goldengate GG_A"
  for s in "$STB orcl_stb ORCL_STB" "$PRM orcl ORCL"; do
    read -r h db dir <<< "$s"
    ssh -o BatchMode=yes grid@$h "$ENV; asmcmd ls +DATA/$dir/tde >/dev/null 2>&1 || asmcmd mkdir +DATA/$dir/tde"
    printf "alter system set wallet_root = '+DATA/%s' scope = spfile sid = '*';\nexit\n" "$dir" | sql $h
    ssh -o BatchMode=yes oracle@$h "$ENV; srvctl stop database -db $db -stopoption immediate && srvctl start database -db $db"
    printf "alter system set tde_configuration = 'KEYSTORE_CONFIGURATION=FILE' scope = both sid = '*';\nexit\n" | sql $h
  done
  # the standby's PDBs come back MOUNTED after a restart (no saved state there)
  printf "alter pluggable database all open read only;\nexit\n" | sql $STB
  ssh -o BatchMode=yes root@$PRM "$G/agctl start goldengate GG_A"
  dgm "enable fast_start failover" "show configuration"
  status ;;

create)
  sql $PRM <<SQL
whenever sqlerror exit failure
administer key management create keystore identified by $(pw);
administer key management set keystore open identified by $(pw) container = all;
-- WITH BACKUP: the keystore is copied before it changes (ewallet_<time>_initial.p12 next to it)
administer key management set key using tag 'initial' force keystore identified by $(pw)
  with backup using 'initial' container = all;
-- auto-login (not LOCAL): opens without a password after a restart and can be copied to the standby
administer key management create auto_login keystore from keystore identified by $(pw);
exit
SQL
  # off-host copy of the keystore — losing it means losing every encrypted tablespace and backup
  mkdir -p -m 700 "$ESCROW"
  ssh -o BatchMode=yes grid@$PRM "$ENV; rm -rf /tmp/ks; mkdir -m 700 /tmp/ks
    for f in \$(asmcmd ls +DATA/ORCL/tde); do asmcmd cp +DATA/ORCL/tde/\$f /tmp/ks/ >/dev/null; done"
  ssh -o BatchMode=yes root@$PRM "cd /tmp/ks && tar cf - ." | tar xf - -C "$ESCROW"
  ssh -o BatchMode=yes root@$PRM "rm -rf /tmp/ks"
  chmod 600 "$ESCROW"/*; ls -l "$ESCROW" | sed 1d
  status ;;

standby)
  ssh -o BatchMode=yes root@$STB "rm -rf /tmp/ks; mkdir -m 700 /tmp/ks"
  tar cf - -C "$ESCROW" ewallet.p12 cwallet.sso | ssh -o BatchMode=yes root@$STB "tar xf - -C /tmp/ks; chown -R grid /tmp/ks"
  ssh -o BatchMode=yes grid@$STB "$ENV; for f in ewallet.p12 cwallet.sso; do asmcmd cp /tmp/ks/\$f +DATA/ORCL_STB/tde/\$f >/dev/null; done; asmcmd ls -l +DATA/ORCL_STB/tde"
  ssh -o BatchMode=yes root@$STB "rm -rf /tmp/ks"
  status ;;

status) status ;;
esac
