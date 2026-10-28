#!/bin/bash
# Least-privilege observer: a common user with only SYSDG, and a new observer wallet that holds it.
# Passwords come from lab.env at the repo root (DGADMIN_PASSWORD, OBS_WALLET_PASSWORD), passed on stdin.
# usage (from the host): ./setup_dgadmin.sh    then ./restart_observer.sh
set -eu
. "$(cd "$(dirname "$0")/../.." && pwd)/lab.env"
: "${DGADMIN_PASSWORD:?}" "${OBS_WALLET_PASSWORD:?}"
PRM=prm3 OBS=obs-r2 ALIASES="orcl3 orcl3_stb"

printf 'create user c##dgadmin identified by "%s" container=all;\ngrant sysdg to c##dgadmin container=all;\nexit\n' \
  "$DGADMIN_PASSWORD" | ssh -o BatchMode=yes oracle@$PRM '. ~/.bash_profile >/dev/null 2>&1; sqlplus -s / as sysdba'

# new wallet next to the old one (the old wallet's password was unknown)
printf '%s\n%s\n' "$OBS_WALLET_PASSWORD" "$OBS_WALLET_PASSWORD" | ssh -o BatchMode=yes oracle@$OBS \
  '. ~/.bash_profile >/dev/null 2>&1; rm -rf ~/wallet.new; mkdir -m 700 ~/wallet.new; mkstore -wrl ~/wallet.new -create >/dev/null'
for a in $ALIASES; do
  printf '%s\n%s\n%s\n' "$DGADMIN_PASSWORD" "$DGADMIN_PASSWORD" "$OBS_WALLET_PASSWORD" | ssh -o BatchMode=yes oracle@$OBS \
    ". ~/.bash_profile >/dev/null 2>&1; mkstore -wrl ~/wallet.new -createCredential $a c##dgadmin >/dev/null"
done

# test the new wallet with a temporary TNS_ADMIN before using it
ssh -o BatchMode=yes oracle@$OBS ". ~/.bash_profile >/dev/null 2>&1; T=\$(mktemp -d); cp \$TNS_ADMIN/tnsnames.ora \$T/
sed 's#/home/oracle/wallet#/home/oracle/wallet.new#' \$TNS_ADMIN/sqlnet.ora > \$T/sqlnet.ora; export TNS_ADMIN=\$T
for a in $ALIASES; do
  printf \"set heading off feedback off\nselect sys_context('USERENV','AUTHENTICATED_IDENTITY')||' as '||sys_context('USERENV','SESSION_USER')||' @ '||sys_context('USERENV','DB_UNIQUE_NAME') from dual;\n\" \
    | sqlplus -s -L /@\$a as sysdg | grep -v '^\$'
done; rm -rf \$T"
echo "new wallet OK — swap: mv ~/wallet ~/wallet.bak_sys && mv ~/wallet.new ~/wallet, then ./restart_observer.sh"
