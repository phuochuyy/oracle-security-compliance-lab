# Sourced by the security test scripts so they keep working once Database Vault is enabled in their PDB:
#   dv_on <host> <PDB>             true when Database Vault is enabled there
#   dv_window <host> open <reason> | close   change window through dv.sh (SYS becomes realm owner for the test, then not)
#   dv_users <host> <PDB service>  SQL on stdin as the Database Vault account manager (users and profiles are its job)
# The region follows from the host: prm1/prm2/stb1/stb2 = A, prm3/stb3 = B. Passwords from this repository's lab.env, on stdin.
DVDIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
dv_region() { case $1 in prm[12]|stb[12]) echo A ;; *) echo B ;; esac; }
dv_on() {
  printf "set heading off feedback off pages 0\nselect status from cdb_dv_status s join v\$containers c on c.con_id = s.con_id where c.name = upper('%s') and s.name = 'DV_ENABLE_STATUS';\nexit\n" "$2" \
    | ssh -o BatchMode=yes "oracle@$1" ". ~/.bash_profile >/dev/null 2>&1; sqlplus -s / as sysdba" | grep TRUE >/dev/null
}
dv_window() { local h=$1; shift; DV_REGION=$(dv_region "$h") "$DVDIR/dv.sh" window "$@" | tail -n 2; return "${PIPESTATUS[0]}"; }
dv_users() {
  local h=$1 svc=$2 pw sfx; [ "$(dv_region "$h")" = A ] && sfx=_A || sfx=
  pw=$( . "$DVDIR/../lab.env"; v=DV_ACCTMGR_PASSWORD$sfx; printf '%s' "${!v:-}")
  [ -n "$pw" ] || { echo "DV_ACCTMGR_PASSWORD$sfx is empty" >&2; return 1; }
  { printf 'connect c##dvacctmgr/"%s"@//%s.rac:1521/%s\n' "$pw" "$h" "$svc"; cat; echo exit; } \
    | ssh -o BatchMode=yes "oracle@$h" ". ~/.bash_profile >/dev/null 2>&1; sqlplus -s -L /nolog" 2>&1 \
    | sed -E 's/(identified by )"[^"]*"/\1"********"/Ig' | { grep -vE '^$|^Connected' || true; }
}
