#!/bin/bash
# Separate administrative privileges instead of SYS for everything:
#   C##BKADMIN   SYSBACKUP   RMAN jobs. Can back up and recover; cannot read application data.
#   C##KEYADMIN  SYSKM       master keys and keystores. Can rotate a key; cannot read data or run a backup.
# (Data Guard already runs as C##DGADMIN with SYSDG.) Grants go to the password file, which Data Guard copies to the standby.
# Passwords are random, kept in this repository's lab.env (mode 600) as <NAME>_PASSWORD_<A|B>, sent on stdin only.
# usage (from the host): ./07_admin_roles.sh <primary host> <A|B>     e.g. prm3 B
set -eu -o pipefail
H=${1:?primary host} R=${2:?region A or B}
d=$(cd "$(dirname "$0")/.." && pwd); ENVF=$d/lab.env
. "$ENVF"
gen() { python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Ab12#'+''.join(secrets.choice(a) for _ in range(14))+'_9')"; }
get_pw() {  # get_pw <variable>: the value from lab.env, created there the first time
  local v=$1 p
  p=${!v:-}
  if [ -z "$p" ]; then p=$(gen); printf "%s='%s'\n" "$v" "$p" >> "$ENVF"; fi
  printf '%s' "$p"
}
pb=$(get_pw "BKADMIN_PASSWORD_$R"); pk=$(get_pw "KEYADMIN_PASSWORD_$R")
out=$(ssh -o BatchMode=yes "oracle@$H" '. ~/.bash_profile >/dev/null 2>&1; sqlplus -s / as sysdba' 2>&1 <<SQL
set feedback on lines 150
create user c##bkadmin identified by "$pb" profile c##svc_profile container = all;
alter user c##bkadmin account unlock container = all;
grant create session, set container to c##bkadmin container = all;
grant sysbackup to c##bkadmin container = all;
create user c##keyadmin identified by "$pk" profile c##svc_profile container = all;
alter user c##keyadmin account unlock container = all;
grant create session, set container to c##keyadmin container = all;
grant syskm to c##keyadmin container = all;
set heading on feedback off pages 20
col username for a18
select username, sysdba, sysbackup, sysdg, syskm, account_status from v\$pwfile_users order by 1;
exit
SQL
)
printf '%s\n' "$out" | grep -vE '^$' | grep -E 'ORA-[0-9]+|USERNAME|^---|C##|^SYS ' | grep -v 'ORA-01920' | cut -c1-100
if printf '%s\n' "$out" | grep -E 'ORA-[0-9]+' | grep -vE 'ORA-01920' | grep -q .; then echo "STOP: unexpected error above" >&2; exit 1; fi
