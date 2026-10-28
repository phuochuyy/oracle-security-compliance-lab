#!/bin/bash
# SECPDB: the PDB this lab hardens — shared BANKDB dataset at scale 1 on the RAC primary orcl (ASM +DATA),
# protected by the Data Guard standby orcl_stb (default STANDBYS=ALL). BANK.CARDS.PAN holds card-like
# numbers in clear text: the data TDE, redaction and auditing are about.
# Passwords from lab.env (SECPDB_ADMIN_PASSWORD, BANK_PASSWORD), sent on stdin, never on a command line.
# usage (from the host): ./create_secpdb.sh
set -eu
. "$(cd "$(dirname "$0")/.." && pwd)/lab.env"
: "${SECPDB_ADMIN_PASSWORD:?}" "${BANK_PASSWORD:?}"
PRM=prm1
S="ssh -o BatchMode=yes oracle@$PRM"
ENV=". ~/.bash_profile >/dev/null 2>&1; cd ~/bankdb"

printf 'whenever sqlerror exit failure
create pluggable database secpdb admin user pdbadmin identified by "%s" create_file_dest = '"'+DATA'"';
alter pluggable database secpdb open instances = all;
alter pluggable database secpdb save state instances = all;
exit\n' "$SECPDB_ADMIN_PASSWORD" | $S "$ENV; sqlplus -s / as sysdba"

# 01_schema.sql takes the password as &2: define it on stdin so it stays out of ps
printf 'define 1 = SECPDB\ndefine 2 = "%s"\n@01_schema.sql\n' "$BANK_PASSWORD" | $S "$ENV; sqlplus -s / as sysdba" > /dev/null
$S "$ENV; sqlplus -s / as sysdba @02_load.sql SECPDB 1" | grep -E "rows created|ORA-"
$S "$ENV; sqlplus -s / as sysdba @03_verify.sql SECPDB"
