#!/bin/bash
# Role-based service for SECPDB on both clusters (like GG_A's ogg_a): after a switchover the new primary
# starts the PRIMARY-role service, which opens the PDB. Without it SECPDB stayed MOUNTED on the new primary
# (SAVE STATE is per instance name: orcl1 is saved, orcl_stb1 is not).
# usage (from the host): ./05_secpdb_service.sh
set -eu
ENV=". ~/.bash_profile >/dev/null 2>&1"
for s in "prm1 orcl orcl1 orcl2" "stb1 orcl_stb orcl_stb1 orcl_stb2"; do
  read -r h db p a <<< "$s"
  ssh -o BatchMode=yes oracle@$h "$ENV
    srvctl config service -db $db -service secpdb_app >/dev/null 2>&1 ||
      srvctl add service -db $db -service secpdb_app -pdb SECPDB -role PRIMARY -preferred $p -available $a -policy AUTOMATIC
    srvctl config service -db $db -service secpdb_app | grep -E 'Service name|role|Pluggable|Preferred'"
done
ssh -o BatchMode=yes oracle@prm1 "$ENV; srvctl start service -db orcl -service secpdb_app; srvctl status service -db orcl -service secpdb_app"
