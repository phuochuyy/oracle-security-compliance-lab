#!/bin/bash
# Do the standby's keystores hold every master key the primary has? A standby without the current key stops redo apply with
# ORA-28374 at the first encrypted block, and a keystore does not travel with redo (02-tde/README.md, finding 5).
# Compares key IDs container by container. It tells you why apply stopped, or that it is about to: with real-time apply
# the standby reaches the new key within seconds of a SET KEY, so prevention is 08_rotate_key.sh, not this check.
# No password: both keystores are auto-login. No key material in the output: a key ID identifies a key, it does not reveal it.
# usage (from the host): ./07_key_check.sh <primary host> <standby host>     e.g. prm3 stb3
# exit code = number of containers with a key missing on the standby
set -u
P=${1:?primary host} S=${2:?standby host}
keys() {
  printf "set heading off feedback off pages 0 lines 200\nselect con_id || ' ' || key_id from v\$encryption_keys order by 1;\nexit\n" \
    | ssh -o BatchMode=yes -o ConnectTimeout=5 "oracle@$1" '. ~/.bash_profile >/dev/null 2>&1; sqlplus -s / as sysdba' 2>&1
}
a=$(keys "$P") b=$(keys "$S")
for x in "$a" "$b"; do
  if grep -qE 'ORA-|SP2-|Permission denied|timed out' <<< "$x"; then echo "CRIT cannot read keys: $(grep -m1 -E 'ORA-|SP2-|denied|timed' <<< "$x" | cut -c1-100)"; exit 99; fi
done
bad=0
for c in $(awk '{print $1}' <<< "$a" | sort -un); do
  n=$(awk -v c="$c" '$1 == c' <<< "$a" | wc -l)
  m=$(comm -23 <(awk -v c="$c" '$1 == c {print $2}' <<< "$a" | sort) <(awk -v c="$c" '$1 == c {print $2}' <<< "$b" | sort) | wc -l)
  if [ "$m" = 0 ]; then echo "OK   con_id $c: $n keys on $P, all on $S"
  else echo "CRIT con_id $c: $m of $n keys on $P are missing on $S: copy the keystore now, then check apply"; bad=$((bad + 1)); fi
done
exit "$bad"
