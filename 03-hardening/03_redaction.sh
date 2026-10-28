#!/bin/bash
# Data Redaction on BANK.CARDS.PAN (PCI-DSS 3.4.1: show at most the first 6 / last 4 digits).
# Full PAN only for sessions with the role CARD_FULL_VIEW enabled; everybody else sees ************1234.
# Test users: ANALYST2 (SELECT on CARDS), FRAUD_OPS (SELECT + CARD_FULL_VIEW). Both dropped at the end.
# Also shows what redaction does NOT do: the WHERE clause still sees the real value.
# usage (from the host): ./03_redaction.sh
set -eu
ENV=". ~/.bash_profile >/dev/null 2>&1"
sql() { ssh -o BatchMode=yes oracle@prm1 "$ENV; sqlplus -s / as sysdba" 2>&1 | grep -vE "^$"; }
gen() { python3 -c "import secrets,string; a=string.ascii_letters+string.digits; print('Ab12'+''.join(secrets.choice(a) for _ in range(12))+'#_')"; }
pa=$(gen) pf=$(gen)
as() { ssh -o BatchMode=yes oracle@prm1 "$ENV; sqlplus -s -L '$1/\"$2\"@//prm1.rac:1521/secpdb_app.rac'" 2>&1 | grep -vE "^$"; }

sql <<SQL | grep -E "ORA-|completed|created|succeeded"
alter session set container = secpdb;
create role card_full_view;
begin
  dbms_redact.add_policy(
    object_schema       => 'BANK',
    object_name         => 'CARDS',
    policy_name         => 'CARDS_PAN_MASK',
    column_name         => 'PAN',
    function_type       => dbms_redact.partial,
    -- 16 digits, no separators: keep the last 4, '*' for positions 1-12
    function_parameters => 'VVVVVVVVVVVVVVVV,VVVVVVVVVVVVVVVV,*,1,12',
    expression          => 'SYS_CONTEXT(''SYS_SESSION_ROLES'', ''CARD_FULL_VIEW'') = ''FALSE''',
    policy_description  => 'PCI-DSS 3.4.1: PAN masked unless CARD_FULL_VIEW is enabled');
end;
/
create user analyst2 identified by "$pa" profile sec_admin_profile;
create user fraud_ops identified by "$pf" profile sec_admin_profile;
grant create session to analyst2, fraud_ops;
grant select on bank.cards to analyst2, fraud_ops;
grant card_full_view to fraud_ops;
SQL

q="set lines 120 feedback off
col pan for a20
select card_id, pan, expiry from bank.cards where card_id <= 3 order by card_id;"
echo "== ANALYST2 (no role)"; as analyst2 "$pa" <<< "$q"
# FRAUD_OPS gets the full number from the database; this script replaces its middle digits by '#' (not the
# redaction '*') in its own output, so no full PAN ends up in a log or in git, even a synthetic one
echo "== FRAUD_OPS (CARD_FULL_VIEW) — database returns the full PAN, middle digits replaced by # by this script"
as fraud_ops "$pf" <<< "$q" | sed -E 's/\b([0-9]{4})[0-9]{8}([0-9]{4})\b/\1########\2/g'
echo "== ANALYST2: the WHERE clause still uses the real value (redaction is display masking, not access control)"
real=$(printf "set heading off feedback off\nalter session set container = secpdb;\nselect pan from bank.cards where card_id = 1;\nexit\n" | sql | grep -E "^[0-9]{16}$")
as analyst2 "$pa" <<< "set feedback off
select count(*) cards_matching_guess from bank.cards where pan like '${real:0:6}%';
select count(*) exact_match from bank.cards where pan = '$real';"
echo "(the guessed values are the BIN of card 1 and the full PAN — run as the analyst, who only sees masks)"

sql <<'SQL' | grep -E "ORA-|dropped"
alter session set container = secpdb;
drop user analyst2 cascade;
drop user fraud_ops cascade;
SQL
