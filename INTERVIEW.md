# Interview prep — Oracle Security & Compliance

> Status: **not built yet.** These are preparation notes for the topics this lab will cover. Do not present
> them as finished work; present them as "what I know and what I am building".

## What already exists (real evidence)

While tuning in [oracle-performance-tuning-lab](https://github.com/phuochuyy/oracle-performance-tuning-lab)
the AWR wait list showed `Failed Logon Delay`. The unified audit trail showed **275 failed SYS logons
(ORA-01031) from the Data Guard observer host every ~12 s**, plus 5 ORA-01017 from the standby around
restarts — while FSFO reported the observer as healthy. Investigating that is the first task of this
lab: a real security-monitoring finding, found from a performance symptom.

## Topics and short answers

**What does TDE protect against, and what not?** Data at rest: datafiles, backups, redo/archived logs of
encrypted tablespaces are unreadable without the keys (stolen disk or backup). It does not protect against
a privileged user querying the data — that is access control, auditing, redaction.

**Licensing.** TDE and Data Redaction are part of the **Advanced Security Option** (extra license on
premises). Virtual Private Database, Unified Auditing, Privilege Analysis (since 19c) and DBSAT are
included / free.

**Keystore basics (23ai).** `WALLET_ROOT` + `TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=FILE'`; software
keystore with password, plus auto-login (or local auto-login) so the database opens unattended. Back up the
keystore with every key change — losing it means losing the data, and an RMAN backup of the database does
not contain it.

**TDE with Data Guard.** The standby needs the same keys: copy the keystore (or use OKV/HSM). Encrypted
tablespaces stay encrypted in redo, so redo transport carries encrypted blocks. Re-keying on the primary
requires copying the keystore again.

**TDE with GoldenGate.** Integrated Extract reads redo of encrypted tablespaces through the database
(keystore open). The trail on disk is a separate copy — encrypt it as well (trail encryption), otherwise
card numbers sit in clear text in the trail files.

**Unified Auditing — what to audit first?** Logon failures, privileged users (SYS, DBA role) activity, DDL,
grants, and access to sensitive tables. Audit policies are created with `CREATE AUDIT POLICY` and enabled
with `AUDIT POLICY ... BY/EXCEPT`.

**Least privilege.** Privilege Analysis (`DBMS_PRIVILEGE_CAPTURE`) records which privileges an application
really uses during a period, so unused ones can be revoked with evidence.

**PCI-DSS v4.0 mapping (the lab's target).**

| Requirement | Control in the lab |
|-------------|--------------------|
| 3 — protect stored account data | TDE, Data Redaction/VPD on `BANK.CARDS.PAN` (fake, Luhn-valid numbers from BANKDB) |
| 4 — encrypt transmission | SQL*Net native encryption or TLS |
| 7 — restrict access by need to know | roles + Privilege Analysis |
| 8 — identify and authenticate | password profiles, lockout |
| 10 — log and monitor | Unified Auditing policies |
| 11 — test security regularly | DBSAT report before and after |

## Planned evidence

DBSAT before/after, TDE on BANKDB with a switchover proving Data Guard and GoldenGate still work
(reusing `verify.py` from the HA/DR lab), audit records for each scenario.
