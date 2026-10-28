# Interview prep — Oracle Security & Compliance

> Status: **in progress.** Finding 1 and **TDE (on RAC + Data Guard + GoldenGate) are done with evidence**;
> auditing policies, redaction, Privilege Analysis and DBSAT are still preparation notes — present them as
> "what I know and what I am building".

## What already exists (real evidence)

While tuning in [oracle-performance-tuning-lab](https://github.com/phuochuyy/oracle-performance-tuning-lab)
the AWR wait list showed `Failed Logon Delay`. The unified audit trail showed **275 failed SYS logons
(ORA-01031) from the Data Guard observer host every ~12 s** (1,325 by the time I fixed it) — while FSFO
reported the observer as healthy.

**Cause:** the observer's wallet held SYS. DGMGRL tries SYSDG first; SYS had no SYSDG in the password file,
so every connection failed once and then succeeded as SYSDBA. **Fix:** a common user with only SYSDG
(`C##DGADMIN`) in a new wallet — the old wallet's password was nowhere, which is its own finding. Tested
the wallet with a temporary `TNS_ADMIN` before swapping, then enabled FSFO briefly to prove the
observer still works: 0 failed logons. Least privilege (the observer does not need SYSDBA) and the
failed-logon alert becomes meaningful again.

**Still open, and I say so:** 2 ORA-01017 with an empty username each time the standby starts. I ruled out
the password file (copied it — no change), the broker, a wallet and the startup scripts.

**Why SYSDG and not SYSDBA for Data Guard?** Separation of duties (12c+): SYSDG can do Data Guard operations
(switchover, failover, observer) but cannot read application data or change users.

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

## TDE — what I did and what broke (real evidence, [02-tde](02-tde/))

**Setup in one breath.** RAC primary + ADG standby. `WALLET_ROOT` in ASM (static, so a restart — standby
first), united-mode keystore, a master key per PDB, auto-login (not local, so it can be copied), the
keystore copied to the standby, an off-host copy of the `.p12`. Then `ALTER TABLESPACE ... ENCRYPTION
ONLINE ... ENCRYPT`: 6 s for 512 MB, the standby converted its own file while applying redo.

**How did you prove it works?** I grep a real card number in the raw files, no database login: datafile on
both sites, an archived log, an RMAN backup piece — 3–4 hits each before, 0 after. Plus a reader and a writer
running during a REKEY: 0 errors. Checksums of the dataset equal on both sites.

**What did TDE not fix?** Everything written before: 2 archived logs still had the card number — one of them
from a *test* PDB with the same data that nobody had encrypted (encrypted it too: test copies of card data
are in PCI scope). And GoldenGate: Integrated Extract reads encrypted redo without any change, but writes
the **trail in clear** — on the RAC's DBFS and, after the distribution path, on the other site. Fixed with
`ENCRYPTTRAIL AES256`; it needed a master key in the GG wallet, shared by both deployments because the
other site's Replicat decrypts the trail.

**TDE with Data Guard — the drill I would mention first.** I rotated the master key on the primary and did
not copy the keystore: redo apply stopped within seconds with `ORA-28374` — for the **whole CDB**, not only
that PDB. Copying the keystore fixed it in 37 s. Rule: copy the keystore to every standby right after
`SET KEY`.

**Did you ever restore the keystore backup?** Yes: deleted the standby's keystore and restarted it, restored
from the off-host `.p12` with the password, recreated the auto-login keystore there: apply running again in
19 s. And it taught me one more thing: the keystore stayed open as `PASSWORD` type, so after the next
switchover the new primary could not open the keystore for a PDB (`ORA-28365`). After a password-based
restore, close it so it runs on auto-login — and check `WALLET_TYPE` before a switchover.

**Mistakes I made.** A failing `ADMINISTER KEY MANAGEMENT` statement printed the keystore password in my
terminal (sqlplus echoes the statement). I changed the password, deleted backups made under the old one, and
mask the password in every script output now. Also: every `BACKUP KEYSTORE` writes another `cwallet.sso` —
a password-free copy of the keys — so the off-host copy keeps only `.p12` files.

**Switchover with TDE.** 57–63 s each way with auto-login keystores, GG_A followed. The PDB stayed
`MOUNTED` on the new primary (saved state is per instance name) → role-based service for it on both clusters.

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

DBSAT before/after (needs the DBSAT download), audit records for each scenario, Privilege Analysis results,
redaction/VPD queries as app vs auditor user, network encryption in `V$SESSION_CONNECT_INFO`.
