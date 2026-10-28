# Interview prep — Oracle Security & Compliance

> Status: **done with evidence** — failed logons, TDE (RAC + Data Guard + GoldenGate), network encryption,
> profiles/privileges, Unified Auditing, redaction, assessment 27 FAIL → 0. Still preparation notes only:
> Privilege Analysis, VPD, audit retention — say so if asked.

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

## Assessment without DBSAT

**Why no DBSAT?** It is free, but only through My Oracle Support with a support contract; registering my
OCI Free Tier CSI failed. I wrote the checks myself in the CIS Benchmark sections (parameters, users,
privileges, audit, network) plus PCI checks for the card table: 27 FAIL before, 0 after, 5 ACCEPTs with a
written reason each. **What I learned about my own checks:** two audit checks said PASS while my test showed
the gap — so a check that reads the dictionary is not enough, every control got a test scenario.

## Network encryption

`sqlnet.ora` on the server only: `ENCRYPTION_SERVER = REQUIRED` (AES256), `CRYPTO_CHECKSUM_SERVER =
REQUIRED` (SHA256), `ALLOWED_LOGON_VERSION_SERVER = 12a`. Clients default to ACCEPTED, so they negotiate.
Proof in `V$SESSION_CONNECT_INFO` (adapter banners). **Catch:** existing sessions stay unencrypted —
GoldenGate, the observer and redo transport were encrypted only after reconnecting (redo transport: after a
standby restart, 5/5). Before the change nothing was encrypted, including redo between the two sites.

## Profiles and least privilege

People: 90-day expiry, lockout after 5, reuse limits, `ORA12C_STRONG_VERIFY_FUNCTION` (it rejected my own
test password). Service accounts with a wallet password (observer): same, but no expiry — documented
ACCEPT, because an expired wallet password silently leaves FSFO without an observer. The data owner `BANK`
is schema-only (`NO AUTHENTICATION`). **What broke:** revoking `UTL_TCP/UTL_HTTP/...` from PUBLIC made 14
Oracle objects invalid (Oracle Text incl. `DBMS_VECTOR_CHAIN`, GSM incl. a logoff trigger, Spatial).
`DBA_DEPENDENCIES` showed which package each needed; direct grants + `UTL_RECOMP` → 0 invalid. Next time:
dependency query and grants *before* the revoke.

## Unified Auditing — what I audit and two mistakes I made

Card table access (`SELECT/INSERT/UPDATE/DELETE ON bank.cards`), grants/revokes, code and trigger DDL,
successful and failed logons, all SYS top-level statements (`ORA_ALL_TOPLEVEL_ACTIONS BY SYS`, the 23ai
replacement for `AUDIT_SYS_OPERATIONS`), plus the predefined `ORA_SECURECONFIG`.
1. `actions select, insert, update, delete on bank.cards` — `ON` binds only to the last action: SELECT was
   audited on every object. Write `select on bank.cards, insert on bank.cards, ...`.
2. A **common** policy enabled in the root did not audit DDL of a **local** user in the PDB — tested with a
   procedure created with and without a local policy. Local users need local policies.

## Data Redaction

Partial redaction on PAN (last 4 visible) unless the session has a role. Not access control: a user who
sees only masks can still run `WHERE pan = '...'` and confirm a number — so CARDS access is also audited and
granted per role. SYS and `EXEMPT REDACTION POLICY` holders always see clear values.

**PCI-DSS v4.0 mapping** — with evidence links: [05-assessment/pci-dss-mapping.md](05-assessment/pci-dss-mapping.md).
3.4.1 redaction, 3.5.1 TDE + trail encryption, 3.6/3.7 key procedures, 4.2.1 network encryption, 7.2 least
privilege, 8.3 profiles, 10.2.1 audit policies, 11.3 assessment before/after.

## Not done yet (say it if asked)

Privilege Analysis (`DBMS_PRIVILEGE_CAPTURE`) for an application user, VPD, audit trail retention/purge
(PCI-DSS 10.5 — a deletion job I would agree with the team first), the 2 ORA-01017 per standby start.
