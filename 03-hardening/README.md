# Hardening — parameters, network, profiles, privileges, redaction

Findings come from the [assessment baseline](../05-assessment/results/before.txt); each step is re-checked
by [`assess.sh`](../05-assessment/assess.sh) at the end.

## 1. Parameters and network — [`01_params_network.sh`](01_params_network.sh)

| Change | Where | Why |
|--------|-------|-----|
| `GLOBAL_NAMES = TRUE`, `SEC_PROTOCOL_ERROR_TRACE_ACTION = LOG` | primary + standby, dynamic (`scope = both`) | P02, P08; no database links exist, nothing to break |
| `sqlnet.ora` in the database home: `SQLNET.ENCRYPTION_SERVER = REQUIRED` (AES256), `CRYPTO_CHECKSUM_SERVER = REQUIRED` (SHA256), `ALLOWED_LOGON_VERSION_SERVER = 12a` | prm1, stb1 (no file existed) | N01–N03, PCI-DSS 4.2 — card data between sites and to GoldenGate |
| `ADMIN_RESTRICTIONS_LISTENER = ON` | grid home `listener.ora`, `lsnrctl reload` | N04: no runtime `SET` commands on the listener |
| `AUDIT_SYS_OPERATIONS` | not changed | static, and in 26ai it only drives the desupported traditional audit — SYS is audited by a unified policy instead (see auditing) |

**Result** — TCP sessions with the AES256 / SHA256 adapters in `V$SESSION_CONNECT_INFO`
([`before`](results/01-network-before.txt), [`after`](results/01-network-after.txt)):

| Connection | Before | After |
|------------|--------|-------|
| new client connection (BANK → `secpdb_app`) | no encryption adapter | AES256 + SHA256 |
| GoldenGate Extract / Replicat (after restart) | 0 / 8 | **8 / 8** |
| observer obs-r1 (after restart) | 0 / 3 | **3 / 3** + 1 on the standby |
| **redo transport + broker primary → standby** (after a standby restart) | 0 / 6 | **5 / 5** |
| `dbfs_client` (GoldenGate's DBFS mount) | 0 / 4 | 0 / 4 — old sessions, encrypted after the next remount |

Only the server side was changed: 26ai clients default to `ACCEPTED`, so they negotiate encryption when
the server requires it. Sessions opened before the change keep running unencrypted until they reconnect —
the "after" numbers needed restarts of GoldenGate, the observer and the standby.

**prm2 and stb2** were off when this was applied, and stayed unencrypted. Now the lab's boot script installs
the same `sqlnet.ora` and listener line on every Region A RAC node each time it starts one
([`vm-nne.sh`](https://github.com/phuochuyy/oracle-ha-dr-failover-lab/blob/main/lab/files/vm-nne.sh), called
from `labctl` `sync_node`; no change when the file already matches). prm2: installed at boot, a new connection
through prm2's listener landed on instance `orcl2` with AES256 + SHA256
([`results/01-nne-prm2-20261103.txt`](results/01-nne-prm2-20261103.txt)). stb2: installed at its next boot.

Also fixed in `01_params_network.sh verify`: it passed the PDBADMIN password on the sqlplus command line
(readable with `ps` on prm1). Now `sqlplus /nolog` and `CONNECT` on stdin; `verify [node] [service]`.

## 2. Profiles, schema-only owner, PUBLIC grants — [`02_profiles_privs.sh`](02_profiles_privs.sh)

| Change | Why |
|--------|-----|
| `C##SVC_PROFILE` (common) → `C##DGADMIN`: 5 failed logins, lock 1 day, reuse 20/365, `ORA12C_STRONG_VERIFY_FUNCTION`, 10 sessions, inactive 120 days, **no password expiry** | U10. The observer's password lives in a wallet: if it expired, FSFO would lose its observer silently. Expiry is the one visible ACCEPT; rotation is a manual procedure |
| `SEC_ADMIN_PROFILE` (SECPDB) → `PDBADMIN`: all CIS limits incl. 90-day expiry | U10, PCI-DSS 8.3 |
| `BANK` → `NO AUTHENTICATION` (schema-only account) | the data owner cannot log in at all; access goes through granted users (next step) |
| `REVOKE EXECUTE ... FROM PUBLIC` on `UTL_TCP/SMTP/HTTP/INADDR`, `HTTPURITYPE`, `DBMS_LDAP`, `UTL_FILE`, `DBMS_ADVISOR` — root and SECPDB (the grants are local per container, `COMMON=NO`) | R01, R02 |
| kept: `DBMS_SQL`, `DBMS_LOB`, `DBMS_SCHEDULER`, `DBMS_JOB`, `DBMS_RANDOM`, `DBMS_XMLGEN`, `DBMS_JAVA` — ACCEPT | used by Oracle components and applications; removing needs per-component testing |

**What broke:** after the revokes, **11 Oracle objects invalid in CDB$ROOT and 3 in SECPDB** — Oracle Text
(`CTXSYS`, including `DBMS_VECTOR_CHAIN`), GSM (`GSMADMIN_INTERNAL`, including the database logoff trigger
`GSMLOGOFF`) and `MDSYS` used the `PUBLIC` grant. `DBA_DEPENDENCIES` of the invalid objects named the
packages; a direct grant to exactly those owners + `UTL_RECOMP` → **0 invalid** in both containers.
In production: run the dependency query and the invalid-object count *before* revoking, and grant first.

Checked afterwards: PDBADMIN connects (encrypted), BANK gets `ORA-01017`, the observer still logs in with
the new profile, Data Guard `SUCCESS`. Log: [`results/02-profiles-privs.log`](results/02-profiles-privs.log).

## 3. Data Redaction on `CARDS.PAN` — [`03_redaction.sh`](03_redaction.sh)

`DBMS_REDACT.ADD_POLICY` partial redaction: digits 1–12 replaced by `*` unless the session has the role
`CARD_FULL_VIEW` enabled (PCI-DSS 3.4.1). Log: [`results/03-redaction.log`](results/03-redaction.log).

| Reader | `PAN` shown |
|--------|-------------|
| `ANALYST2` (SELECT on CARDS) | `************0018` |
| `FRAUD_OPS` (SELECT + `CARD_FULL_VIEW`) | full number (masked to `9000########0018` by the script before it is logged) |
| SYS / users with `EXEMPT REDACTION POLICY` | full number — redaction never applies to them |

**What redaction does not do:** the analyst, who only sees masks, ran `WHERE pan LIKE '<BIN>%'` → 24,000
rows, and `WHERE pan = '<full number>'` → 1 row. The predicate uses the real value, so a user can confirm
or guess numbers. Redaction is display masking for applications and reports; who may query `CARDS` at all
is access control (roles, VPD), and every query on it is audited (`SEC_CARDS_ACCESS`).

## 4. Row-level control on `CARDS` — [`06_vpd.sh`](06_vpd.sh)

Redaction hides what is displayed; it does not stop a query from testing a value. VPD closes that across regions: an analyst reaches only the cards of their assigned region, for reads and changes, and someone with no assignment reaches none. Logs: [SECPDB](results/06-vpd-secpdb.log), [PERF](results/06-vpd-perf.log), [DRILLPDB](results/06-vpd-drillpdb.log).

| Who | Cards visible (SECPDB / PERF) | Test of a card from another region in `WHERE` | Change to another region's card |
|-----|-------------------------------|---------------------------------------|---------------------------------|
| Any analyst, before | 24,000 / 384,000 | finds it | possible |
| `ANALYST_NORTH` | 4,831 / 76,930 | 0 rows | 0 rows updated |
| `ANALYST_SOUTH` | 9,650 / 154,004 | 0 rows | moving its own card to another region: `ORA-28115` |
| `ANALYST_NONE`, no assignment | 0 / 0 | 0 rows | |
| `BANK`, the application account | every card, exempt in the policy function | | |
| `SYS` | every card: **VPD does not apply to it** | | |

**What it costs**, logical reads per statement after a first execution, on the larger PDB:

| Statement | Before | With the policy | With the policy and an index on `ACCOUNT_ID` |
|-----------|--------|-----------------|---------------------------------------------|
| One card by id | 10 | 21 | 21 |
| Cards of one account | 2,858 | 2,857 | 23 |
| Count of visible cards | 763 | 11,574 | 9,601 |

A single-row lookup doubles but stays small. The real cost is a query across all cards, which has to work out the region of every account. The index was missing anyway: `CARDS.ACCOUNT_ID` is a foreign key with none, the same pattern as the slow Flashback Table in the backup lab.

Design points, each from a test:

- **A predicate runs with the rights of the user who issues the statement.** My first version named `ACCOUNTS` and `CUSTOMERS` directly: `ORA-28113` for every analyst, and the fix I wanted to avoid was granting them those tables. The predicate now reads a view owned by `SEC_ADMIN`, which returns only the accounts of the caller's own region, so an analyst gains no new table and no map of the other regions.
- **`SEC_ADMIN` is schema-only:** no password, no system privilege. Changes to `STAFF_REGION` and every `DBMS_RLS` call are audited by `SEC_VPD_ADMIN`.
- **Test values are hashed.** Statements on `CARDS` are audited with their text, so a test that typed a card number would write it into the audit trail and its CSV archive.
- **Who bypasses it:** `SYS`, and holders of `EXEMPT ACCESS POLICY`: here only Oracle-maintained accounts and roles (`GSMADMIN_INTERNAL`, `GSMUSER_ROLE`, `OGG_CAPTURE`). Assessment check C06 fails if one of ours is added.

**On the standby too:** the same analyst sees the same 4,831 cards when connected to `SECPDB` on the Active Data Guard standby; the policy, the view and the assignment come with redo ([log](results/06-vpd-adg.txt)).

**Limits.** Inside their own region an analyst can still test a value in `WHERE`: audit is what covers that. `BANK` is exempt, so a leaked application password sees everything. A VPD policy does not stop `SYS`.

## 5. Separate administrative privileges — [`07_admin_roles.sh`](07_admin_roles.sh)

SYS does everything and audit can only say "SYS did it". Backups and keys now have their own accounts; Data Guard already had `C##DGADMIN`. Logs: [Region B](results/07-admin-roles-regionB.txt), [Region A](results/07-admin-roles-regionA.txt), where the RAC's offloaded backups also run as `C##BKADMIN`.

| Account | Privilege | Does | Reading `BANK.CARDS` |
|---------|-----------|------|---------------------|
| `C##BKADMIN` | `SYSBACKUP` | RMAN level 0, validate, through a wallet ([log](https://github.com/phuochuyy/oracle-backup-recovery-drills/blob/main/01-strategy/results/r7-sysbackup.txt)) | `ORA-41900` missing READ privilege |
| `C##KEYADMIN` | `SYSKM` | Master key rotation | `ORA-00942` |

The audit trail now names the person's account and the privilege used: `RMAN_AUDIT ... C##BKADMIN ... Backup`, `C##KEYADMIN ... SYSKM ... ADMINISTER KEY MANAGEMENT`. The grants reach the standby's password file through redo with no copy.

**Limit:** the OS user `oracle` is in every OS group, so anyone logged in as `oracle` can still connect `/ as sysdba`. Real separation also needs one OS account per duty, in `backupdba` and `kmdba` only; this lab has one OS account. Archived log housekeeping still runs by OS authentication.

## 6. Listener allow list in Region B — [`08_valid_nodes.sh`](08_valid_nodes.sh)

A machine that is not on the list is refused before it can try a password. Log: [`results/08-valid-nodes-regionB.txt`](results/08-valid-nodes-regionB.txt).

| From | Before | After |
|------|--------|-------|
| KVM host, not on the list, wrong password | `ORA-01017`: reached the database | `DPY-4011`: connection closed by the listener |
| prm1, the observer, prm3, stb3, in both directions | reach the listener | reach the listener |

After the listener restart, standby first: broker `SUCCESS`, FSFO Zero Data Loss with the observer, one row each way through GoldenGate, prm1 to the recovery catalog.

**It is a list of addresses, so it has to be maintained:** a new client, or a node that changes address, is refused until it is added and the listener restarted. Names are not used, because one name that does not resolve would stop the listener from starting. The list is part of what `labctl` installs at boot, otherwise the next boot would remove it. Region A is not done: its SCAN and node listeners run from the Grid home, and a change there needs its own test.

## Privilege Analysis (2026-10-30)

[`04_privilege_analysis.sh`](04_privilege_analysis.sh) `start | work | stop`: a database-wide capture in SECPDB
(`DBMS_PRIVILEGE_CAPTURE`, all users except SYS), the three reports REPORT_RO exists for, then the results
([`results/04-privilege-analysis.log`](results/04-privilege-analysis.log)):

| REPORT_RO | Privileges |
|-----------|------------|
| used | `CREATE SESSION`; `SELECT` on `ACCOUNTS`, `BRANCHES`, `CUSTOMERS`, `TRANSACTIONS` (through `BANK_READ`) |
| granted, **not used** | `SELECT` on `BANK.CARDS` — the table with the card numbers |

So the reporting role carries the one grant PCI-DSS 7 cares most about without needing it (the PAN is
redacted for it, but the right to read the table is still there). Recommendation: `BANK_READ` without
`CARDS`, a separate role for whoever needs card data. Limits: one run of the reports; a real capture covers
a whole business cycle, month end included.

**Applied the same day, as code:** `REPORT_RO` and `BANK_READ` are defined in the automation lab's `users.yml`.
I had written here that a manual `REVOKE` "would be put back" — wrong: the role only *added* missing grants, so
removing the line from `users.yml` changed nothing either. The automation lab's role now also revokes object
grants that are not in the file; run 1 `revoke SELECT on "BANK"."CARDS" from bank_read`, run 2 no change.
Afterwards ([log](results/04-privilege-analysis-after-revoke.log)): Privilege Analysis — no unused privilege
for REPORT_RO; assessment still 0 FAIL, C04 "who can read BANK.CARDS" = nobody but the owner.

First run: `ORA-01017` for REPORT_RO — my script piped the password into `ssh` *and* gave it a heredoc,
so the heredoc became stdin and `read` took the first SQL line as the password (2 of 5 allowed failures used,
the counter reset at the next good logon). Now the `connect` line and the SQL go as one stream, which also
keeps the password off the VM's command line.

## Region B

Everything above was done on Region A. Region B holds the recovery catalog, the GoldenGate peer and two PDBs with
card-like data, and the assessment had never looked at it. [`05_region_b.sh`](05_region_b.sh) applies the same baseline in the
same order; log: [`results/05-region-b-20261107.log`](results/05-region-b-20261107.log).

| What differs from Region A | Why |
|----------------------------|-----|
| `BANK` keeps a password and gets a service profile | workloads and drills log in as it; on Region A the owner is schema-only |
| `GG_SVC_PROFILE` and `PERF_SVC_PROFILE`, 40 sessions | GoldenGate holds 8 sessions at rest; parallel query slaves count against the limit. Kept visible as ACCEPT |
| Direct grants on `UTL_FILE`, `DBMS_ADVISOR`, `UTL_HTTP` to SQLT, `AUDIT_MGR`, `RCO` | found with `DBA_DEPENDENCIES` before the revoke |
| Observer exception for `obs-r2` | same audit policy, other host |

Result: 54 FAIL → 0 ([before](../05-assessment/results/r6-orcl3-before-20261107.txt),
[after](../05-assessment/results/r6-orcl3-after-20261107.txt)). The 24 ACCEPT lines each carry their reason in the file.
`GGREPL` tablespaces stay unencrypted: `check_plaintext` looks for PAN and that PDB has none, so this is not the same as
Region A, where `ORCLPDB2.APP_DATA` is encrypted.

**Not done yet at this point:** the standby stb3 (parameters are per site, `sqlnet.ora` arrives through `labctl` at its next start);
sessions opened before the change, such as `dbfs_client`, Extract and Replicat, stay unencrypted until they reconnect.

