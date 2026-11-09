# Database Vault: even SYS cannot read card data

Every earlier control stops people who are not DBAs. A DBA, or anyone who gets `SYS`, could still read every card number: VPD and redaction do not apply to `SYS`. Database Vault closes that, and separates the people who administer the database from the people who administer security and accounts. Done in both regions, following the *Database Vault Administrator's Guide* for Oracle AI Database 26ai: chapter 3 for a CDB (3.2.5 for RAC), 11.3 for Data Guard:

- Region B: `orcl3`, PDB `PERF`, standby `ORCL3_STB` (sections below up to *Licensing*)
- Region A: the RAC `orcl`, PDB `SECPDB`, RAC standby `orcl_stb` ([its own section](#region-a-the-rac))

Script: [`dv.sh`](dv.sh), one step per call, `DV_REGION=A` for Region A. Evidence: [`results/`](results/) (Region B) and [`results/region-a/`](results/region-a/).

## Who does what now

| Account | Role | Can | Cannot |
|---------|------|-----|--------|
| `C##DVOWNER` | `DV_OWNER` | realms, rules, authorizations | read the protected data |
| `C##DVACCTMGR` | `DV_ACCTMGR` | create, change, drop users and profiles | grant itself data access |
| `C##DVOWNER_BACKUP`, `C##DVACCTMGR_BACKUP` | the same, break-glass | bring the everyday accounts back | (passwords kept outside every repository) |
| `SYS` | `SYSDBA` | run the database, start and stop it | read `CARDS`, `CUSTOMERS`, `ACCOUNTS`; create users; grant `DV_OWNER`; read the audit trail |
| `SEC_AUDITOR` | `AUDIT_VIEWER`, authorized by the DV owner | read the audit trail | change anything |
| `BANK` | realm owner | its application, from the application hosts | log in from anywhere else |

## How it was enabled

1. Prerequisites checked on both sites (`OS_ROLES`, `REMOTE_OS_ROLES` false, password file exclusive, `SQL92_SECURITY` true); backups validated; the privileges of `DBA`, `SCHEDULER_ADMIN` and the Data Pump roles saved; a guaranteed restore point, dropped at the end.
2. FSFO off, broker configuration disabled.
3. Root: `CONFIGURE_DV` with the **backup** accounts first, as the guide orders, `utlrp`, `ENABLE_DV` by the backup owner in regular mode, restart as `SYSOPER`. Regular, not strict: the other PDBs (GoldenGate, drills, the recovery catalog) keep working without Database Vault.
4. The backup accounts grant `DV_OWNER` and `DV_ACCTMGR` to the everyday accounts.
5. `PERF`: `CONFIGURE_DV`, `ENABLE_DV`, close and open.
6. Standby: wait until it has applied everything, restart, broker and FSFO back on: `SUCCESS`, Database Vault enabled on the standby's root and `PERF`.
7. A mandatory realm on `BANK.CARDS`, `CUSTOMERS`, `ACCOUNTS`, **in simulation first**; a `CONNECT` rule for `BANK`, also in simulation; unified audit of realm violations, rule failures and Database Vault changes; the audit retention job authorized.
8. The lab's normal work run against the simulation, the log read, then both enforced.

## What the simulation showed

Every normal activity ran with **no violation**: workloads as `BANK`, level 1 backup and validate as `C##BKADMIN`, the plan regression check, the assessment, the health check, the audit archive job ([activities](results/simulation-activities.txt)). What it logged is what should be blocked ([log](results/simulation-log.txt)):

- `SYS` reading `CARDS` and `CUSTOMERS`
- `BANK` connecting from prm1
- `SYS` creating the VPD objects in `SEC_ADMIN` and granting on the realm's tables: on a real system that work goes through the account manager and a change window

## Verification, enforced ([`verify.sh`](verify.sh), [results](results/verification.txt))

| Test | Expected | Result |
|------|----------|--------|
| `SYS` reads `CARDS`, `CUSTOMERS` | refused | `ORA-01031` |
| `SYS` reads `TRANSACTIONS` (not in the realm) | works | works |
| `C##DVOWNER` reads `CARDS` | refused | `ORA-00942` |
| `BANK` from prm3 | works | 384,000 cards |
| `BANK` from prm1 | refused, audited | `ORA-47306` "BANK may only connect from an application host"; audit shows the host ([record](results/rule-failure-audit.txt)) |
| `SYS` creates a user | refused | `ORA-01031` |
| `C##DVACCTMGR` creates a user | works | works |
| Analyst of the NORTH region, through role `CARD_ANALYST` | realm allows, VPD limits | 76,930 cards |
| `SYS` reads the audit trail | refused | `ORA-01031`; `SEC_AUDITOR` reads it |
| Audit | violations recorded | 8 realm violations by `SYS`, 4 refused account commands, 1 refused grant, every DV change by `C##DVOWNER` |
| Backup level 1, validate | work | rc=0, validate 215 s ([operations](results/operations-enforced.txt)) |
| GoldenGate both ways | works | rows in 3 to 13 s |
| Assessment | 0 FAIL | 0 FAIL; new check D01: DV enabled where configured |
| Switchover to stb3 and back | DV stays on, SYS still refused | 20 s and 25 s, DV enabled on each new primary, GoldenGate followed ([log](results/switchover-with-dv.txt)) |
| Break-glass procedure | backup accounts restore the owner | restored; see below |

**Privileges Database Vault took away** ([diff](results/privs-revoked-by-dv.txt)): from `DBA`, among others, `BECOME USER`, `CREATE ANY JOB`, `MANAGE SCHEDULER`, `SELECT ANY TRANSACTION`; from `SCHEDULER_ADMIN` and `IMP_FULL_DATABASE` their job and queue privileges. 34 lines, root and `PERF`. **They do not come back after `DISABLE_DV`**: the saved list is how they would be granted again.

## The break-glass test, and my mistake in it

The procedure: the backup owner takes `DV_OWNER` from the everyday owner, the account manager resets its password, the backup owner grants the role back. `SYS` cannot do any of it (`ORA-47410`).

My first script reset the password and then stopped, before saving the new value: one step printed nothing, `grep` returned 1, `set -e` ended the script. The everyday owner was left without its role and with a password nobody had, which turned the test into the real thing. The backup accounts restored it. The script now saves the value first. The grant back also failed once with `ORA-65048` / `ORA-12850` (no parallel server for a DDL across PDBs) and worked on the next try ([log](results/breakglass-test.txt)).

**Without the backup accounts there would have been no way back:** `SYS` cannot grant `DV_OWNER`, and the guide says a database whose only owner is lost needs Database Vault disabled by that owner, which is impossible.

## Cost

| Workload, 4 sessions | Before | After |
|----------------------|--------|-------|
| Statement query (case 1), /s | 79,704.76, 78,702.17 | 72,369.91, 67,668.44 |
| Monthly report (case 5), /s | 46.04, 45.36 | 47.20, 43.89 |

The statement query is 12 % lower after, the report unchanged. The statement query reads `TRANSACTIONS`, which is not in the realm, and on this laptop the same setting has ranged from 75,291 to 99,083 /s ([memory report](https://github.com/phuochuyy/oracle-performance-tuning-lab/tree/main/04-reports/memory)). I cannot separate a Database Vault cost from that noise with two runs each.

## What changes in daily work

- Users and profiles are created by `C##DVACCTMGR`, not `SYS` (the VPD script's test users fail as `SYS` now).
- A DBA who must change a protected table needs the DV owner to authorize it for that change.
- Data Pump on `PERF` needs `DBMS_MACADM.AUTHORIZE_DATAPUMP_USER`; the export of the OCI project will need it.
- Patching needs `DV_PATCH_ADMIN` for `SYS` during the patch, revoked after.
- Undo: `dv.sh disable`, in the guide's order (PDB then root, primary then standby), then the saved privileges granted again.

## Licensing and limits

Database Vault is an extra-cost option of Enterprise Edition (Licensing Information, Security table). The OS user `oracle` can still stop the database or read datafiles, which are encrypted by TDE: Database Vault controls SQL access, TDE protects the files, and neither replaces separate OS accounts.

## Region A: the RAC

Same procedure, same accounts (own passwords per database), with what the RAC and this PDB changed.

**Enabling** ([log](results/region-a/enable-log.txt)): broker and FSFO off; `CONFIGURE_DV` and `ENABLE_DV` in the root by the backup accounts; every instance restarted with `srvctl` (`-force`: DBFS, XAG and GoldenGate depend on the database); then `SECPDB`; then the standby, restarted with `srvctl` after it had applied everything; broker and FSFO back: `SUCCESS`, Database Vault enabled on both sites' root and `SECPDB`. Only one instance per site was running, so this was a full restart, not the rolling enablement the guide allows; prm2 and stb2 read the new state when they next start.

**What was different here**

- `BANK` and `SEC_ADMIN` are schema-only accounts in `SECPDB` (finding 7): nobody logs in as them. The account that logs in is `REPORT_RO`, whose role `BANK_READ` reads `ACCOUNTS` and `CUSTOMERS` for three reports (Privilege Analysis). The simulation logged exactly those reads; `BANK_READ` became a realm participant and the next run logged nothing. The connect rule covers `REPORT_RO` and `BANK`.
- The application hosts are every address of the four RAC nodes: public, node VIPs, SCAN and the GoldenGate VIP (15 addresses). A session to an address on the same node takes that address as its source.
- With the realm owner unable to log in, planned work on the realm's tables (a grant to a test analyst, the plaintext check reading a card) runs in a **change window**: `dv.sh window open <reason> [test users]` makes `SYS` realm owner and the test users participants, `window close` removes them and checks; every window is in [`change-windows.txt`](results/region-a/change-windows.txt) and in the audit trail as `Add Realm Auth` / `Delete Realm Auth`.
- `SYS` cannot create users as soon as Database Vault is enabled, even with the realm still in simulation. The redaction, VPD-on-standby and plaintext tests now let the account manager create and drop their users ([`dv_helpers.sh`](dv_helpers.sh)).

**Verification, enforced** ([verification](results/region-a/verification.txt), [tests](results/region-a/tests-enforced.txt), [operations](results/region-a/operations-enforced.txt))

| Test | Result |
|------|--------|
| `SYS` reads `CARDS`, `CUSTOMERS` / `TRANSACTIONS` | `ORA-01031` / works |
| `C##DVOWNER` reads `CARDS` | `ORA-00942` |
| An account bound to the connect rule set, from prm1 / from prm3 | in / `ORA-47306` |
| `SYS` / `C##DVACCTMGR` creates a user | `ORA-01031` / works |
| Analyst of NORTH through `CARD_ANALYST`, primary and Active Data Guard standby | 4,831 cards on both |
| Redaction: analyst / fraud role | `************0141` / full number (masked by the script); WHERE-clause inference still works |
| Plaintext check (datafile both sites, archived log, backup piece) | 0 hits in all four |
| `REPORT_RO` reports | work |
| Level 1 on the standby, validate (`C##BKADMIN`) | success, 546 s and 125 s |
| GoldenGate both ways | 5 to 7 s |
| Assessment | 0 FAIL, D01 PASS in root and `SECPDB` |
| Switchover to stb1 and back | 73 s and 75 s; DV on, `SYS` refused on each new primary; GoldenGate followed ([log](results/region-a/switchover-with-dv.txt)) |
| Break-glass procedure | owner restored at the first try ([log](results/region-a/breakglass-test.txt)) |

The same 34 privileges were revoked as in Region B ([diff](results/region-a/privs-revoked-by-dv.txt)).

**Not tested here:** `REPORT_RO` from a foreign host (its password is in the automation lab's vault); a temporary account bound to the same rule set stood in for it. No workload cost: Region A has no performance workload on `SECPDB`.

**Problems on the way**

- **A card number in clear, caused by the simulation itself** (finding 14). In simulation mode Database Vault stores the full SQL text of every violation in `DVSYS.SIMULATION_LOG$`, in SYSAUX. TDE here encrypts the data tablespaces, not SYSAUX, so the plaintext check's test card (inserted by `SYS` while the realm was simulating) reached the archived log in clear: hits=2, after 0 in every run since TDE. Enforced, the same check is back to 0. Lessons: run the simulation with statements that carry no card numbers; encrypting SYSTEM and SYSAUX too would close it; I found no documented way to purge the simulation log.
- GoldenGate's Extract abended twice (`OGG-06219`) after the primary restart, while the broker configuration was disabled, and started cleanly once it was enabled again. The same error followed the failover of HA/DR run 6 and is still unexplained there.
- My script errors, each caught by the next step: `olsnodes` not in the oracle user's path (no instance started; the GoldenGate service start brought it up); `dgmgrl -silent` prints nothing on `enable configuration` and my check waited for "Enabled"; the PDB's services stayed down after the close and open; the redaction test, broken since VPD (finding 15), stopped half-way and its cleanup dropped the test users before closing the window, so the close failed on them (`ORA-29504`). `SYS` had been removed first; the order is fixed.

