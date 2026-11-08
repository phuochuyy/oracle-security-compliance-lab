# Database Vault on orcl3: even SYS cannot read card data

Every earlier control stops people who are not DBAs. A DBA, or anyone who gets `SYS`, could still read every card number: VPD and redaction do not apply to `SYS`. Database Vault closes that, and separates the people who administer the database from the people who administer security and accounts. Done in Region B (`orcl3`, PDB `PERF`, standby `ORCL3_STB`), following the *Database Vault Administrator's Guide* for Oracle AI Database 26ai: chapter 3 for a CDB, 11.3 for Data Guard.

Script: [`dv.sh`](dv.sh), one step per call. Evidence: [`results/`](results/).

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

Database Vault is an extra-cost option of Enterprise Edition (Licensing Information, Security table). Region B only: the card data of Region A (`SECPDB` on the RAC) is not protected this way yet; a RAC enablement is rolling and also involves its standby, XAG and GoldenGate. The OS user `oracle` can still stop the database or read datafiles, which are encrypted by TDE: Database Vault controls SQL access, TDE protects the files, and neither replaces separate OS accounts.
