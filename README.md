# Oracle Security & Compliance Lab — TDE · Unified Auditing · least privilege

> Status: **done for the database layer** — TDE on RAC + Active Data Guard + GoldenGate Active-Active,
> network encryption, profiles, least privilege, Unified Auditing, Data Redaction; assessment
> **27 FAIL → 0** (5 documented ACCEPTs). DBSAT needs a support contract, so the assessment is a
> CIS-style script ([why](05-assessment/README.md)). Open: one finding (1b); audit
> retention is [designed and sized](https://github.com/phuochuyy/oracle-performance-tuning-lab/tree/main/03-cases/10-audit-overhead)
> (archive → last-archive timestamp → purge job, ~0.35 ms CPU and 0.68 KB per record) but not switched on.

## Findings

| # | Finding | Fix | Result |
|---|---------|-----|--------|
| 1 | [1,325 failed SYS logons (ORA-01031) from the observer, every ~12 s](01-baseline/failed-logons/) — found from `Failed Logon Delay` in AWR | observer as `C##DGADMIN` with **SYSDG only**, new wallet | 0 failed logons; FSFO tested with the new observer (PCI-DSS 7, 10) |
| 1a | same on Region A: 1,689 SYS ORA-01031 from obs-r1 | same fix (`C##DGADMIN` on orcl, own passwords) | 15 per 3 min → **0** |
| 1b | 2 ORA-01017 (empty user) per standby start, both regions | — | **open**, hypotheses tested and ruled out are listed |
| 2 | [Card numbers readable in datafiles, archived redo and backups on both sites](01-baseline/plaintext/) | [TDE](02-tde/): online AES256 encryption, 6 s per tablespace, under load | 3–4 hits per file → **0**; 0 application errors during the rewrite (PCI-DSS 3.5) |
| 3 | Same card data in a test PDB, never encrypted ([residual check](01-baseline/plaintext/residual_plaintext.sh)) | `BANK_DATA` encrypted too (6 s) | `verify_drillpdb.sh` PASS; re-grepped on the re-run: **0 hits** on both sites |
| 4 | [GoldenGate trails held card numbers in clear after TDE](02-tde/README.md) — on both sites | `ENCRYPTTRAIL AES256`, shared GG master key | 5 hits per trail → **0**, replication both ways working (PCI-DSS 3, 4) |
| 5 | [A master key change stops redo apply on the standby for the whole CDB](02-tde/README.md) (`ORA-28374`) | copy keystore right after `SET KEY`; tested restore from the off-host copy | recovered in 37 s / 19 s; switchover 57–69 s each way with TDE |
| 6 | [No network encryption — not even redo transport between sites](03-hardening/README.md) | `sqlnet.ora`: AES256 + SHA256 required, logon version 12a | 0 → all new sessions, GoldenGate 8/8, redo transport 5/5 encrypted (PCI-DSS 4.2) |
| 7 | [Every account on the DEFAULT profile; data owner could log in; PUBLIC could use UTL_TCP/HTTP/FILE](03-hardening/README.md) | service + admin profiles, schema-only `BANK`, revokes | revokes broke 14 Oracle objects → direct grants, 0 invalid |
| 8 | [No audit of card data access, grants, code DDL, successful logons](04-auditing/README.md) | 5 policies | test shows each action once; found two of my own policy mistakes on the way |
| 9 | [PAN shown in full to every reader](03-hardening/README.md) | Data Redaction (last 4) | analyst sees `************0018`; WHERE-clause inference documented |
| 10 | [The GoldenGate admin password in clear on the VMs](#re-run-2026-10-29) — adminclient echoes its `CONNECT ... PASSWORD` line; one lab script left that command file **world-readable in `/tmp` on 3 VMs** | output masked, command files `umask 077` and always removed; **password rotated** on 16 accounts that shared it ([runbook](03-hardening/password-rotation.md)) | 0 in output, 0 files left; never in Git (all 5 repos and history); old password refused everywhere |
| 11 | [Trail files written before `ENCRYPTTRAIL` still hold clear PANs 3 days later](#re-run-2026-10-29) — no trail purge is set up | purge task on both deployments (every 6 h, only files all readers passed, keep 24 h); local trails blocked by `OGG-30480` → one-off purge by the same rule | 66 local + 68 received files removed; after 24 h a second local purge by the same rule (17 + 7 files): **0 hits on all 4 trails** (2026-10-30), replication checked after — **closed**; the local-trail purge stays manual (`OGG-30480`) |
| 12 | [The performance test PDB on the other database held 384,000 card-like numbers in clear](https://github.com/phuochuyy/oracle-performance-tuning-lab/tree/main/03-cases/09-tde-overhead) — orcl3 had no TDE at all | keystore on orcl3, `BANK_DATA` of PERF encrypted offline in place (3.3 GB, 12 s; online would have needed a second copy) | 4 hits → **0**; measured cost: commit-heavy transfers −18 %, scans from disk −7 to −8 %, cached reads unchanged (PCI-DSS 3.5) |

## Re-run 2026-10-29

After the HA/DR re-run (2 FSFO failovers, GoldenGate moved to the standby and back) and the backup drills
(a TDE datafile restored from backup), every check again:

| Check | Result | Evidence |
|-------|--------|----------|
| Assessment | **0 FAIL** — ACCEPT 5, INFO 4, PASS 56, same as `after` | [`05-assessment/results/rerun-20261029.txt`](05-assessment/results/rerun-20261029.txt) |
| Card number in raw files (datafile ×2, new archived log, uncompressed backup piece) | 0 hits each | [`rerun-20261029.txt`](01-baseline/plaintext/rerun-20261029.txt) |
| DRILLPDB datafile (restored from backup that day) on both sites | 0 hits — finding 3 now re-grepped | [`drillpdb-rerun-20261029.txt`](01-baseline/plaintext/drillpdb-rerun-20261029.txt) |
| Network encryption | **19/19** TCP sessions AES256 + SHA256 on both sites, incl. redo transport after the failovers (dbfs_client 0/4 → 5/5: those sessions now postdate the change) | [`01-network-rerun-20261029.txt`](03-hardening/results/01-network-rerun-20261029.txt) |
| Audit scenario | each action once; logons now under `SEC_LOGON_SUCCESS` (the logon tuning), not `ORA_LOGIN_LOGOUT` as in the first run | [`02-test-rerun-20261029.log`](04-auditing/results/02-test-rerun-20261029.log) |
| Data Redaction | same masks; script failed on the existing role/policy (ORA-01921, ORA-28069) → made re-runnable | [`03-redaction-rerun-20261029.log`](03-hardening/results/03-redaction-rerun-20261029.log) |
| GoldenGate trails | new rows: 0 hits on all 4 trails; **old trails: 5 hits each** (finding 11) | [`10-goldengate-rerun-20261029.log`](02-tde/results/10-goldengate-rerun-20261029.log) |
| Failed logons, 6 h | **0 SYS ORA-01031**; 18 empty-user ORA-01017 (1b), all inside the failover test window | [`rerun-20261029.txt`](01-baseline/failed-logons/rerun-20261029.txt) |

New on the way: **finding 10**. `tests/gg.sh` printed `CONNECT ... PASSWORD <the password>` on my terminal —
adminclient echoes every command it reads. Looking for other copies: `timeline.sh` (HA/DR test harness)
wrote the same line to `/tmp/tl.oby` and never removed it — mode 644 on prm1, stb1 and prm3. Fixed in the
HA/DR repo (masked output, `umask 077`, `rm`), files deleted. The password should still be changed: it is
the shared lab password and has been readable by any local user of those VMs.

**Finding 11.** 109 trail files on GG_A and 108 on GG_B since 10-26 (18 MB / 16 MB): nothing purges them, so the
clear PANs written before `ENCRYPTTRAIL` are still there. My TDE notes said "until the trail purge removes
them" — there is no trail purge.

Fix: an Admin Server task `purge_trails` on both deployments (REST `POST /services/v2/tasks/purge_trails`, body [`02-tde/purge_trails_task.json`](02-tde/purge_trails_task.json)):
trails `ea` and `eb`, `useCheckpoints: true`, keep at least 24 h, every 6 h. Run once at once: the received
trails were purged up to the 24 h limit; the **local** trails were not — `OGG-30480 Not purging trail
sequence 'ea000000000' because a process is still using it`, although the Extract and the distribution
path both checkpoint the newest file (seq 57) and no other checkpoint file exists. Not solved. So the local
trails were purged once by hand with the same rule (older than 24 h **and** below the reader's
checkpoint: 32 files on GG_A, 34 on GG_B). Replication both ways checked after (10 of 10 rows).
The files written just before `ENCRYPTTRAIL` (10-28 18:50–19:44) are younger than 24 h, so the round 1
markers are still found (5 hits each) — to re-check when they have aged out.

Audit volume (3 h): 557 records/hour of `ORA_ALL_TOPLEVEL_ACTIONS` in the root — my own SYS scripts during
the drills. With no retention/purge job the trail only grows ([`04-volume-rerun-20261029.txt`](04-auditing/results/04-volume-rerun-20261029.txt)).

## Goal

Harden a database that stores card-like data the way a bank or payment company would, and show
the effect of each control — including what it does to Data Guard and GoldenGate.

## Controls — what was built, what was not

| Area | Implementation | Verified by | PCI-DSS (v4.0) | Status |
|------|----------------|-------------|----------------|--------|
| Encryption at rest | TDE (united keystore in ASM, online encryption, master and tablespace key rotation) | raw-file grep of a card number: 3–4 hits → 0 | 3.5 | done |
| TDE with Data Guard | keystore copied to the standby; drills: missing key, lost keystore; switchover | apply lag, switchover 57–69 s | 3.5, 3.6 | done |
| TDE with GoldenGate | Integrated Extract on encrypted redo, `ENCRYPTTRAIL AES256` | trails 5 hits → 0, replication both ways | 3.5, 4 | done |
| Encryption in transit | native network encryption AES256 + SHA256 required (TLS not set up) | `V$SESSION_CONNECT_INFO` incl. redo transport | 4.2 | done |
| Masking | Data Redaction on `CARDS.PAN` | analyst vs `CARD_FULL_VIEW` user | 3.4 | done (**VPD not built**) |
| Least privilege | schema-only owner, PUBLIC revokes, SYSDG observer, no ANY/DBA grants | assessment R0x checks; [Privilege Analysis](03-hardening/README.md#privilege-analysis-2026-10-30): REPORT_RO used 4 of its 5 table grants, `SELECT` on `CARDS` never | 7.2 | done (role change belongs to the automation lab's `users.yml`) |
| Authentication | profiles for people and service accounts, strong verify function, 12a verifiers | assessment U10/N03, `ORA-28003` in the audit test | 8.3 | done |
| Auditing | Unified Auditing: card table, grants, code DDL, logons, SYS | test scenario, volume tuning | 10.2 | done (**retention/purge not set up**) |
| Assessment | CIS-style script — DBSAT needs a support contract | 27 FAIL → 0 | 11.3 | done |

## Licensing

TDE and Data Redaction are part of **Oracle Advanced Security**, an extra-cost option on Enterprise Edition
on-premises (included in some Oracle Cloud offerings). Native network encryption / TLS, Unified Auditing and
Privilege Analysis are included in Enterprise Edition. Checked against the *Oracle Database 23ai Licensing
Information User Manual*; this lab uses the options for learning — check the licenses before using them at work.

## Layout

```
00-setup/      SECPDB on the RAC primary with BANKDB (card-like PANs)
01-baseline/   failed-logons/ (finding 1), plaintext/ (card numbers in raw files, before/after TDE)
02-tde/        keystore, online encryption, Data Guard drills, switchover, GoldenGate — scripts + results/
03-hardening/  parameters + network encryption, profiles + privileges, Data Redaction
04-auditing/   Unified Auditing policies + test scenario
05-assessment/ assess.sh + checks.sql (CIS-style), before/after, PCI-DSS mapping
notes/worklog.md   problems hit on the way, including my own mistakes
```

Environment: RAC `orcl` (prm1, ASM) → ADG `orcl_stb` (stb1), FSFO, observer obs-r1; GoldenGate GG_A ↔
GG_B (orcl3 on prm3). Passwords in the git-ignored `lab.env` (`lab.env.example`), sent on stdin.

## Deliverables checklist

- [x] `01-baseline/` findings before hardening (failed logons, plaintext card data) — DBSAT replaced, see 05
- [x] `02-tde/` keystore setup, tablespace encryption, rotation, DG + GG impact notes
- [x] `03-hardening/` parameters, network encryption, profiles, privileges, redaction, Privilege Analysis
- [x] `04-auditing/` policies + sample audit records for each scenario
- [x] `05-assessment/` CIS-style assessment before/after (DBSAT unavailable)
- [x] [PCI-DSS mapping](05-assessment/pci-dss-mapping.md) with evidence links
