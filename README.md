# Oracle Security & Compliance Lab — TDE · Unified Auditing · least privilege

> Status: **done for the database layer** — TDE on RAC + Active Data Guard + GoldenGate Active-Active,
> network encryption, profiles, least privilege, Unified Auditing, Data Redaction; assessment
> **27 FAIL → 0** (5 documented ACCEPTs). DBSAT needs a support contract, so the assessment is a
> CIS-style script ([why](05-assessment/README.md)). Open: one finding (1b), Privilege Analysis, audit
> retention.

## Findings

| # | Finding | Fix | Result |
|---|---------|-----|--------|
| 1 | [1,325 failed SYS logons (ORA-01031) from the observer, every ~12 s](01-baseline/failed-logons/) — found from `Failed Logon Delay` in AWR | observer as `C##DGADMIN` with **SYSDG only**, new wallet | 0 failed logons; FSFO tested with the new observer (PCI-DSS 7, 10) |
| 1a | same on Region A: 1,689 SYS ORA-01031 from obs-r1 | same fix (`C##DGADMIN` on orcl, own passwords) | 15 per 3 min → **0** |
| 1b | 2 ORA-01017 (empty user) per standby start, both regions | — | **open**, hypotheses tested and ruled out are listed |
| 2 | [Card numbers readable in datafiles, archived redo and backups on both sites](01-baseline/plaintext/) | [TDE](02-tde/): online AES256 encryption, 6 s per tablespace, under load | 3–4 hits per file → **0**; 0 application errors during the rewrite (PCI-DSS 3.5) |
| 3 | Same card data in a test PDB, never encrypted ([residual check](01-baseline/plaintext/residual_plaintext.sh)) | `BANK_DATA` encrypted too (6 s) | `verify_drillpdb.sh` PASS (not re-grepped) |
| 4 | [GoldenGate trails held card numbers in clear after TDE](02-tde/README.md) — on both sites | `ENCRYPTTRAIL AES256`, shared GG master key | 5 hits per trail → **0**, replication both ways working (PCI-DSS 3, 4) |
| 5 | [A master key change stops redo apply on the standby for the whole CDB](02-tde/README.md) (`ORA-28374`) | copy keystore right after `SET KEY`; tested restore from the off-host copy | recovered in 37 s / 19 s; switchover 57–63 s each way with TDE |
| 6 | [No network encryption — not even redo transport between sites](03-hardening/README.md) | `sqlnet.ora`: AES256 + SHA256 required, logon version 12a | 0 → all new sessions, GoldenGate 8/8, redo transport 5/5 encrypted (PCI-DSS 4.2) |
| 7 | [Every account on the DEFAULT profile; data owner could log in; PUBLIC could use UTL_TCP/HTTP/FILE](03-hardening/README.md) | service + admin profiles, schema-only `BANK`, revokes | revokes broke 14 Oracle objects → direct grants, 0 invalid |
| 8 | [No audit of card data access, grants, code DDL, successful logons](04-auditing/README.md) | 5 policies | test shows each action once; found two of my own policy mistakes on the way |
| 9 | [PAN shown in full to every reader](03-hardening/README.md) | Data Redaction (last 4) | analyst sees `************0018`; WHERE-clause inference documented |

Interview prep notes: [INTERVIEW.md](INTERVIEW.md).

## Goal

Harden a database that stores card-like data the way a bank or payment company would, and show
the effect of each control — including what it does to Data Guard and GoldenGate.

## Controls

| Area | Implementation | Verify | PCI-DSS (v4.0) |
|------|----------------|--------|----------------|
| Encryption at rest | TDE tablespace encryption, keystore, key rotation | `V$ENCRYPTED_TABLESPACES`, datafile `strings` test | Req 3 |
| TDE with Data Guard | keystore on standby, redo/redo-apply still working | switchover after enabling TDE | Req 3 |
| TDE with GoldenGate | Extract reading encrypted redo, trail encryption | replicated rows, trail not readable | Req 3, 4 |
| Encryption in transit | Native network encryption or TLS for SQL*Net | `V$SESSION_CONNECT_INFO` | Req 4 |
| Masking | Data Redaction / VPD on card number column | query as app vs auditor user | Req 3 |
| Least privilege | roles per duty, Privilege Analysis (`DBMS_PRIVILEGE_CAPTURE`) | unused privileges revoked | Req 7 |
| Authentication | password profile (complexity, lockout, lifetime) | failed-login test | Req 8 |
| Auditing | Unified Auditing policies: privileged users, DDL, logon failures, access to card table | `UNIFIED_AUDIT_TRAIL` evidence | Req 10 |
| Assessment | DBSAT collect + report | high/medium findings before vs after | Req 11 |

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
- [x] `03-hardening/` parameters, network encryption, profiles, privileges, redaction (Privilege Analysis: open)
- [x] `04-auditing/` policies + sample audit records for each scenario
- [x] `05-assessment/` CIS-style assessment before/after (DBSAT unavailable)
- [x] [PCI-DSS mapping](05-assessment/pci-dss-mapping.md) with evidence links

## CV line (fill only with real results)

`Hardened an Oracle 23ai RAC + Active Data Guard + GoldenGate Active-Active setup for PCI-DSS: TDE online
under load (0 errors), keystore drills (standby apply stopped by a key change, recovered in 37 s), GoldenGate
trails found in clear text and encrypted, network encryption incl. redo transport, Unified Auditing,
redaction; security assessment 27 FAIL → 0; 3,000+ failed SYS logons from the FSFO observers removed.`
