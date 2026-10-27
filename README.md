# Oracle Security & Compliance Lab — TDE · Unified Auditing · least privilege

> Status: **planned**. Controls are mapped to PCI-DSS requirements and verified with a DBSAT
> assessment before and after.

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

## Deliverables checklist

- [ ] `01-baseline/` DBSAT report before hardening
- [ ] `02-tde/` keystore setup, tablespace encryption, rotation, DG + GG impact notes
- [ ] `03-access/` roles, privilege analysis results, profiles, redaction/VPD
- [ ] `04-auditing/` policies + sample audit records for each scenario
- [ ] `05-assessment/` DBSAT report after, findings table
- [ ] PCI-DSS mapping table completed with evidence links

## CV line (fill only with real results)

`Implemented TDE, Unified Auditing and least-privilege roles mapped to PCI-DSS; DBSAT high findings X → Y.`
