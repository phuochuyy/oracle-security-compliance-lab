# Unified Auditing — [`01_policies.sh`](01_policies.sh)

Gaps from the [assessment baseline](../05-assessment/results/before.txt): no audit of grants/revokes,
synonyms, code and trigger DDL, successful logons/logoffs, SYS statements, access to `BANK.CARDS`.

| Policy | Scope | Covers | PCI-DSS v4.0 |
|--------|-------|--------|--------------|
| `C##SEC_CHANGES` (common, enabled in the root) | all containers — common users | `GRANT`, `REVOKE`, synonyms, procedure/function/package/trigger DDL | 10.2.1.5 (privilege changes), 10.2.1.7 (system-level objects) |
| `SEC_CHANGES` (local, SECPDB) | **local users** of SECPDB | the same actions | 10.2.1.5, 10.2.1.7 |
| `ORA_LOGIN_LOGOUT` (predefined) | all users, root and SECPDB | **failed** logons (default setting, kept) | 10.2.1.4 |
| `C##SEC_LOGON_SUCCESS` (common) + `SEC_LOGON_SUCCESS` (SECPDB) | all users, `WHEN` not (identity `C##DGADMIN` **and** host `obs-r1.rac`) | successful logons and logoffs | 10.2.1 |
| `ORA_ALL_TOPLEVEL_ACTIONS` (predefined) `BY SYS` | root | every top-level statement of SYS — the 23ai replacement for `AUDIT_SYS_OPERATIONS` | 10.2.1.2 |
| `SEC_CARDS_ACCESS` (SECPDB) | all users | `SELECT/INSERT/UPDATE/DELETE ON bank.cards` | 10.2.1.1 |
| `ORA_SECURECONFIG` (predefined, already on) | all | user/role/profile/system changes, audit policy changes | 10.2.1.5, 10.2.1.6 |

## Test scenario — [`results/02-test.log`](results/02-test.log)

A local analyst user is created, granted SELECT on CARDS, reads it, creates and drops a procedure, is revoked
and dropped. Every step is in `UNIFIED_AUDIT_TRAIL` once, under the expected policy:

```
SYS       CREATE USER       ANALYST1         ORA_SECURECONFIG
SYS       GRANT             BANK.CARDS       SEC_CHANGES, C##SEC_CHANGES, ORA_SECURECONFIG
ANALYST1  LOGON                              ORA_LOGIN_LOGOUT
ANALYST1  SELECT            BANK.CARDS       SEC_CARDS_ACCESS
ANALYST1  CREATE PROCEDURE  ANALYST1.P_TEST  SEC_CHANGES
ANALYST1  DROP PROCEDURE    ANALYST1.P_TEST  SEC_CHANGES
ANALYST1  LOGOFF                             ORA_LOGIN_LOGOUT
SYS       REVOKE            BANK.CARDS       SEC_CHANGES, C##SEC_CHANGES, ORA_SECURECONFIG
SYS       DROP USER         ANALYST1         ORA_SECURECONFIG
```

## It took three runs — the mistakes are the useful part

| Run | What the trail showed | Cause |
|-----|-----------------------|-------|
| 1 ([log](results/02-test-first-attempt.log)) | `CREATE USER` failed `ORA-28003` — and was audited, as was the failed logon | the new strong verify function rejected my random test password (the profile works) |
| 2 ([log](results/02-test-second-attempt.log)) | (a) **no record** of the analyst's `CREATE PROCEDURE`; (b) 22 `SELECT` records on `SYS.USER$`, `OBJ$`, `DUAL`… under the CARDS policy | (a) the common policy enabled in the root did not audit a **local** user's DDL in the PDB — proven separately: [`03-common-vs-local-policy.txt`](results/03-common-vs-local-policy.txt) (procedure p1 without a local policy: no record; p2 with it: recorded). (b) `actions select, insert, update, delete on bank.cards` — `ON` binds to DELETE only; SELECT/INSERT/UPDATE were audited on **every object** |
| 3 | as above, clean | local `SEC_CHANGES`; `select on bank.cards, insert on bank.cards, ...` |

My assessment had said PASS for both broken cases (an enabled policy with those actions existed), so the
checks were tightened: in a PDB only local policies count, and C02 needs all four actions bound to CARDS.

## Volume — [`results/04-volume.txt`](results/04-volume.txt)

| Version | Successful-logon records | Who |
|---------|--------------------------|-----|
| `ORA_LOGIN_LOGOUT` for successes too | **378/hour** in the root | 57 of 65 logons in 10 min = the observer (`dgmgrl@obs-r1`) reconnecting, ~8,000/day of noise |
| own policy `EXCEPT c##dgadmin` | still 326/hour, all from the observer | **did not work**: the observer connects `AS SYSDG`, so the session user is `SYSDG`, not `C##DGADMIN` (and `EXCEPT sysdg` would hide every person using SYSDG) |
| own policy `WHEN AUTHENTICATED_IDENTITY <> 'C##DGADMIN' OR HOST <> 'obs-r1.rac'` | **0 from the observer** in 5 min; PDBADMIN, SYS, DBSNMP logons recorded | the same wallet used from another host is still audited; failures stay audited for everybody via `ORA_LOGIN_LOGOUT` |

Details: [`05-logon-tuning.log`](results/05-logon-tuning.log). The assessment lists the condition (A09) so it
does not hide. Seen right after a database start: ~10 `GRANT` records by SYS on `SYS.ORA_TEMP_1_DS_*`
(internal temporary tables of the statistics job) — internal noise, left in rather than filtering SYS.

**Retention (PCI-DSS 10.5.1: 12 months, 3 immediately available) — not set up:** that is a purge job
(`DBMS_AUDIT_MGMT` with a last-archive timestamp after exporting the records), i.e. automatic deletion —
agreed with the team first, not created on my own in this lab.

## Re-run 2026-10-29

Same records, each action once ([`results/02-test-rerun-20261029.log`](results/02-test-rerun-20261029.log)). The
LOGON/LOGOFF lines are now under `SEC_LOGON_SUCCESS` — the example above is from before the logon tuning,
when successes went to `ORA_LOGIN_LOGOUT`.
