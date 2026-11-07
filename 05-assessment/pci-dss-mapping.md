# PCI-DSS v4.0 mapping — what this lab shows, with evidence

Only requirements the database layer can show. Card numbers are synthetic (BANKDB).

| Req. | Requirement (short) | Control in the lab | Evidence |
|------|---------------------|--------------------|----------|
| 3.4.1 | PAN masked when displayed (max BIN + last 4) | Data Redaction on `CARDS.PAN`, full view only with `CARD_FULL_VIEW` | [`03-redaction.log`](../03-hardening/results/03-redaction.log) |
| 3.5.1 | PAN unreadable wherever stored | TDE AES256 on the tablespaces with card data on both regions (primary, standby, test PDBs); GoldenGate trails `ENCRYPTTRAIL AES256`; RMAN backups encrypted with the keystore | [`before.txt`](../01-baseline/plaintext/before.txt) → [`after.txt`](../01-baseline/plaintext/after.txt), [`10-goldengate.log`](../02-tde/results/10-goldengate.log) |
| 3.6 / 3.7 | key management procedures | keystore in ASM, off-host copy, password change, restore tested, key copy to standby after every `SET KEY` | [`02-tde`](../02-tde/README.md) sections 1 and 3 |
| 3.6.1, 3.7.4 | key rotation by a written procedure, without losing the standby | Apply off, `SET KEY WITH BACKUP`, keystore to standby and off host, apply on; key IDs compared across sites | [`08_rotate_key.sh`](../02-tde/08_rotate_key.sh), [log](../02-tde/results/08-key-check-regionB.txt) |
| 4.2.1 | strong cryptography for PAN in transit | SQL*Net native encryption AES256 + SHA256 required (clients, GoldenGate, redo transport between sites) | [`01-network-after.txt`](../03-hardening/results/01-network-after.txt) |
| 7.2 | access by least privilege | schema-only owner `BANK`, no `ANY`/DBA grants to non-Oracle users, PUBLIC network/file packages revoked, observer with SYSDG only | [`after.txt`](results/after.txt) R0x, [failed logons](../01-baseline/failed-logons/) |
| 7.2 | access by need to know, at row level | VPD policy `CARDS_BY_REGION`: analysts reach only their region's cards, default deny, check option on changes | [`06_vpd.sh`](../03-hardening/06_vpd.sh), [`results/06-vpd-secpdb.log`](../03-hardening/results/06-vpd-secpdb.log) |
| 7.2.6, 10.2.1 | administrators identified, privileges by duty | `SYSBACKUP` for RMAN, `SYSKM` for keys, `SYSDG` for Data Guard; audit names the account and the privilege used | [`07_admin_roles.sh`](../03-hardening/07_admin_roles.sh), [log](../03-hardening/results/07-admin-roles-regionB.txt) |
| 8.3 | strong authentication | profiles: lockout after 5, 90-day expiry for people, reuse limits, `ORA12C_STRONG_VERIFY_FUNCTION`, only 12c verifiers (`12a`) | [`after.txt`](results/after.txt) U10, N03; `ORA-28003` in [`02-test-first-attempt.log`](../04-auditing/results/02-test-first-attempt.log) |
| 10.2.1.x | audit logs for card data access, admin actions, failed logons, privilege and object changes | unified audit policies | [`02-test.log`](../04-auditing/results/02-test.log) |
| 10.3.3 | audit log copied promptly to a log server others cannot change | `UNIFIED_AUDIT_SYSTEMLOG` to syslog, forwarded with a disk queue; burst and outage tested | [`03_syslog.sh`](../04-auditing/03_syslog.sh), [log](../04-auditing/results/r7-syslog-cost.txt) |
| 11.3 / 6.3 | find and fix vulnerabilities and insecure settings | repeatable assessment script (CIS-style), before/after | [`before.txt`](results/before.txt) → [`after.txt`](results/after.txt) |
| 10.5.1 | audit logs kept 12 months, the last 3 at hand | archive to CSV, then purge only what was archived; PERF, SECPDB and root; encrypted audit tablespace, off-host copy | [`04-auditing`](../04-auditing/README.md#retention--02_retentionsh) |

**Not covered here:** forwarding audit logs to a central system (10.3.3), patching (6.3.3), key custodians and split knowledge
(3.6.1 — organisational). Twelve months of archives are planned, not yet held: the lab is younger than that.
