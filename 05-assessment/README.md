# Assessment — DBSAT replaced by a CIS-style check script

**Why not DBSAT.** DBSAT is free for Oracle support customers but is downloaded from My Oracle Support
(Doc ID 2138254.1). My account has no support contract: registering the CSI of an OCI Free Tier tenancy
failed (`VBCP-PPEP-776`, "invalid or a mismatch"). So I wrote the checks myself, grouped like the
**CIS Oracle Database Benchmark** sections, plus checks for the card data (PCI-DSS). The check IDs are the
lab's own — mapping them to CIS recommendation numbers needs the CIS PDF (free after registration), not
done yet.

**What runs:** [`assess.sh`](assess.sh) runs [`checks.sql`](checks.sql) in `CDB$ROOT` and `SECPDB` of the
RAC primary, plus file checks on `sqlnet.ora` / `listener.ora`. One line per check:
`id | section | container | PASS / FAIL / ACCEPT / INFO | check | actual value`.
- **ACCEPT** = known deviation with a written reason, kept visible (e.g. `REMOTE_LOGIN_PASSWORDFILE` must
  stay `EXCLUSIVE`: Data Guard redo transport and the SYSDG observer user need the password file).
- Oracle-maintained accounts and roles are left out of the privilege checks (`ORACLE_MAINTAINED = 'Y'`).

| Section | Checks |
|---------|--------|
| 2 parameters | `AUDIT_SYS_OPERATIONS`, `GLOBAL_NAMES`, `OS_ROLES`, `REMOTE_LOGIN_PASSWORDFILE`, `REMOTE_OS_ROLES`, `SEC_*` (failed logins, protocol errors, banner), `SQL92_SECURITY`, `RESOURCE_LIMIT` |
| 3 users | default passwords on open accounts, 10G hashes, public DB links, password/resource limits of every profile in use |
| 4 privileges | `PUBLIC` EXECUTE on network / file / crypto / dynamic-SQL packages, `ANY` privileges, DBA role, `WITH ADMIN OPTION`, powerful privileges, access to sensitive `SYS` tables, password file users |
| 5 audit | pure unified auditing; enabled policies (all users, successes too) covering user/role, grants, profiles, DB links/synonyms, system changes, code DDL, logon/logoff |
| 6 network | server-side native encryption and checksums required, `ALLOWED_LOGON_VERSION_SERVER`, listener admin restrictions |
| PCI | card data only in encrypted tablespaces (3.5), access to `BANK.CARDS` audited (10.2), PAN masked (3.4), who can read `CARDS` (7) |

## Baseline — [`results/before.txt`](results/before.txt)

**32 PASS, 27 FAIL, 1 ACCEPT, 2 INFO** (after TDE, before any other hardening).

| Section | FAIL | What failed |
|---------|------|-------------|
| 2 parameters | 3 | `AUDIT_SYS_OPERATIONS=FALSE`, `GLOBAL_NAMES=FALSE`, `SEC_PROTOCOL_ERROR_TRACE_ACTION=TRACE` |
| 3 users | 2 | every account (root and SECPDB) on the `DEFAULT` profile: 10 failed logins, 180-day life, no verify function, unlimited sessions |
| 4 privileges | 8 | `PUBLIC` can execute `UTL_TCP/SMTP/HTTP/INADDR`, `HTTPURITYPE`, `DBMS_LDAP`, `UTL_FILE`, `DBMS_SQL`… (root and SECPDB) |
| 5 audit | 8 | no audit of `GRANT/REVOKE`, synonyms, procedure/package/trigger DDL, successful logons/logoffs |
| 6 network | 4 | no `sqlnet.ora` in the database home: no encryption/checksum required, logon version default; listener without admin restrictions |
| PCI | 2 | nobody audits access to `BANK.CARDS`; PAN shown in full to every reader |

Already good thanks to earlier work or 23ai defaults: no default passwords, no 10G hashes, no `ANY`
privileges or DBA grants to non-Oracle users, pure unified auditing, card data in encrypted tablespaces.

## After hardening — [`results/after.txt`](results/after.txt)

**56 PASS, 0 FAIL, 5 ACCEPT, 4 INFO** (INFO: password file users, who can read CARDS, and A09 — every
audit exclusion, so the logon-audit condition for the observer stays visible).

| | Before | After |
|-|--------|-------|
| FAIL | **27** (23 under the final check rules) | **0** |
| ACCEPT | 1 | 5 |
| INFO | 2 | 4 |
| PASS | 32 | 56 |

The checks changed after the baseline, and I say so: `DBMS_LOB`/`DBMS_RANDOM` moved from R02/R03 to the
accepted R04 group (counted with the final rules the baseline has 23 FAIL), P01 accepts the unified-audit
equivalent, and two audit checks became **stricter** after my audit test showed they had passed wrongly
(see [04-auditing](../04-auditing/)). More lines after (65 vs 62): new profiles are in use and A09 was added.

**The 5 ACCEPTs** — deviations kept on purpose, visible in every run:

| Check | Container | Why it stays |
|-------|-----------|--------------|
| P04 `REMOTE_LOGIN_PASSWORDFILE = EXCLUSIVE` | root | Data Guard redo transport and the SYSDG observer user need the password file |
| U10 `C##SVC_PROFILE` without password expiry | root, SECPDB | the observer's password is in a wallet; an expired password would silently leave FSFO without observer — rotated by procedure instead |
| R04 `PUBLIC` EXECUTE on `DBMS_SQL`, `DBMS_LOB`, `DBMS_SCHEDULER`, `DBMS_JOB`, `DBMS_RANDOM`, `DBMS_XMLGEN`, `DBMS_JAVA` | root, SECPDB | general-purpose packages used by Oracle components; the network/file revoke already broke 14 Oracle objects |

How the 27 were fixed: [parameters + network](../03-hardening/README.md),
[profiles + privileges](../03-hardening/README.md),
[auditing](../04-auditing/), [redaction](../03-hardening/README.md).
