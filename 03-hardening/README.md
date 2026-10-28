# Hardening — parameters, network, profiles, privileges, redaction

Findings come from the [assessment baseline](../05-assessment/results/before.txt); each step is re-checked
by [`assess.sh`](../05-assessment/assess.sh) at the end.

## 1. Parameters and network — [`01_params_network.sh`](01_params_network.sh)

| Change | Where | Why |
|--------|-------|-----|
| `GLOBAL_NAMES = TRUE`, `SEC_PROTOCOL_ERROR_TRACE_ACTION = LOG` | primary + standby, dynamic (`scope = both`) | P02, P08; no database links exist, nothing to break |
| `sqlnet.ora` in the database home: `SQLNET.ENCRYPTION_SERVER = REQUIRED` (AES256), `CRYPTO_CHECKSUM_SERVER = REQUIRED` (SHA256), `ALLOWED_LOGON_VERSION_SERVER = 12a` | prm1, stb1 (no file existed) | N01–N03, PCI-DSS 4.2 — card data between sites and to GoldenGate |
| `ADMIN_RESTRICTIONS_LISTENER = ON` | grid home `listener.ora`, `lsnrctl reload` | N04: no runtime `SET` commands on the listener |
| `AUDIT_SYS_OPERATIONS` | not changed | static, and in 23ai it only drives the desupported traditional audit — SYS is audited by a unified policy instead (see auditing) |

**Result** — TCP sessions with the AES256 / SHA256 adapters in `V$SESSION_CONNECT_INFO`
([`before`](results/01-network-before.txt), [`after`](results/01-network-after.txt)):

| Connection | Before | After |
|------------|--------|-------|
| new client connection (BANK → `secpdb_app`) | no encryption adapter | AES256 + SHA256 |
| GoldenGate Extract / Replicat (after restart) | 0 / 8 | **8 / 8** |
| observer obs-r1 (after restart) | 0 / 3 | **3 / 3** + 1 on the standby |
| **redo transport + broker primary → standby** (after a standby restart) | 0 / 6 | **5 / 5** |
| `dbfs_client` (GoldenGate's DBFS mount) | 0 / 4 | 0 / 4 — old sessions, encrypted after the next remount |

Only the server side was changed: 23ai clients default to `ACCEPTED`, so they negotiate encryption when
the server requires it. Sessions opened before the change keep running unencrypted until they reconnect —
the "after" numbers needed restarts of GoldenGate, the observer and the standby.

**Still to do:** prm2 and stb2 (not running in this lab scenario) need the same `sqlnet.ora` and listener
line before they start, otherwise connections through those nodes are unencrypted.
