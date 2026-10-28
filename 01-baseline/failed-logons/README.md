# Finding 1 — Thousands of failed SYS logons from the Data Guard observer

**How it was found:** not by a security tool. While tuning orcl3 in the
[performance lab](https://github.com/phuochuyy/oracle-performance-tuning-lab), AWR listed the wait
`Failed Logon Delay`. The unified audit trail (`ORA_LOGON_FAILURES` is on by default in 23ai) showed where
the failed logons came from ([`audit_failed_logons.sql`](audit_failed_logons.sql), [`before.txt`](before.txt)):

| Return code | User | From | Program | Records | Period |
|-------------|------|------|---------|---------|--------|
| ORA-01031 insufficient privileges | SYS | obs-r2 | `dgmgrl` (observer) | 1,325 (+1,328 without host) | 10-26 16:17 → 10-28 01:26, every ~12 s |
| ORA-01017 invalid username/password | *(empty)* | stb3 | `oracle` (standby instance) | 41 | 2 per standby start |
| ORA-01017 | GGADMIN | prm3 | `adminsrvr` | 5 | one evening, while setting up GoldenGate |

FSFO was working the whole time — the observer looked healthy.

## Why it matters

- ~7,000 failed **SYS** logons a day bury real attacks: an alert on failed privileged logons is useless
  when it fires every 12 seconds.
- The observer was connecting **as SYS with SYSDBA**: far more privilege than it needs (PCI-DSS req 7).
- Each failure costs the server a delayed logon (`Failed Logon Delay` in AWR).

## Root cause (observer)

The observer starts with `dgmgrl /@orcl3` from an auto-login wallet created 10-26 16:17 — the minute the
failures start. The wallet held **SYS**. DGMGRL/observer connections try **SYSDG** first and fall back to
SYSDBA. SYS has no SYSDG in the password file (`V$PWFILE_USERS.SYSDG = FALSE`), so every connection logged
one ORA-01031, then succeeded as SYSDBA. Reproduced by hand from obs-r2:

```
sqlplus /@orcl3 as sysdg   -> ORA-01031: insufficient privileges
sqlplus /@orcl3 as sysdba  -> SYS
```
and by restarting the observer: 6 new ORA-01031 records within 3 minutes.

## Fix — least privilege for the observer

1. A common user with **only SYSDG** (no SYSDBA, no other privileges):
   ```sql
   create user c##dgadmin identified by "..." container=all;
   grant sysdg to c##dgadmin container=all;
   ```
   The password file change reached the standby on its own (redo, 12.2+): `V$PWFILE_USERS` on stb3 lists
   `C##DGADMIN SYSDG=TRUE`.
2. A **new** wallet for the observer with `C##DGADMIN` for both aliases (`orcl3`, `orcl3_stb`) — the old
   wallet's password was not recorded anywhere, so its credentials could not be changed. New wallet tested
   with a temporary `TNS_ADMIN` before the swap (`SESSION_USER=SYSDG`, `AUTHENTICATED_IDENTITY=C##DGADMIN`
   on both databases); old wallet kept as `wallet.bak_sys`. Passwords live in the git-ignored `lab.env`.
3. Observer restarted with the new wallet.

## Result

| | Before | After |
|-|--------|-------|
| failed logons from the observer | 6 in 3 min after an observer restart (~7,000/day) | **0** in 3 min |
| FSFO with the observer (enabled briefly to test, then disabled again) | — | `Enabled in Zero Data Loss Mode`, observer obs-r2, configuration SUCCESS, **0** failed logons |
| privilege used by the observer | SYS / SYSDBA | `C##DGADMIN` / SYSDG only |

On the way: my first observer restart did not start anything — `start_observer.sh` checks
`pgrep "dgmgrl.*start observer"` and the old observer was still shutting down, so the script thought one
was running. Then my restart script stopped the observer and started nothing: `pgrep -if "dgmgrl.*start observer"`
also matched the script's own `bash -c` command line. Fixed in [`start_observer.sh`](start_observer.sh) (pattern anchored
to the dgmgrl binary path); [`restart_observer.sh`](restart_observer.sh) waits for the old process.
Reproducible setup: [`setup_dgadmin.sh`](setup_dgadmin.sh) (passwords from `lab.env`, see `lab.env.example`).

## Region A — same finding, same fix

The RAC region had the same observer setup: **1,689** SYS ORA-01031 from `dgmgrl@obs-r1` (plus 1,282
without host) since 10-26. Fixed the same way with its own passwords: `./setup_dgadmin.sh A`,
`./restart_observer.sh A` (which also anchored the same unanchored `pgrep` in obs-r1's `start_observer.sh`).
[`region-a-before-after.txt`](region-a-before-after.txt): **15** SYS ORA-01031 from obs-r1 in the 3 minutes
before (+15 without host) → **0** in the 3 minutes after.

## Still open — ORA-01017 with an empty username from the standby

Two records every time the standby instance ORCL3_STB starts, ~1 s after `Starting ORACLE instance`, to
service `ORCL3.rac`, listener `PROGRAM=oracle`. Redo transport, apply and the broker all work. Ruled out so far:

| Hypothesis | Test | Result |
|------------|------|--------|
| standby ARCn (FAL) with a stale password file | `ss -tnp` during a restart showed `ora_arc2` connecting at the same time; copied the primary's password file to the standby (old one kept) | still 2 failures → not the password file; ARCn timing was a coincidence |
| Data Guard broker | standby broker log | broker bootstrap starts *after* the failures |
| a wallet / external authentication | `sqlnet.ora` on stb3 | none exists |
| a script on stb3 | `oracle-db.sh`, `ogg-ha-controller.sh` | both connect locally (`/ as sysdba`), not over the network |
| client-side SQL*Net trace | `TRACE_LEVEL_CLIENT=16` during a restart | only the local sqlplus sessions were traced |
| kernel audit of `connect()` | `auditctl -S connect -F uid=oracle` | no events recorded — to investigate |

Region A shows the same pattern: `oracle@stb1.rac` 478 and `oracle@stb2.rac` 412 records, and 2 within the
minute I restarted orcl_stb (TDE drill) — so it is not specific to Region B's setup.

No account can be locked by these (no username). Next idea: `strace`/`bpftrace` on stb3 (not installed) or a
server-side errorstack on the primary (`event 1017`).
