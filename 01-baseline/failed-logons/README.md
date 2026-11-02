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

## My own lab script had the same problem

`labctl.sh` (the lab control script, HA/DR repo) ran every broker command as `dgmgrl sys/<password>@...`:
one more SYS ORA-01031 per call (SYSDG tried first), and the SYS password on the command line of the VM
(visible in `ps`). Since 2026-10-29 it connects as `C##DGADMIN` with the password on stdin, read from a
mode-600 file — **0 SYS ORA-01031** since, across two scenario switches (`dg-a`, `dg-b`) and a snapshot
standby drill. (The empty-user ORA-01017 of 1b still came with every standby restart: 10 on orcl3 from stb3
during that drill, whose conversions restart the standby.)

## 1b — ORA-01017 with an empty username from the standby (source found 2026-11-02, see the end)

Two records every time the standby instance ORCL3_STB starts, ~1 s after `Starting ORACLE instance`, to
service `ORCL3.rac`, listener `PROGRAM=oracle`. Redo transport, apply and the broker all work. Ruled out so far:

| Hypothesis | Test | Result |
|------------|------|--------|
| standby ARCn (FAL) with a stale password file | `ss -tnp` during a restart showed `ora_arc2` connecting at the same time; copied the primary's password file to the standby (old one kept) | still 2 failures → not the password file; ARCn timing was a coincidence |
| Data Guard broker | standby broker log | broker bootstrap starts *after* the failures — **wrong on Region A**, see 2026-11-02: the broker's `NSV0` is one of the sources |
| a wallet / external authentication | `sqlnet.ora` on stb3 | none exists |
| a script on stb3 | `oracle-db.sh`, `ogg-ha-controller.sh` | both connect locally (`/ as sysdba`), not over the network |
| client-side SQL*Net trace | `TRACE_LEVEL_CLIENT=16` during a restart | only the local sqlplus sessions were traced |
| kernel audit of `connect()` | `auditctl -S connect -F uid=oracle` | no events recorded — **my mistake**: the events were there, `ausearch -ts` returned nothing (2026-11-02) |

Region A shows the same pattern: `oracle@stb1.rac` 478 and `oracle@stb2.rac` 412 records, and 2 within the
minute I restarted orcl_stb (TDE drill) — so it is not specific to Region B's setup.

**New evidence (found by the health-check playbook of the automation lab):** after a lab start, prm1's
listener log shows the standby connecting to the primary in bursts — `PROGRAM=oracle`, `HOST=stb1`,
`SERVICE_NAME=orcl.rac`, each connection redirected once with `INSTANCE_NAME=orcl1`:

| Window | stb1 → prm1 connections (listener) | ORA-01017, empty user |
|--------|-------------------------------------|-----------------------|
| 22:06–22:09 (standby start) | 4 | 2 on prm1, 2 on stb1 (22:08:04) |
| 22:19:08–22:19:10 | 22 | 4 on prm1, 4 on stb1 (22:19:10) |
| 22:10–22:18, 22:20–22:29 | 0 | 0 |

My own SQL that ran at 22:19 was ruled out: each statement alone on the standby, and the whole script,
produced 0 new failures. So the failures come with Data Guard's internal standby→primary connections,
not with a client. Next: what opens that burst ~11 min after the start (broker/FSFO health check, gap or
statistics fetch), and a server-side trace of one of those connections.

No account can be locked by these (no username). Next idea: `strace`/`bpftrace` on stb3 (not installed) or a
server-side errorstack on the primary (`event 1017`).

## Re-run 2026-10-29 — 1b during failovers

6 hours including the HA/DR failover tests ([`rerun-20261029.txt`](rerun-20261029.txt)): **0 SYS ORA-01031**.
18 empty-user ORA-01017, all between 12:04 and 13:01, the window of the switchovers and the two FSFO failovers
with reinstates: 13 from `oracle@stb1.rac (TNS V1-V3)`, 3 from `oracle@prm1.rac` (from both sides, as the
roles changed), 2 pairs from `dgmgrl@stb1.rac` (an empty user, then `/`, 1 s later — not from my scripts,
which connect as `C##DGADMIN` and would show that user). Fits the lead above: Data Guard's own connections at role
changes and restarts. Still open.

## 2026-10-30 — one more source of empty-user ORA-01017

After a cold start the standby's audit trail had, besides the known `oracle@stb1.rac (TNS V1-V3)` records,
2 empty-user ORA-01017 from **`OraJavaAgentDriver` on stb1** at the database start (00:48) — the Java agent
of Grid's CVU, which on the primary logs in as DBSNMP with the credential from the cluster wallet `CVUDB`.
The standby's cluster has no `CVUDB` wallet (`crsctl query wallet -type CVUDB` → CLSW-9), so its agent
tries without a user. That explains those 2, not the `oracle@stb1` ones (different program) — 1b stayed open (until 2026-11-02, below).

## 2026-11-02 — 1b traced to Oracle's internal connections; a real stale password file on stb2

Evidence: [`20261102/`](20261102/). Region A started with prm1 + stb1 + stb2 (no observer).

**First, a real ORA-01017 that was not 1b.** Besides the empty-user records, the primary had **8 SYS
ORA-01017 from stb2** at 00:56–00:59 (stb2 had been started once to receive files), and the standby had SYS
rejected from prm1 on instance 2 (1 at 00:58, 2 at 10:22). Cause: `orcl_stb` had **no password file
registered in CRS** (`Password file:` empty), so each instance used its own `$ORACLE_HOME/dbs/orapw<SID>`.
Redo updated stb1's file at the SYS rotation of 10-29 (17:08); stb2 was off, its file stayed the one of
08-25 ([before](20261102/pwfile-before.txt)). My rotation runbook said "password file in ASM → standby" —
true for the primary only. Fix: stb1's file copied into ASM (`asmcmd pwcopy` as grid — its
`--dbuniquename` form failed: grid may not modify the oracle-owned resource), registered with
`srvctl modify database -db orcl_stb -pwfile +DATA/ORCL_STB/PASSWORD/pwdorcl_stb`, stb2's local file
renamed `.bak_20261102`, stb2 restarted. After: both instances on the ASM file
(`gv$passwordfile_info`), **0 SYS ORA-01017** over two restarts of stb2, transport VALID / NO GAP, lag 0
([after](20261102/logons-and-pwfile-after.txt)). stb1's local file is still there (unused); renamed at its
next restart.

**Then 1b itself.** Every start of stb2 still produced one empty-user ORA-01017 on the primary (10:28:06,
10:32:22). With the kernel audit of `connect()` on stb2 during the second restart
([`stb2_auditd_connect_to_primary.txt`](20261102/stb2_auditd_connect_to_primary.txt)), the **only** process
on stb2 that connected to the primary's listeners was **`ora_nsv0`** — the broker's network process (created
10:32:19). Its trace ([`stb2_nsv0_36532.trc`](20261102/stb2_nsv0_36532.trc)):

```
*** 2026-11-02T10:32:22.585751+07:00
KGFCHECK kgfnStmtExecute01c: (ret == OCI_SUCCESS): FAILED at kgfn.c:3936
*** 2026-11-02T10:32:22.845064+07:00
rfiupicl(): Connect identifier used is: orcl
Connected to instance 1 [DRCX (pid=20140 dbun=orcl inst=orcl1 host=prm1.rac)]
```

The same `kgfnStmtExecute01c FAILED` line is in the traces of 4 MMON slaves on stb2 (`M001`–`M004`, action
"RAC PDB Flush Slave Action", next to `kgfpOpenPwFile` / `kgfpFileAttr` on the password file —
[`stb2_m002_36921.trc`](20261102/stb2_m002_36921.trc)) — matching the 4 empty-user records at
10:32:47–48 — and of `M000` on stb1 (2 records at 10:32:52–53). So the empty-user logons are the first
attempt of internal connections made through Oracle's `kgfn` layer; the next attempt succeeds (NSV0
connected 0.26 s later; the standby's internal logons show up as `PUBLIC`/`SYSOPER`, return code 0).

**What I can and cannot say:** the source processes are identified, the failures carry no username (no
account can be locked) and the work they belong to succeeds. *Why* `kgfn` tries without a username first
is inside Oracle's code — I found no note for it (closest: MOS 2115559.1, ORA-1017 from the broker at a
RAC switchover). **Status: explained, accepted.** A failed-logon alert should exclude exactly this pattern
(empty username, program `oracle@<own standby/primary host> (TNS V1-V3)`), never all ORA-01017.

**Two corrections to my earlier counts:** the standby's `UNIFIED_AUDIT_TRAIL` also shows the primary's
records (they arrive by redo, same `OS_PROCESS`), so counting "2 on prm1, 2 on stb1" double-counts if
those are the same records — the earlier per-site numbers were not re-checked for this. And the
"no events recorded" of the kernel audit (table above) was `ausearch -ts` returning nothing; the events
were in `/var/log/audit/audit.log`.

