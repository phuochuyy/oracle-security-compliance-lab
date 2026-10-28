# Worklog — problems hit while building this lab

## Finding 1: failed SYS logons (branch `findings/failed-logons`)

- Counted the failed logons: 1,325 SYS ORA-01031 from `dgmgrl@obs-r2`, plus a second record without a host
  for each, and 41 ORA-01017 with an empty user from `oracle@stb3`.
- **stb3 ORA-01017, wrong guess first:** `ss -tnp` caught `ora_arc2` connecting at the same moment, and the
  standby's password file differed from the primary's → I copied the primary's file over (old one kept as
  `orapwORCL3.bak_before_sync`). Still 2 failures per start. The timing put them ~1 s after instance start,
  before the broker; client tracing and `auditctl` gave nothing. Left open, documented.
- **Observer:** `sqlplus /@orcl3 as sysdg` → ORA-01031 reproduced it. The wallet password was not recorded
  anywhere, so I built a new wallet instead of editing the old one.
- **Restarting the observer, twice wrong:** (1) the old observer was still exiting when `start_observer.sh`
  ran, so it thought one was running; (2) after I added a wait, the script's unanchored `pgrep -if
  "dgmgrl.*start observer"` matched my own `bash -c` command line. Observer was down ~1 min. Same
  `pgrep -f` self-match as in the perf lab — anchored the pattern to the binary path.
- Side finding on stb3: no HugePages (`2048K pages available 0`, memlock 8 MB) — SGA on 4K pages.
