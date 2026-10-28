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

## SECPDB and the plaintext baseline (branch `setup/secpdb`)

- Moved to RAC Region A (`labctl.sh dg-a`: prm1 + stb1 + obs-r1 + prm3). SECPDB created from the seed on
  the primary; on the standby it stayed **MOUNTED** — `SAVE STATE` on the primary does not open it there.
  `alter pluggable database secpdb open read only` on stb1, then the checksums matched.
- First run of `check_plaintext.sh`: the archived log showed 0 hits for a card I had just inserted. The
  query took the highest `SEQUENCE#` — seq 376 from **before the RESETLOGS** of the backup drills (current
  incarnation is at seq ~41). Fixed by filtering on `V$DATABASE.RESETLOGS_CHANGE#`; then 3 hits.

## TDE keystore (branch `tde/keystore`)

- `WALLET_ROOT` is static: restarted the standby first, then the primary (FSFO disabled, GG_A stopped).
  `agctl start goldengate GG_A` answered `XAG-216: already running` — XAG had already started GG_A with
  the database.
- The `WITH BACKUP` file of the first `SET KEY` is an empty keystore (3,584 bytes): taken before the change.
- Tried to verify the off-host copy: `mkstore -list` and `orapki wallet display` → `Got tag 3 instead of 16`
  (same md5 as in ASM, so not a broken copy — the 23ai keystore is not PKCS#12). `MERGE KEYSTORE ... INTO
  NEW KEYSTORE` → `ORA-02000 missing EXISTING keyword` (23ai only merges into an existing keystore), then
  `INTO EXISTING` → `ORA-46638`, trace `could not load the target with error 29106`. `BACKUP KEYSTORE ... TO
  '/tmp/ksb'` → `ORA-46620`. Gave up on a file-level check; the restore drill will test the copy.
- **My mistake:** the `ORA-02000` error printed the keystore password in my terminal. Changed the password,
  deleted backups made under the old one, added masking to the script.
- Password-change run: the keystore password changed, but the script then called itself (`"$0" escrow`),
  which re-read `lab.env` with the **old** password → `ORA-46627 password mismatch` in the check. Nothing
  broken — saved the new password, then rewrote the modes as functions.
- md5 of `ewallet.p12` changed after every check: `BACKUP KEYSTORE` (my password check) rewrites it.
  Check first, copy second.
- Every `BACKUP KEYSTORE` also writes a `cwallet_<time>.sso`: password-free key copies piling up in ASM
  and in my off-host folder. Off-host copy is `.p12` only now; extra `.sso` removed.
