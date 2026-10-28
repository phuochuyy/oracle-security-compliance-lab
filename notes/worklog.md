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

## Online encryption (branch `tde/encrypt-online`)

- First run lost the application numbers: `set serveroutput on` came before `alter session set container`
  → no DBMS_OUTPUT at all in the PDB. Moved it after the switch; the numbers come from the REKEY run.
- `residual_plaintext.sh` first said "0 of 51 logs" — the `ssh` inside `while read` swallowed the loop's
  input, only one log was checked. `ssh -n`; then 2 logs with hits.
- One of them was from DRILLPDB (same PAN as SECPDB, deterministic data): encrypted it too.

## Observer Region A (branch `findings/observer-region-a`)

- Found while preparing the TDE switchover: wanted the broker as a SYSDG user instead of SYS, ran the
  failed-logon query on orcl → 1,689 SYS ORA-01031 from obs-r1. Same cause as Region B.
- Scripts take the region now (`A`/`B`), separate passwords per CDB (`*_A` in lab.env).
- obs-r1's `start_observer.sh` had the same unanchored `pgrep -if` — fixed before restarting this time.

## TDE with Data Guard (branch `tde/dataguard`)

- Rotation drill: my `dml()` ran `alter system archive log current` inside SECPDB → `ORA-65040`, but the log
  line still said "log archived". The drill result holds anyway: real-time apply read the `SET KEY` redo from
  the standby redo log and MRP stopped with `ORA-28374` within seconds. Fixed (switch to CDB$ROOT).
- After copying the new keystore, the standby still showed 5 keys in `V$ENCRYPTION_KEYS` (primary: 6), but
  apply ran again; after the next keystore open it showed 6.
- **Switchover, first attempt:** the new primary orcl_stb had SECPDB `MOUNTED`; after opening it,
  `ORA-28365 Wallet is not open` on the encrypted table, and my checksum query failed with it. Cause was my
  own restore in the "lost keystore" drill: I opened the keystore with the password and created
  `cwallet.sso`, but the keystore stayed `OPEN / PASSWORD` — a PDB opened later does not get the keystore.
  Restore step now closes the keystore at the end, so it reopens as AUTOLOGIN. orcl_stb itself was fixed by
  the restart Clusterware did during the switchback (`OPEN / AUTOLOGIN` after it).
- **Switchback took 348 s** (switchover: 63 s). My script sent it 1 s after the first switchover; the broker
  log shows `Forwarding CTL_SWITCH` at 19:26:17 and nothing until `Starting task: SWITCHOVER` at 19:31:26,
  while orcl was just restarting as standby (and stb1 logged heavy swapping). The script now waits for
  `VALIDATE DATABASE ... Ready for Switchover: Yes`. Rerun for clean numbers.

## TDE and GoldenGate (branch `tde/goldengate`)

- Expected Extract to need something for encrypted redo — it did not (Integrated Extract uses the database
  keystore). The surprise was the other way: clear PANs in every trail after TDE.
- `ENCRYPTTRAIL` + `ETROLLOVER` → both Extracts `ABENDED`, `OGG-06114`: no master key in the deployment
  wallet (empty directory). `ADD MASTERKEY` on GG_A, copied `cwallet.sso` VM-to-VM to GG_B. `START EXTRACT
  EXTA` said "already running": the HA profile had restarted it in the meantime (autoRestart 15 s).
- Cleanup followed the A-A rule (Replicats stopped after passing the last change, drop, start): no abend.

## Assessment (DBSAT replaced) and parameters/network (branches `assessment/cis-baseline`, `hardening/params-network`)

- DBSAT: MOS registration with the CSI of my OCI Free Tier tenancy failed (`VBCP-PPEP-776`). Wrote the
  checks myself, CIS sections + PCI checks.
- `checks.sql` first run: `PLS-00103` — a constant declared after the local procedures; then `nvl('missing: '
  || v, ...)` was never null, so PASS lines said "missing:"; `REDACTION_COLUMNS` has no `POLICY_NAME`.
- P01 `AUDIT_SYS_OPERATIONS=FALSE`: static, and only for traditional audit (desupported in 23ai). Changed
  the check to accept the unified equivalent (`ORA_ALL_TOPLEVEL_ACTIONS` for SYS).
- Test connection: `localhost` → `ORA-12541` (listener on the node IP), then `ORA-12514` (service name is
  `secpdb_app.rac`, db_domain).
- After the sqlnet change only *new* sessions were encrypted: restarted EXTA/REPA (graceful STOP is not
  restarted by the HA profile — had to START them), the observer, and the standby for redo transport.

## Profiles and PUBLIC grants (branch `hardening/profiles-privs`)

- Revoking network/file packages from PUBLIC invalidated 14 Oracle objects (CTXSYS, GSMADMIN_INTERNAL incl.
  a LOGOFF trigger, MDSYS). Should have checked `DBA_DEPENDENCIES` first; fixed with direct grants.
- `UTL_MAIL` is not installed here (`ORA-04042` on the revoke) — harmless.
- First dependency query: `ORA-00918 CON_ID ambiguous` (two CDB views joined).
- Network test switched from BANK to PDBADMIN, since BANK cannot log in any more.

## Auditing and redaction (branches `auditing/policies`, `hardening/redaction`)

- `CREATE PUBLIC SYNONYM` is not an action option (`ORA-46356`) — `CREATE SYNONYM` covers it.
- Common policy without `C##` → `ORA-65095`.
- `AUDIT POLICY ora_login_logout` on top of the default `WHENEVER NOT SUCCESSFUL` changed nothing: needed
  `NOAUDIT` first. And enabling it in the root did not change SECPDB.
- Test run 1: the strong verify function rejected my own random test password (`ORA-28003 ... 2 or more
  digits`) — the profile works; the generator now always has 2 digits/upper/lower/special.
- **Test run 2 found two real mistakes:** (1) `actions select, insert, update, delete on bank.cards` puts
  `ON` only on DELETE — SELECT/INSERT/UPDATE were audited on *every* object (dictionary noise under the
  CARDS policy). (2) The common `C##SEC_CHANGES` enabled in the root did not record DDL of a **local** user
  in SECPDB (tested with and without a local policy). My assessment check had said PASS for both — fixed the
  checks too (C02 needs all four actions on CARDS; in a PDB only local policies count).
- Redaction log: the first run printed FRAUD_OPS's full (synthetic) PANs; masked the saved log with sed and
  added the same masking to the script before committing.
