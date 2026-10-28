# TDE — Transparent Data Encryption on RAC + Data Guard

Database: RAC primary `orcl` (prm1, ASM) → physical standby `orcl_stb` (stb1, Active Data Guard), FSFO with
observer obs-r1, GoldenGate GG_A capturing ORCLPDB2. Data: SECPDB / BANKDB ([baseline](../01-baseline/plaintext/)).

## 1. Keystore — [`01_keystore.sh`](01_keystore.sh)

| Step | What | Evidence |
|------|------|----------|
| `params` | `WALLET_ROOT='+DATA/<db_unique_name>'` (static → restart, **standby first**), `TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=FILE'`. FSFO disabled and GG_A stopped for the restarts, enabled again after | [`results/01-params.log`](results/01-params.log) |
| `create` | united mode keystore in `+DATA/ORCL/tde` (ASM: one keystore for every RAC instance), a master key for CDB$ROOT and each PDB (`container = all`), auto-login keystore (not *local*, so it can be copied) | [`results/02-create.log`](results/02-create.log) |
| `standby` | copy `ewallet.p12` + `cwallet.sso` into the standby's `+DATA/ORCL_STB/tde` — the keystore does **not** travel with redo | [`results/03-standby.log`](results/03-standby.log): standby `OPEN / AUTOLOGIN`, same 5 key IDs |
| `password`, `escrow` | change the keystore password, copy the keystore off the database host, compare md5 of all copies | [`results/04-password-escrow.log`](results/04-password-escrow.log) |

Status after this step: primary `OPEN / PASSWORD` (opened with the password; auto-login after the next
restart), standby `OPEN / AUTOLOGIN`, 5 master keys on both. Nothing encrypted yet — redo apply was
not affected (apply lag 0 after the keys were created, before the standby had them).

### What I learned on the way

- **`WITH BACKUP` backs up the keystore *before* the change.** The `ewallet_..._initial.p12` written by the
  first `SET KEY ... WITH BACKUP` is 3,584 bytes: an empty keystore, no key in it. The useful copy is the one
  taken **after** the key exists.
- **A failing `ADMINISTER KEY MANAGEMENT` statement prints the password.** sqlplus echoes the statement
  with the error (`ORA-02000 ... identified by "<password>"`). That happened to me once in a test (terminal
  only, no file): I **changed the keystore password**, deleted the keystore backups made under the old one,
  and the script now masks the password in every output.
- **`cwallet.sso` is the keys without a password.** And every `BACKUP KEYSTORE` writes another
  `cwallet_<time>_<tag>.sso` next to the `.p12`. The off-host copy holds only `.p12` files; the standby gets
  `cwallet.sso` VM-to-VM through a pipe; the extra `cwallet_*.sso` are removed.
- **Checking a keystore copy is not trivial in 23ai.** `orapki`/`mkstore` fail with `Got tag 3 instead of 16`
  (the file is not PKCS#12 — first bytes `43 22`, not `30`), and `MERGE KEYSTORE` from a file copy fails
  (`ORA-46638`, trace: `could not load the target with error 29106`). What the script checks: same md5 in ASM
  on both sites and off-host, and the password opens the live keystore. The real test of the off-host copy
  is a restore — see the drill below.
- **`BACKUP KEYSTORE` rewrites `ewallet.p12`** (md5 changes): check the password first, then copy.

### Operations rules (PCI-DSS 3.6 / 3.7)

- Back the keystore up after **every** key change (`SET KEY`, `REKEY`, password change) and copy it to the
  standby **before** the first encrypted change reaches it.
- The off-host copy and the keystore password are stored apart (here: `~/oracle-lab/keystore-backup/`,
  password in the git-ignored `lab.env`). The password is never on a command line.

## 2. Online tablespace encryption — [`02_encrypt_online.sh`](02_encrypt_online.sh)

`ALTER TABLESPACE bank_data ENCRYPTION ONLINE USING 'AES256' ENCRYPT` in SECPDB (512 MB file, 65 MB used),
while one session reads `CARDS`/`ACCOUNTS` and one updates `ACCOUNTS` every 50 ms.

| Operation | Primary | Application (90 s) | Standby |
|-----------|---------|--------------------|---------|
| `ENCRYPT` | 6 s, new datafile (ASM/OMF, no `FILE_NAME_CONVERT` needed) | — (my output bug, see below) | converted its own copy while applying the redo, `ENCRYPTED=YES`, apply lag 0 |
| `REKEY` (new tablespace key) | 6 s, datafile rewritten again | reader 1,711 ok / **0 errors**, writer 1,780 ok / **0 errors** | same, apply lag 0 |

Logs: [`results/05-encrypt-online.log`](results/05-encrypt-online.log), [`results/06-rekey-online.log`](results/06-rekey-online.log).
BANKDB checksums match on both sites after encryption.

**Result** — [`../01-baseline/plaintext/after.txt`](../01-baseline/plaintext/after.txt):

| File | PAN hits before | after |
|------|-----------------|-------|
| BANK_DATA datafile, primary | 4 | **0** |
| BANK_DATA datafile, standby | 3 | **0** |
| archived log with a new card | 3 | **0** |
| RMAN backup piece | 4 | **0** |

**What TDE did not fix** — [`residual_plaintext.sh`](../01-baseline/plaintext/residual_plaintext.sh), [`residual.txt`](../01-baseline/plaintext/residual.txt):
- 2 of 51 archived logs still hold the card number in clear: seq 41 = the SECPDB load (before encryption),
  and seq 21 from 01:32 — **DRILLPDB**, the backup-drill PDB with the *same* BANKDB data, never
  encrypted. A test copy of card data is in PCI scope like production → DRILLPDB's `BANK_DATA` encrypted too
  (6 s, `verify_drillpdb.sh` PASS, [`results/05b-drillpdb-encrypt.log`](results/05b-drillpdb-encrypt.log)).
- Pre-encryption archived logs and backups stay readable until they age out. To do in production: a new
  level 0 right after encrypting, then remove older backups/archived logs when the retention allows
  (not done here — deleting backups is not my call in this lab).
- New tablespaces are still created unencrypted (`TABLESPACE_ENCRYPTION=MANUAL_ENABLE`). Option:
  `AUTO_ENABLE` (every new tablespace encrypted).

**Key rotation, two levels:** `SET KEY` rotates the **master key** (re-wraps the tablespace keys, no data
rewritten, seconds); `REKEY` changes the **tablespace key** and rewrites the file (above: 6 s for 512 MB).
