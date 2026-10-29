# Rotating the shared lab password (2026-10-29)

Why: finding 10 — the GoldenGate admin password was readable by any local user on prm1, stb1 and prm3.
The same value turned out to be the password of **16 accounts**. Rotated all of them to one new random value
(23 characters), the old one kept in a mode-600 file only until every check passed.

## 1. Inventory — before changing anything

| Where | How it was found |
|-------|------------------|
| `lab.env` of 3 repos + the lab control script (`DB_PASSWORD`, `OGG_PASSWORD`, `OGG_ADMIN_PASSWORD`) | compared values, printed only the variable names |
| Ansible vault (`vault_ogg_admin_password`) | `ansible-vault view` compared, not printed |
| `pathsync.conf` on prm1, stb1, prm3 (+ the host copies `labctl` deploys) | `grep -F` with the password on stdin |
| alias `dgb` in stb1's `.bash_profile` (`dgmgrl sys/<pw>@orcl_stb`) | same |
| database accounts | a login test per open account (16 of 32 matched) |

Database accounts with the shared value: orcl — SYS, SYSTEM, DBSNMP, BANK + PDBADMIN (DRILLPDB), GGADMIN +
DBFS_USER (ORCLPDB2); orcl3 — SYS, SYSTEM, BANK + PDBADMIN (DRILLPDB), GGADMIN + DBFS_USER + PDBADMIN (GGREPL),
PDBADMIN (PERF, RCAT). GoldenGate: `oggadmin` in 4 user stores (Service Manager and Admin Server, each site).

## 2. What depends on each one

| Account | Depends on it | Done |
|---------|---------------|------|
| SYS (orcl) | password file in ASM → standby orcl_stb (redo transport authenticates as SYS: `redo_transport_user` empty) | `ALTER USER` on the primary; the standby's password file was updated **through redo** — SYS on orcl_stb accepted the new password, rejected the old one |
| SYS (orcl3) | password file `orapwORCL3` on stb3 — **stb3 was off** | copy kept on the host; `labctl` installs it when stb3 next starts (one-time `files/pending/`) |
| DBSNMP (orcl) | Grid's CVU (`ora.cvu`, program `OraJavaAgentDriver`) via the cluster wallet `CVUDB` | `crsctl modify wallet -type CVUDB -name orcl -user DBSNMP -passwd` — refused as root (CLSW-17) and grid (CLSW-12), no error as **oracle** — to confirm at CVU's next DBSNMP logon |
| GGADMIN | GG credential store aliases `OGG_A` / `OGG_B` | `ALTER CREDENTIALSTORE REPLACE USER ...`, `DBLOGIN USERIDALIAS` OK |
| DBFS_USER | `dbfs_client` wallet on **every** node of the region (`/u01/app/oracle/ogg_tns/wallet`), 3 of 6 nodes off | wallet password unknown (not recorded anywhere) → new wallets built beside the old ones, swapped right after `ALTER USER`; `sqlplus /@DBFS_A` / `/@DBFS_B` OK on the 3 running nodes; copies for prm2, stb2, stb3 installed by `labctl` at their next start |
| oggadmin | 4 user stores; distribution path credentials `GG_B_RCV` / `GG_A_RCV` (domain OGGNET) on the *other* site; **XAG** (checks GG_A every 30 s); `pathsync.conf` | REST `PATCH /services/v2/authorizations/Security/oggadmin` per port; `agctl modify goldengate GG_A --adminuser oggadmin` in the same second (window 2 s, XAG restart count 0); path aliases replaced; both paths restarted to re-authenticate |

## 3. Checks after

- SYS: new password accepted on orcl, orcl_stb, orcl3; old one refused (ORA-01017).
- Broker Region A SUCCESS, FSFO enabled, transport/apply lag 0; dest 2 VALID after a log switch.
- RMAN with `lab.env` to the standby + recovery catalog: connected.
- GoldenGate: old password HTTP 403, new 200 on all 4 ports; marker rows both ways (10 of 10 in 20 s);
  `labctl status`, `gg.sh`, `timeline.sh` with the new `lab.env`.
- Ansible `health.yml` with the re-encrypted vault: ok on all running hosts.
- Removed: old DBFS wallets, the `dgb` password, a backup of the control script that still held it.
  Shell histories and one XAG log on the VMs still contain the **old** value — now useless.

## Problems on the way

- `ALTER USER DBSNMP` failed with `ORA-04036` (PGA_AGGREGATE_LIMIT 2 GB reached: 10 MMON slaves held
  383 MB); worked on retry a minute later.
- My REST script changed port 9100, then used the *new* password to authenticate on 9101 — HTTP 403:
  Service Manager and Admin Server have **separate user stores**. Re-run for 9101 with the old one.
- `ansible-vault encrypt --vault-password-file` with `vault_password_file` already in `ansible.cfg`:
  "vault-ids default,default" error, the vault was not rewritten; the decrypted copy was still on disk
  until I re-ran without the option and shredded it.
- While I was checking, GG_A stopped: not the password change — **the primary hung on a full `+FRA`**
  ("Stuck Archiver"), CRS stopped the `ogg_a` service tree with it. See the backup lab's README.

## Missed, found by the next failover test (same evening)

XAG stores the GoldenGate admin password **per cluster**. I updated it on the primary's cluster only; the
standby's cluster (stb1/stb2) kept the old one. Nothing showed it until a failover to stb1: XAG's health
check returned `3`, the start timed out after 300 s and GoldenGate stayed down (the database was fine,
0 transactions lost). `agctl modify goldengate GG_A --adminuser oggadmin` on stb1, then the next failover
recovered by itself in 1 min 49 s ([HA/DR run 3](https://github.com/phuochuyy/oracle-ha-dr-failover-lab#run-3--after-the-password-rotation-2026-10-29-evening)).
Lesson: a credential inventory has to cover every cluster, and a rotation is only finished after a role change.

