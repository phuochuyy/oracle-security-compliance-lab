# Baseline — card numbers are readable outside the database

**Database:** SECPDB on the RAC primary `orcl` (ASM `+DATA`), standby `orcl_stb`, BANKDB scale 1
([`00-setup/create_secpdb.sh`](../../00-setup/create_secpdb.sh), checksums match on both sites).
`BANK.CARDS.PAN` holds 16-digit card numbers.

**Test:** [`check_plaintext.sh`](check_plaintext.sh) takes the PAN of card 1 and counts how often it appears
in the raw bytes of files a thief could copy — no database login needed. Output: [`before.txt`](before.txt).

| File | Hits before TDE |
|------|-----------------|
| BANK_DATA datafile, primary (copied out of ASM) | 4 |
| BANK_DATA datafile, standby | 3 |
| archived redo log after inserting a test card | 3 |
| RMAN backup piece of BANK_DATA (uncompressed) | 4 |

Several hits per file: the table row and the unique index `CARDS_PAN_UK` entry, plus older block versions.
The standby has the same data — Data Guard copies the exposure to the second site.

**Notes**
- The regular backups here are `COMPRESSED BACKUPSET`: a plain grep finds nothing, but that is not
  protection — RMAN restores them on any host without a key. The test uses an uncompressed piece.
- The PAN is never written to the output: only the first 4 and last 4 digits (PCI-DSS 3.4 allows that).
- PCI-DSS 3.5: stored PAN must be unreadable. Next: [TDE](../../02-tde/).
