# Strategy: database security

The plan behind this lab, written as I would for a real system. Results: [details](details.md). Mapping to requirements: [PCI-DSS](../05-assessment/pci-dss-mapping.md).

## Goal

Card data unreadable outside the database, every access to it recorded, each account holding only what it needs, and proof of all this that can be rerun. A control that breaks the standby or replication is not finished, so each one is tested with both.

## Layers

| Layer | Control | How it is verified |
|-------|---------|--------------------|
| Data at rest | TDE on tablespaces with card data, on primary, standby and GoldenGate trails; encrypted backups | [Search the raw files for a known card number](../01-baseline/plaintext/check_plaintext.sh) |
| Data in transit | Native network encryption required, including redo transport | [New connections and session list](../03-hardening/01_params_network.sh) |
| Network access | Listener allow list in Region B | [Refused from an unlisted machine, the required ones still connect](../03-hardening/08_valid_nodes.sh) |
| Access | Profiles, schema-only owner, PUBLIC grants revoked, separate Data Guard administrator, Privilege Analysis | [Assessment](../05-assessment/assess.sh) |
| Display | Data Redaction of card numbers | Test users. A `WHERE` clause still sees the real value, which the next layer limits |
| Rows | Virtual Private Database: an analyst reaches only their own region's cards | [Test users of two regions and one without an assignment](../03-hardening/06_vpd.sh) |
| Records | Unified Auditing, archive then purge, daily off-host copy, and a summary of each record sent off the machine as it is written | [Test scenario](../04-auditing/README.md) |

## Running it

- **Baseline and drift:** the assessment script runs on both regions after every change and must stay at 0 FAIL. A [weekly check](../05-assessment/drift_check.sh) compares it with the accepted baseline and reports what changed; on a real system the report would go to the security team.
- **Exceptions register:** a deviation is an `ACCEPT` line in the assessment with its reason, not a hidden check.
- **Key management:** after every master key change the keystore goes to the standby first, or its redo apply stops. An off-host keystore copy exists; a restore needs it.
- **Accounts:** people expire, service accounts rotate by a [written procedure](../03-hardening/password-rotation.md) listing every place a credential lives, including nodes that are off.
- **Before revoking:** check `DBA_DEPENDENCIES`, grant directly, count invalid objects before and after.

## What a control costs

Security has a price, and it should be known: [TDE](https://github.com/phuochuyy/oracle-performance-tuning-lab/tree/main/03-cases/09-tde-overhead), [auditing](https://github.com/phuochuyy/oracle-performance-tuning-lab/tree/main/03-cases/10-audit-overhead). TDE and Data Redaction need Advanced Security; Database Vault is another option and was not used here.

## Limits

The checks are my own script in the style of the CIS benchmark, not DBSAT (no support contract), and they are not mapped to CIS numbers. No real central log server (the host stands in for one), no HSM, no Database Vault, and one person holds every key: a bank separates these duties. No release updates applied. Passing my own checks is not a compliance claim.
