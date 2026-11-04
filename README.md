# Oracle Security & Compliance Lab

A banking database with card-like test data, hardened along PCI-DSS lines. The lab also shows what each control does to Data Guard and GoldenGate, because a control that breaks the standby is not finished.

## What is in it

- **Encryption at rest** with TDE on the primary, the standby and the GoldenGate trail files.
- **Network encryption**, including redo transport.
- **Least privilege**: a separate Data Guard administrator, service profiles, Privilege Analysis.
- **Unified Auditing** with an archive-then-purge retention job.
- **Data Redaction** of card numbers.
- **An assessment script** in the style of CIS, mapped to PCI-DSS with evidence.

TDE and Data Redaction are part of Oracle Advanced Security, an extra-cost option on Enterprise Edition on-premises.

## Where to look

- [Findings and results](docs/details.md)
- [TDE](02-tde/README.md)
- [Hardening](03-hardening/README.md)
- [Auditing](04-auditing/README.md)
- [Assessment](05-assessment/README.md)
- [PCI-DSS mapping](05-assessment/pci-dss-mapping.md)
- [Worklog, including my mistakes](notes/worklog.md)
