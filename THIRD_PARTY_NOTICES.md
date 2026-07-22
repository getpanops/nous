# Third-Party Notices — nous

The nous intel bundle is assembled at build time from the upstream sources listed below.
The **nous source code** (updater, rules, grafana/) is MIT-licensed — see [LICENSE](LICENSE).
The **assembled OCI bundle** is a composite work and carries the licenses of its constituent sources.

---

## Intelligence Sources

### SigmaHQ Community Detection Rules
- **License:** Detection Rules License 1.1 (DRL 1.1)
- **Source:** https://github.com/SigmaHQ/sigma
- **DRL summary:** Permits use for detection, research, and building detection platforms. Does not permit building a competing rule *distribution* service without written permission from the SigmaHQ project. Attribution required.

### YARA-Forge Curated Ruleset
- **License:** CC BY 4.0 (curation layer); underlying rules carry their original per-rule licenses
- **Source:** https://github.com/YARAHQ/yara-forge
- **Note:** Review individual rule metadata for upstream attribution. Commercial redistribution of the assembled ruleset should account for per-rule license terms.

### Signature-Base (Florian Roth)
- **License:** CC BY-NC 4.0
- **Source:** https://github.com/Neo23x0/signature-base
- **Restriction:** NonCommercial clause applies. Do not include in commercially redistributed bundles. Self-hosted, non-commercial detection use is permitted with attribution.

### Emerging Threats Open Rules (Suricata)
- **License:** BSD 2-Clause
- **Source:** https://rules.emergingthreats.net/open/suricata-7.0/

### MITRE ATT&CK Enterprise (STIX)
- **License:** CC BY 4.0
- **Source:** https://github.com/mitre-attack/attack-stix-data
- **Attribution:** "This project makes use of ATT&CK® — MITRE ATT&CK® is a registered trademark of The MITRE Corporation."

### CISA Known Exploited Vulnerabilities Catalog
- **License:** Public Domain (US Government Work)
- **Source:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog

### Elastic Security Detection Rules
- **License:** Elastic License 2.0 (EL2)
- **Source:** https://github.com/elastic/detection-rules
- **Restriction:** EL2 prohibits providing this content as part of a managed/SaaS service offered to third parties. Self-hosted use is permitted. These rules are downloaded as reference only and should not be redistributed commercially.

---

## Operations Sources

### kubernetes-mixin
- **License:** Apache 2.0
- **Source:** https://github.com/kubernetes-monitoring/kubernetes-mixin

### node_exporter mixin
- **License:** Apache 2.0
- **Source:** https://github.com/prometheus/node_exporter

### etcd mixin
- **License:** Apache 2.0
- **Source:** https://github.com/etcd-io/etcd

### Awesome Prometheus Alerts
- **License:** MIT
- **Source:** https://github.com/samber/awesome-prometheus-alerts

### Pyrra SLO Examples
- **License:** Apache 2.0
- **Source:** https://github.com/pyrra-dev/pyrra

### OpenSLO Examples
- **License:** Apache 2.0
- **Source:** https://github.com/OpenSLO/OpenSLO

### Container Solutions Kubernetes Runbooks
- **License:** Apache 2.0
- **Source:** https://github.com/containersolutions/runbooks
