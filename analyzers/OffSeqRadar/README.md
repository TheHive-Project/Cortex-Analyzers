# OffSeq Radar Analyzer

Query [OffSeq Threat Radar](https://radar.offseq.com), a vulnerability and threat intelligence service that combines NVD, CISA KEV, FIRST EPSS, ENISA EUVD, public exploit sources (Metasploit, Exploit-DB, nuclei, PoC-in-GitHub) and exploitation observed by OffSeq's Mirage honeypots.

### Flavors

| Flavor | Data types | Returns |
|--------|------------|---------|
| `OffSeqRadar_CVE` | `cve` | Priority score (0–100) with its factors, CVSS, CISA KEV dates and ransomware use, EPSS with percentile, exploit maturity and sources, ENISA EUVD status, product and CWEs. |
| `OffSeqRadar_IOC` | `ip`, `domain`, `fqdn`, `url`, `hash`, `mail`, `filename` | Threat reports (up to 5) whose extracted indicators contain the observable. |

### Taxonomies

- `OffSeqRadar:Priority` – `malicious` for the critical band, `suspicious` for high.
- `OffSeqRadar:KEV` – `malicious` when the CVE is in CISA KEV.
- `OffSeqRadar:EPSS` – `suspicious` at 0.1 or above.
- `OffSeqRadar:Exploit` – public exploit maturity, when known.
- `OffSeqRadar:Threats` – number of matching reports; `suspicious` when an indicator matches the observable exactly.

### Requirements

1. Create an account at [radar.offseq.com](https://radar.offseq.com/console?auth=signup). Every plan, including the free one, has API access within its quota.
2. Create an API key under **Console > Settings**.

### Configuration

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `key` | OffSeq Radar API key. | yes | |
| `base_url` | API base URL. | no | `https://radar.offseq.com/api/v1` |

API reference: [radar.offseq.com/api-docs](https://radar.offseq.com/api-docs) ([OpenAPI](https://radar.offseq.com/openapi.json)).
