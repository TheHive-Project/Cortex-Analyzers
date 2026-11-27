### Flowtriq

Check [Flowtriq](https://flowtriq.com) for DDoS attack intelligence on an IP address.

Flowtriq is a DDoS detection and mitigation platform. This analyzer queries its threat intelligence API to determine whether an IP has been observed participating in DDoS attacks across Flowtriq's monitored infrastructure.

#### Returned Data

- **Risk score** (0-100) indicating overall threat level
- **Attack count** and number of networks where the IP was seen
- **Attack families** (e.g., DNS amplification, NTP reflection, SYN flood)
- **Severity breakdown** (critical, high, medium, low)
- **Peak traffic rates** (PPS/BPS)
- **First/last seen timestamps**
- **Related attacker IPs** (co-occurring sources in the same incidents)
- **Threat intel feed matches**
- **ASN and country** of the queried IP

#### Requirements

A Flowtriq API key is required. Configure it as the `api_key` parameter.

Optionally, set `api_url` if using a self-hosted Flowtriq instance (defaults to `https://flowtriq.com`).
