# DECTRAX Cortex Analyzer

### Overview
[DECTRAX](https://dectrax.com) is an autonomous cyber deception, canary token provisioning, and line-rate firewall interdiction platform.

This analyzer queries DECTRAX honeypots, canary honeytokens, and active firewall External Dynamic List (EDL) feeds to evaluate observables within TheHive and Cortex SIRP.

### Supported Observables
- `ip`
- `domain`
- `fqdn`

### Taxonomy & Verdicts
The analyzer outputs normalized taxonomies and verdicts for investigated observables:
- **`DECTRAX:Interdiction="Blocked in Firewall EDL"`** (Level: `malicious`) — Indicator has engaged in active adversarial scanning or brute force and is dynamically quarantined on border firewalls.
- **`DECTRAX:Deception="{N} Decoy Interactions"`** (Level: `suspicious`) — Indicator probed decoy ports or canary services.
- **`DECTRAX:Status="Clean"`** (Level: `safe`) — Observable is not observed in any deception traps or quarantined lists.

### Configuration
- `url`: Base URL of the DECTRAX API service (default: `https://api.dectrax.com`).
- `key`: Optional Bearer token / API key.
- `cert_check`: Verify TLS/SSL certificates (`true` / `false`).
