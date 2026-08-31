### ThreatFox

[ThreatFox](https://threatfox.abuse.ch/) is a free platform from abuse.ch for sharing indicators
of compromise (IOCs) associated with malware. This analyzer looks up IPs, domains, URLs and
hashes against the ThreatFox database.

#### Requirements

You need an Auth-Key to use the ThreatFox API. It is free and shared across all abuse.ch
services (URLhaus, MalwareBazaar, ThreatFox, ...) — get one at https://auth.abuse.ch/.

Set it as the `key` configuration item.

#### Known limitations

- `search_ioc` (ip/domain/url/fqdn) is reliable, but the search index lags ingestion by a few
  minutes, sometimes longer for large reporting batches.
- ThreatFox tracks network/C2 IOCs. Hashes only appear when attached to an IOC as a malware
  sample, so `hash` coverage is thin (use MalwareBazaar for hashes).
- Since May 2025 the API drops IOCs older than 6 months (still visible in the web UI).

A "not found" from this analyzer, especially for a hash, is not a clean verdict.
