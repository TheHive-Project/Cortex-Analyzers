### Darkmoon

[Darkmoon](https://github.com/ASCIT31/Dark-Moon) is an autonomous AI penetration testing platform: an LLM
orchestrates specialist agents and offensive tools, and each finding is backed by evidence from a real
exploit attempt. This analyzer looks up what Darkmoon has **already found** on a URL, domain, FQDN or IP
address, so an analyst triaging an alert on an asset can see its known, proven weaknesses (severity, CVSS,
CVE, MITRE ATT&CK technique, endpoint, remediation advice) next to the observable.

The analyzer is read-only. It never starts a scan and never sends evidence (requests, responses, logs).

#### Requirements

The Darkmoon **dashboard API** (`/api/v1`, port 8000 by default) is a **Darkmoon Pro** component. The open
source edition runs as a CLI with local JSON and Markdown output and has no REST API for this analyzer to
query.

Configuration items:

- `url`: base URL of the dashboard API, with or without the `/api/v1` suffix.
- `token`: an API bearer token. If it is empty, `username` and `password` are used to log in
  (`POST /api/v1/auth/login`).
- `verify_ssl`: verify the TLS certificate (default `true`).
- `min_severity`: lowest severity reported, `info` to `critical` (default `info`).
- `include_unconfirmed`: also report findings the agents could not confirm (default `true`).
- `max_findings`: maximum findings kept in the report, most severe first (default `100`).

#### How observables are matched

A finding matches an observable when the host of the finding `endpoint` equals the host of the observable,
or when it belongs to a campaign whose target host equals it. Ports and paths are ignored, so a `url`
observable returns the findings of its whole host.

#### Output

- Taxonomies: `Darkmoon:Findings`, `Darkmoon:Proven` (findings with status `exploited` or `confirmed`),
  `Darkmoon:Critical` and `Darkmoon:High`. The level is `malicious` when a critical or high finding exists,
  `suspicious` for medium, `info` otherwise.
- Full report: campaigns, counts by severity and the list of findings.

#### Known limitations

- No finding for a host only means Darkmoon has not tested it, or found nothing. It is not a clean verdict.
- Findings can include false positives and must be reviewed by a qualified human. Findings with status
  `unconfirmed` were not proven by the agents.
