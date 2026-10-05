### isMalicious

[isMalicious](https://ismalicious.com) is a threat intelligence service that aggregates threat feeds,
blocklists and enrichment sources into a reputation verdict for IP addresses, domains and URLs.
This analyzer looks up `ip`, `domain` and `fqdn` observables with the `GET /check` endpoint of the
[isMalicious API](https://ismalicious.com/api-docs), at the `standard` enrichment level.

#### Requirements

You need an isMalicious account to use the analyzer; free accounts are available
([plans and quotas](https://ismalicious.com/pricing)).

- `api_key` (required): the **X-API-KEY value** shown under *API credentials* on your isMalicious
  account page, i.e. the Base64 encoding of `apiKey:apiSecret`. It is sent as
  `Authorization: Bearer <value>`.
- `api_url` (optional): defaults to `https://api.ismalicious.com`. Configurations that still use the
  former default, `https://ismalicious.com`, keep working.

#### Report

- **Status**: the `malicious` flag. `Clean` means the API did not flag the observable as malicious; it is
  not a safety verdict on its own, read it with the risk score.
- **Risk score**: 0-100 with the level computed by the API (`safe`, `low`, `medium`, `high`, `critical`,
  or `inconclusive` when there is too little evidence for a verdict).
- **Classification**, **categories** and **detection sources**: only threat listings are reported as
  detections.
- **Infrastructure**: what the observable is known as (for example `cloud`, `cdn`, `tor-exit`,
  `doh-resolver`), drawn from listings that describe it rather than accuse it. These listings are
  not counted as detection sources.
- **Reputation** counters, geolocation and network (ASN) information when available. Country and ASN are
  returned as `other` artifacts.

#### Taxonomies

| Predicate        | Value                                         | Level                                                              |
| ---------------- | --------------------------------------------- | ------------------------------------------------------------------ |
| `Status`         | `Malicious` / `Clean`                         | malicious / safe                                                   |
| `Risk Score`     | score and API level, e.g. `72 (high)`         | critical, high: malicious; medium: suspicious; low, safe: safe; inconclusive: info |
| `Category`       | primary classification                        | info                                                               |
| `Sources`        | number of threat listings                     | malicious when the status is malicious, info otherwise             |
| `Infrastructure` | infrastructure attributes, comma separated    | info                                                               |

#### Errors

A rejected key (HTTP 401), an exhausted rate limit or quota (HTTP 429) and a redirect from `api_url`
are reported as explicit analyzer errors. Redirects are not followed, so the key is only sent to the
configured `api_url`.
