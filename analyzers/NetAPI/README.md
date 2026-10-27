# NetAPI

Check a domain or URL against the [NetAPI](https://netapi.com/) compromised feed and get the
domain's position in the NetAPI Top 1M. The analyzer covers domain names only, not IP addresses.

**No API key is required.** Both lookups are free; an API token of a free NetAPI account only raises
the rate limits.

## What it returns

| Observable | Result |
| --- | --- |
| `domain`, `fqdn` | whether the host, or the registered domain it belongs to, is in the compromised feed now (seen in the last 24 hours) or was in the past, with first and last seen, the feed that reported it and the registrar; plus the domain's rank in the NetAPI Top 1M and within its TLD |
| `url` | the same for the URL's host name (a URL whose host is an IP address is not supported) |

The compromised feed collects hosts that public threat feeds report for malware or phishing
(CERT Polska, blackbook and others) and keeps their history, so a host that left the
blocklists months ago still shows when it was listed. The Top 1M rank helps to read a listing: a
popular domain in the feed is more likely a compromised legitimate site than attacker infrastructure.

## Taxonomies

| Taxonomy | Level |
| --- | --- |
| `NetAPI:Compromised="listed now"` | `malicious` |
| `NetAPI:Compromised="listed until YYYY-MM-DD"` | `info`: a past listing, usually an old incident on a host that was cleaned up since |
| `NetAPI:Compromised="not listed"` | `info`, never `safe`: absence from the feed is not a clearance |
| `NetAPI:Top1M="#N"` or `"not ranked"` | `info`, domains only |

When the listing belongs to the registered domain rather than the exact host, the value says so,
e.g. `listed now via example.com`.

## Configuration

| Item | Default | Purpose |
| --- | --- | --- |
| `timeout` | `30` | HTTP timeout in seconds |
| `key` | none | optional NetAPI API token; without one the limit is 30 lookups a minute and 1,000 a day per IP |

The feed data is published under CC BY 4.0.
