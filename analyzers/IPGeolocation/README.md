### IPGeolocation.io

Enrich IP addresses, domains, autonomous systems and user agents with the
[IPGeolocation.io](https://ipgeolocation.io) v3 API.

An API key is required. [Sign up](https://app.ipgeolocation.io/signup) for a free key
(1,000 credits a day). The free plan covers IP location and user agent parsing; the other
lookups need a paid plan, and the API answers HTTP 401 when a plan does not include one.

#### Flavors

| Flavor | Observables | Returns | Plan | Credits |
| --- | --- | --- | --- | --- |
| `IPGeolocation_Location` | `ip`, `domain`, `fqdn` | country, region, city, coordinates, ASN, company, network, time zone and currency | free for IPs, paid for domains | 1 |
| `IPGeolocation_Security` | `ip` | threat score (0-100) and VPN, proxy, residential proxy, Tor, relay, bot, spam, known attacker, cloud provider and corporate gateway signals, with provider names, confidence and last seen dates | paid | 2 |
| `IPGeolocation_ASN` | `ip`, `autonomous-system` | AS number and name, organization, type, country, registry, allocation date and route counts | paid | 1 |
| `IPGeolocation_AbuseContact` | `ip` | abuse emails, phone numbers, organization, address and network of the IP address | paid | 1 |
| `IPGeolocation_UserAgent` | `user-agent` | client, version, device, engine and operating system, and whether it is a known attack tool | free | 1 |

Credits are only charged for successful lookups. Private and bogon addresses are refused by
the API without a charge.

#### Taxonomies

All tags use the `IPGeolocation` namespace.

- **Location**: `Country`, `ASN`, `Org`, and `IP` (the resolved address) for domains.
- **Security**: `ThreatScore`, plus one tag for each signal that is set: `Tor`, `VPN`, `Proxy`,
  `ResidentialProxy`, `Relay`, `KnownAttacker`, `Bot`, `KnownGoodBot`, `Spam`, `CloudProvider`
  and `CorporateGateway`. VPN, proxy and relay tags show the provider name when known.
- **ASN**: `ASN`, `Org`, `Type`.
- **AbuseContact**: `Email`, `Org`.
- **UserAgent**: `Type`, `Client`, `OS`, `Device`.

The `ThreatScore` tag carries the verdict:

| Threat score | Level |
| --- | --- |
| 0-20 | `info` |
| 21-50 | `suspicious` |
| 51-100 | `malicious` |

Both cut-offs can be changed with `suspicious_threshold` and `malicious_threshold`. A low score
is reported as `info`, never `safe`: finding no risk signals is not the same as an address
being safe, and a green tag in a triage queue reads as a clearance.

User agents that the API identifies as attack or scanning tools (type `Hacker`, for example
sqlmap, Nikto or the Nmap scripting engine) are tagged `suspicious`. User agents are easy to
spoof, so they are never tagged `malicious`. Every other tag is `info`.

#### Artifacts

When artifact extraction is enabled, the analyzer adds:

- the IP address a domain resolved to (`ip`), from the Location flavor;
- the autonomous system of an IP address (`autonomous-system`), from the Location and ASN
  flavors;
- the abuse contact emails (`mail`), from the AbuseContact flavor.

#### Configuration

| Item | Default | Purpose |
| --- | --- | --- |
| `api_key` | none | IPGeolocation.io API key (required) |
| `base_url` | `https://api.ipgeolocation.io` | API endpoint |
| `timeout` | `30` | HTTP timeout in seconds |
| `suspicious_threshold` | `21` | Security flavor only: threat score from which the result is `suspicious` |
| `malicious_threshold` | `51` | Security flavor only: threat score from which the result is `malicious`; set it above 100 to never tag `malicious` |

Every flavor refuses observables above TLP:AMBER and PAP:AMBER by default, because the
observable is sent to a third-party service. The analyzer uses the proxy configured in Cortex.

#### Notes

- International domain names are looked up in their punycode form.
- User agents longer than 8,000 characters or containing non-ASCII characters are sent in a
  request body instead of a header, which needs a paid plan.
- Requests that fail with HTTP 502, 503 or 504, or cannot connect, are retried twice. Requests
  that time out are not retried, because the API may already have answered and charged for them.
- The API key is sent as a query parameter, the only server-side method the API offers. It is
  removed from every error message.
