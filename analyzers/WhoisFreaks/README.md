### WhoisFreaks

[WhoisFreaks](https://whoisfreaks.com) provides live and historical WHOIS, DNS, SSL, subdomain,
IP and ASN data, plus domain and IP reputation. This analyzer brings those lookups into Cortex and
TheHive, so an analyst can enrich an observable with one click instead of copying it into a web
tool: who registered a domain and when, where it points, what else shares its name servers, mail
server or IP, whether look-alike domains exist, and how risky an IP or domain is.

#### How it works

```
TheHive  ── "Run analyzers" on an observable ──►  Cortex  ── starts one Docker container per job ──►
WhoisFreaks analyzer  ── HTTPS, API key in the X-API-KEY header ──►  api.whoisfreaks.com
```

- The analyzer is one Python program offered as **25 flavors**, one per lookup. Each flavor is a
  separate entry in Cortex and TheHive, with its own data types and credit cost, so analysts only
  see the lookups that fit the observable.
- Each run sends WhoisFreaks only the observable's value (or the entries of a bulk file) and the
  API key. Nothing else from the case leaves the platform.
- The result appears in TheHive as coloured summary tags on the observable, a full report rendered
  by the WhoisFreaks report templates, and suggested new observables (name servers, IPs, domains…)
  the analyst can import.
- Every run consumes WhoisFreaks API credits, as listed below. Cortex's job cache reuses a recent
  report for the same lookup without spending credits.

#### Flavors

Twenty flavors work on a single observable:

| Flavor | Data types | What it returns | Credits |
|---|---|---|---|
| `WhoisFreaks_Whois` | domain, fqdn | Live WHOIS: registrar, contacts, dates, name servers, raw record | 1 |
| `WhoisFreaks_WhoisHistory` | domain | Every historical WHOIS snapshot WhoisFreaks holds | 2 |
| `WhoisFreaks_ReverseWhois` | mail, other | Domains whose WHOIS matches an email, keyword, owner or company | 5 per page |
| `WhoisFreaks_DNS` | domain, fqdn, ip | Current DNS records of a domain, or the PTR record of an IP | 1 |
| `WhoisFreaks_DNSHistory` | domain, fqdn | DNS records seen for a domain over time | 2 per page |
| `WhoisFreaks_ReverseDNS` | ip, other (CIDR) | Domains whose A/AAAA record points to the IP, or into the CIDR range | 5 per page |
| `WhoisFreaks_ReverseNS` | fqdn | Domains whose NS record names this name server | 5 per page |
| `WhoisFreaks_ReverseMX` | fqdn | Domains whose MX record points to this mail server | 5 per page |
| `WhoisFreaks_ReverseCNAME` | fqdn | Domains whose CNAME record points to this host | 5 per page |
| `WhoisFreaks_ReverseTXT` | other | Domains with a TXT record holding this text (verification token, SPF include); `*` is a wildcard | 5 per page |
| `WhoisFreaks_DomainReputation` | domain, fqdn | Verdict, threat types, DGA score, trust signals, email security, related IOCs | 5 |
| `WhoisFreaks_DomainAvailability` | domain | Whether the domain can be registered, optionally with suggested alternatives | 1, plus 1 per 5 suggestions |
| `WhoisFreaks_TLDAvailability` | domain, other | Whether a name is available across a list of TLDs (brand protection) | 1 per TLD |
| `WhoisFreaks_SSL` | domain, fqdn | Certificate served by the domain: issuer, validity, alternative names | 1; with `ssl_chain`, plus 1 per 2 certificates |
| `WhoisFreaks_Subdomains` | domain | Known subdomains with first and last seen dates | 2 per page |
| `WhoisFreaks_Typosquatting` | domain, other | Registered look-alike domains of a brand keyword or wildcard pattern | 5 per page |
| `WhoisFreaks_IPWhois` | ip | RIR registration: network, organisation, abuse contacts | 1 |
| `WhoisFreaks_IPReputation` | ip | Threat score and Tor, VPN, proxy, bot, spam, known-attacker signals | 1 |
| `WhoisFreaks_IPGeolocation` | ip | Location, network and ASN | 1 |
| `WhoisFreaks_ASNWhois` | autonomous-system | AS registration: organisation, country, routes, peers | 1 |

Five work on a `file` observable: a text file listing domains and/or IP addresses, such as an
IOC list attached to a case. They use the WhoisFreaks bulk APIs, 100 entries per request:

| Flavor | Entries looked up | What it returns per entry | Credits |
|---|---|---|---|
| `WhoisFreaks_BulkWhois` | domains | Registration status, dates, registrar | 1 per domain |
| `WhoisFreaks_BulkDNS` | domains and IPs | Current DNS records (PTR for IPs) | 1 per entry |
| `WhoisFreaks_BulkDomainAvailability` | domains | Available, registered or unknown | 1 per domain |
| `WhoisFreaks_BulkIPGeolocation` | public IPs | Location, network, ASN, organisation | 1 per IP |
| `WhoisFreaks_BulkIPReputation` | public IPs | Threat score and Tor, proxy, anonymous, bot, spam, known-attacker signals | 1 per IP |

#### Requirements

- A WhoisFreaks account and API key. Sign up at [whoisfreaks.com](https://whoisfreaks.com) (new
  accounts get free credits); the API key is shown in the account dashboard. The plan must include
  the APIs of the flavors you enable and enough credits for the expected volume.
- Outbound HTTPS from the analyzer containers to `api.whoisfreaks.com`. An HTTP proxy configured
  in Cortex for the analyzer is used.

#### Compatibility

- Tested with Cortex 4.2.0 (Docker job runner, Elasticsearch 8.19) and TheHive 6.0.0, with
  cortexutils 2.2.1 on the Python 3 image the Cortex-Analyzers build produces.
- The analyzer only relies on the standard cortexutils job contract, so Cortex 3.1 is expected to
  work the same way; it has not been tested.
- The flavor settings Cortex adds to every analyzer are honoured: **CA Certs** (for a TLS
  inspecting proxy), **HTTP Proxy** / **HTTPS Proxy**, **Job timeout** and **Job cache**.

#### Setup

1. In Cortex, as an organisation administrator, open **Organization > Analyzers** and refresh the
   list. The `WhoisFreaks_*` flavors appear. Before they are in the published catalog, install them
   as private analyzers: see
   [How to manage private custom analyzers](../../docs/admin_guides/manage-private-custom-analyzers-responders.md).
2. In the analyzer configuration of the organisation, open the **WhoisFreaks** base configuration,
   enter the API key in `key`, and adjust the optional settings below. All flavors share it.
3. Enable the flavors you want. In each flavor's dialog, keep TLP and PAP checks on, and set a job
   cache (for example 10 minutes) and a rate limit that match your WhoisFreaks plan. Turn on
   **Extract observables** if analysts should be able to import the suggested observables.
4. In TheHive, import the report templates (**Entities management > Analyzer templates**), so the
   full reports are rendered instead of shown as raw JSON.

**Check the key and the remaining credits** without spending any: the usage endpoint is free.
Its answer echoes the key in `apiKey`, so drop that field:

```bash
curl -s -H "X-API-KEY: $WHOISFREAKS_KEY" https://api.whoisfreaks.com/v1.0/whoisapi/usage | jq 'del(.apiKey)'
```

A `401` means the key is wrong or inactive. `apiCredits` and `apiSubscription` show the balance.

#### Configuration

All items belong to the `WhoisFreaks` base configuration. Each flavor shows only the items that
apply to it.

| Item | Flavors | Default | Values and effect |
|---|---|---|---|
| `key` | all | — (required) | The WhoisFreaks API key. |
| `max_pages` | ReverseWhois, DNSHistory, ReverseDNS, ReverseNS, ReverseMX, ReverseCNAME, ReverseTXT, Subdomains, Typosquatting | `1` | Result pages fetched per run, 1 to 20. Every page is billed; the report shows how many results and pages exist. |
| `max_items` | the 5 Bulk flavors | `100` | Entries of a file looked up per run, 1 to 1000. Each costs 1 credit; the rest are listed as skipped. |
| `reverse_whois_search_type` | ReverseWhois | `keyword` | What an `other` observable is matched against: `keyword`, `owner`, `company` or `email`. A `mail` observable always searches the email. |
| `reverse_whois_exact` | ReverseWhois | `false` | `true` for exact matches only. |
| `reverse_whois_mode` | ReverseWhois | `default` | `default`: 50 full WHOIS records per page. `mini`: 100 compact records (domain, dates, name, email, company). |
| `dns_record_types` | DNS, DNSHistory, BulkDNS | `all` | `all`, or a comma-separated list of `A`, `AAAA`, `CNAME`, `MX`, `NS`, `SOA`, `SPF`, `TXT`. IP lookups always return the PTR record; BulkDNS adds `PTR` when the file holds IPs. |
| `dns_cname_depth` | DNS, BulkDNS | empty (API default) | CNAME hops to follow before collecting records, 0 to 4. |
| `dns_relative_records` | DNS | `true` | Also return the records of CNAME targets. |
| `reverse_dns_sort` | ReverseDNS, ReverseNS, ReverseMX, ReverseCNAME, ReverseTXT | `none` | Order results by the date the record was last seen: `asc` or `desc`. |
| `availability_suggestions` | DomainAvailability | `0` | Also return this many suggested alternative domains, 1 to 100 (`0` = off). Every 5 suggestions cost 1 credit. |
| `availability_tlds` | TLDAvailability | `com,net,org,info,biz,io,co,xyz` | TLDs to check the name against, up to 100. Each TLD costs 1 credit. |
| `ssl_chain` | SSL | `false` | Also return the intermediate and root certificates (1 more credit per 2 certificates). The summary still describes the site's own certificate. |
| `subdomains_status` | Subdomains | `all` | `all`, `active` or `inactive`. |
| `typosquatting_page_size` | Typosquatting | `100` | Look-alike domains per page, 1 to 100. Every page is billed. |
| `ip_malicious_score` | IPReputation, BulkIPReputation | `75` | Threat score from which an IP is tagged `malicious`, 1 to 100. |
| `ip_suspicious_score` | IPReputation, BulkIPReputation | `40` | Threat score from which an IP is tagged `suspicious`, 1 to 100, at most `ip_malicious_score`. |

Invalid values, including a `max_pages` or `max_items` outside its range, stop the job with a
message naming the item, before any request is made.

#### Per-run parameters

A job started through the Cortex API (`POST /api/analyzer/<id>/run`, for example from a playbook
or script) can set any item above for that run only, in its `parameters` object, using the same
name. Example: `"parameters": {"subdomains_status": "active", "subdomains_after": "2025-01-01"}`.

- A per-run value overrides the configuration, except `max_pages` and `max_items`: a run can lower
  them but never raise them (a higher value is reduced to the configured one), so the configured
  values remain the credit limit. `key` and the flavor's service can't be changed per run.
- `subdomains_after` and `subdomains_before` (`YYYY-MM-DD`) exist only as parameters. They limit
  Subdomains to subdomains seen in that window.
- TheHive's **Run analyzers** action sends no parameters, so analysts always get the configured
  values.

#### Observables

- `domain` and `fqdn` observables must be host names. International names are sent in their
  ASCII (punycode) form (`bücher.de` → `xn--bcher-kva.de`); malformed values are rejected before
  any request.
- `ip` observables must be public addresses. Private, loopback, link-local, CGNAT, multicast and
  other reserved addresses are rejected before any request, so they are never sent to WhoisFreaks.
  An IPv4-mapped IPv6 address (`::ffff:8.8.8.8`) is looked up as the IPv4 address.
- ReverseDNS also takes a public CIDR range as an `other` observable (`8.8.8.0/24`): it finds the
  domains with an A (or, for IPv6, AAAA) record in that range.
- `autonomous-system` observables can be written `AS15169`, `as15169` or `15169`.
- ReverseNS, ReverseMX and ReverseCNAME take the host name the records point to, as an `fqdn`
  observable, for example `ns1.example.net`. They are not offered on `domain` observables, so a
  bulk "run all" on a domain doesn't spend credits on lookups that can't match. ReverseTXT takes
  the TXT text; a `*` in it makes it a wildcard pattern.
- TLDAvailability checks the first label of a `domain` observable (`paypal.com` → `paypal`), or an
  `other` observable holding one label.
- Typosquatting uses the first label of a `domain` observable as the keyword (`paypal.com` →
  `paypal`). An `other` observable is used as the keyword, or as a pattern when it contains `*`
  (up to three wildcards, for example `*paypal*`).
- Bulk `file` observables are read as text of up to 1 MB: UTF-8, with or without a byte order
  mark, or UTF-16 with a byte order mark (what Windows Notepad calls "Unicode"). Entries are
  separated by new lines, spaces, commas, semicolons or `|`; text after `#` on a line is ignored.
  Defanged entries (`example[.]com`) and URLs (their host is used, `[IPv6]` hosts included) are
  accepted, and a repeated entry is handled once, whether it is looked up or skipped.
  Email addresses, private or reserved IPs, malformed values and entries of the wrong kind are
  skipped and listed in the report with the reason.

#### Results

The summary tags use the `WhoisFreaks` namespace. Their levels:

| Flavor | Tag level |
|---|---|
| Whois, BulkWhois | `suspicious` for a domain created less than 30 days ago (`Created`, `NewDomains`) |
| DomainReputation | the WhoisFreaks verdict: `safe`, `suspicious` or `malicious` |
| IPReputation, BulkIPReputation | `malicious` for a threat score of at least `ip_malicious_score` (75) or a known attacker; `suspicious` for a score of at least `ip_suspicious_score` (40) or a Tor, VPN, proxy, residential-proxy, bot or spam flag; `safe` for a lower score; `info` (`ThreatScore=unknown`, bulk `Unknown`) when WhoisFreaks returned neither a score nor a flag |
| SSL | `suspicious` when the certificate has expired |
| all others | `info` counts or values |

- The IP thresholds are this analyzer's defaults, not WhoisFreaks': the API documents the score
  as 0 to 100, higher meaning riskier. Tune them to your environment.
- A declared good bot (search-engine crawler, monitor) is not counted as a bot, and a privacy
  relay (such as iCloud Private Relay) carries ordinary users' traffic: both are reported as an
  `info` `Context` tag instead of raising the level.
- When WhoisFreaks holds no record for the observable, the job succeeds with
  `WhoisFreaks:Result="not found"` instead of failing.
- `Partial` means WhoisFreaks returned an incomplete record (HTTP 206); `Cached` means it returned
  a stored record because the live WHOIS server did not answer (HTTP 210).
- `Incomplete` means a later page or bulk batch failed, for example when credits ran out or the
  job's time limit came near; the results already received are kept and the report says where it
  stopped.
- Bulk flavors also report `Skipped` (entries not looked up), `Failed` (entries the API answered
  with an error) and `Missing` (entries the API left out of its answer).

Artifacts (suggested observables) are extracted when artifact extraction is enabled: name servers
and contact emails (WHOIS), domains (reverse WHOIS, reverse DNS flavors, typosquatting, registered
TLD variants), IPs and host names (DNS), subdomains, certificate alternative names, abuse contacts
(IP WHOIS) and AS numbers (IP reputation and geolocation). Bulk flavors return each entry that was
looked up, so the analyst can import the list; bulk IP reputation also tags each IP with its level.
A job suggests at most 1,000 observables; the `Observables` tag and the report say when more were
found.

#### Retries, billing and time limits

- A lookup (`GET`) that fails with a network error, `408`, `429` or a `5xx` is retried up to 3
  times, after 1, 2 and 4 seconds, or after the time the API asks for (`Retry-After`, or
  WhoisFreaks' `X-RateLimit-Remaining-Time`, at most 60 seconds).
- A lookup gets up to 3 minutes to answer: reverse lookups with millions of results can be that
  slow. One left unanswered is resent once; resending a slow query more often only adds load.
- A bulk request (`POST`) is only resent when it was rate-limited (`429`) or never reached the
  server. WhoisFreaks may already have processed and billed a bulk request that timed out or
  failed with `5xx`, so the analyzer reports it instead of paying twice.
- Redirects are never followed: the WhoisFreaks API doesn't redirect, and following one would send
  the API key to another host.
- The analyzer reads the flavor's Cortex job timeout and sends no request in the last minute (or
  last tenth, for timeouts under 10 minutes), so it can always write its report: results already
  received are returned with `Incomplete` instead of being lost when Cortex stops the job.

#### Data handling

- The API key is sent in the `X-API-KEY` header, never in a URL, and is removed from any API
  response and error message before the report is stored. Failed jobs show it as `REMOVED`.
- Only the observable value (or the bulk file's entries) is sent to WhoisFreaks. Private and
  reserved IPs are never sent. `other` observables (ReverseWhois, ReverseTXT, TLDAvailability,
  Typosquatting, ReverseDNS) are sent as typed, so don't run these flavors on free-text notes.
- All flavors check TLP and PAP (maximum AMBER by default), so TLP:RED or PAP:RED observables are
  refused. The DomainReputation and SSL flavors make WhoisFreaks contact the target (to fetch the
  website or its certificate); lower their PAP limit if that is not acceptable for your
  observables.

#### Common errors

| Message | Meaning |
|---|---|
| `WhoisFreaks rejected the API key (HTTP 401)` | The `key` is wrong or disabled. |
| `WhoisFreaks plan or credit problem` / `plan or quota limit reached` | The plan doesn't include this API, or the credits ran out. |
| `Domain extension not supported or inactive at WhoisFreaks (HTTP 403)` | WhoisFreaks has no live WHOIS for that TLD; try WhoisHistory. |
| `WhoisFreaks refused this lookup (HTTP 403)` | WhoisFreaks declined the request; its message says why. |
| `WhoisFreaks does not look up private, reserved or bogon IP addresses (HTTP 423)` | The address is not publicly routable. |
| `WhoisFreaks rate limit exceeded` | Too many requests even after the automatic retries; lower the Cortex rate limit. |
| `Unable to reach the WhoisFreaks API: <error>` | No network path to `api.whoisfreaks.com` (firewall, DNS, proxy) after retries. |
| `The WhoisFreaks API did not answer within 180 seconds (2 attempts) …` | The lookup is very large or WhoisFreaks is busy; try again later. |
| `No answer from the WhoisFreaks API (…); the request was not resent …` | A bulk request timed out or failed after it was sent. Check the credits used before running it again. |
| `Unexpected redirect from the WhoisFreaks API` | Something between Cortex and WhoisFreaks (proxy, DNS) answered for the API; check the network path. |
| `The job's time limit is reached …` | Raise the flavor's job timeout in Cortex, or lower `max_pages` / `max_items`. |
| `Unexpected WhoisFreaks response (…)` | The API answered in a form the analyzer doesn't know; report it with the job ID. |
| `… is not a public IP address; it is not sent to WhoisFreaks` | The observable is a private or reserved IP. |
| `The file holds no … to look up` | The file has no usable entries: check it is text (UTF-8, or UTF-16 with a byte order mark) and lists entries of the flavor's kind. |
| `<item> must be …` | A configuration item or parameter has an invalid value. |

#### Tests

The `tests` folder holds unit tests that run every flavor and the failure cases against a fake
HTTP session, with no network access:

```bash
cd analyzers/WhoisFreaks && pip install -r requirements.txt && python -m unittest discover -s tests -v
```
