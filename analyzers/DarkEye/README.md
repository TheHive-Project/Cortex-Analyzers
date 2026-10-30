# DarkEye

Look up a domain in [DarkEye](https://darkeye.io). One analyzer covers both DarkEye products:

- [HaveIBeenRansom](https://haveibeenransom.com): ransomware leaks and data breaches that
  involve a domain.
- [Breach House](https://breach.house): ransomware victims, data breaches, leads and stealer
  logs.

**An API key is required for at least one product.** Both APIs are paid. Set
`haveibeenransom_api_key`, `breachhouse_api_key`, or both. With one key the analyzer queries that
product only; with neither, the job fails.

## What it returns

| Observable | Result |
| --- | --- |
| `domain`, `fqdn` | the records DarkEye lists for the domain |

Every record carries the product it came from (`HaveIBeenRansom` or `Breach House`) and a
category (`ransomware`, `breach`, `leads` or `stealer`), plus an id, a title, the website, the group,
the country and the date it was discovered. The report also has the record counts per product and
per category.

Only this listing metadata is kept. Leaked content, proof files, leak-site links and download
links are never read from the API responses.

Email addresses are not supported: the Breach House search is free text, so an email lookup would
return records that merely mention the address.

## Partial failures

If one product fails (a wrong key, a quota limit, a timeout), the records from the other product are
kept and the failure is listed in the `errors` field of the report. The job fails only when every
configured product failed, so a report with no records and no errors means DarkEye was asked and
had nothing.

## Taxonomy

`DarkEye:Records=<n>` is `info` when there is no record and `suspicious` when there is at least
one. It is never `malicious`: a record usually means the organisation was a victim, not that the
domain is hostile. It is never `safe` either: no record only means nothing was found. A trailing `+`
(`DarkEye:Records=100+`) means the list was cut short by one of the limits below. `DarkEye:Errors=<n>`
appears when a product failed.

## Quota

Each HaveIBeenRansom page is one call against the key's daily quota, and Breach House takes one call
per lookup. With the defaults a lookup costs at most 5 + 1 calls, and fewer when `max_records` is
reached sooner.

## Configuration

| Item | Default | Purpose |
| --- | --- | --- |
| `haveibeenransom_api_key` | none | HaveIBeenRansom API key |
| `breachhouse_api_key` | none | Breach House API key |
| `max_pages` | `5` | HaveIBeenRansom pages to read, about 20 records each |
| `limit` | `25` | Breach House records per source, 200 at most |
| `max_records` | `100` | records kept per product; bounds the size of the report |
| `timeout` | `30` | HTTP timeout in seconds |
