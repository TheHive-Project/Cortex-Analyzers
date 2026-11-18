# HashScanner_NSRL

Cortex analyzer that looks up a **hash** observable in the **NIST NSRL** via the
[HashScanner](https://www.hashscanner.com) API. It tells you whether the file is
**known** (cataloged in NSRL) so you can filter the known out of a case and focus on
the unknown.

> A match means the file is *known* — **not** that it is safe, clean, or malicious.
> NIST does not label files good or bad.

- **Data type:** `hash` (MD5 / SHA-1 / SHA-256)
- **Requires:** a HashScanner API key — free at <https://www.hashscanner.com/register>

## Configuration

| Item | Required | Default | Description |
|------|----------|---------|-------------|
| `api_key` | yes | — | Your key, `hs_..._sk_...` |
| `api_url` | no | `https://api.hashscanner.com/v1` | API base URL |
| `timeout` | no | `30` | Request timeout (seconds) |

## Output

`short` report — a single taxonomy badge: `HashScanner:NSRL=Known` or `=Unknown`.

`long` report — the file metadata when known (name, size, product, OS, source).
