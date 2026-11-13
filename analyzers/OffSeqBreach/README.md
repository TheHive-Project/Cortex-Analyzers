# OffSeq Breach Analyzer

Query [OffSeq Breach](https://breach.offseq.com) for leaked credentials found in breach datasets, forums and Telegram.

### Flavors

| Flavor | Data types | Returns |
|--------|------------|---------|
| `OffSeqBreach_Domain` | `domain`, `fqdn` | Counts of leaked employee, customer and third-party credentials, with password-strength breakdowns. |
| `OffSeqBreach_Email` | `mail` | Up to 100 leak records for the address: source, date added and whether a password was exposed. |

Passwords are never returned: records stay masked until unlocked in OffSeq Breach.

### Taxonomies

- `OffSeqBreach:Employees` – `malicious` when employee credentials leaked, otherwise `safe`.
- `OffSeqBreach:Customers`, `OffSeqBreach:ThirdParties` – `suspicious`, shown when non-zero.
- `OffSeqBreach:Leaks` – number of records for an email; `malicious` when non-zero.

### Requirements

API access needs the Basic plan or higher. Create a key under **Dashboard > API** at [breach.offseq.com](https://breach.offseq.com).

Each lookup spends one daily search of the plan; repeating the same lookup on the same day is free. Past the allowance the API answers 402, unless `confirm_credit` is enabled to spend pay-per-search credits.

### Configuration

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `key` | OffSeq Breach API key. | yes | |
| `base_url` | API base URL. | no | `https://breach.offseq.com/api/v1` |
| `confirm_credit` | Spend a pay-per-search credit once the daily allowance is used up. | no | `false` |
