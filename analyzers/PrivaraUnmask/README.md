### Privara Unmask

[Privara Unmask](https://tajapps.com/unmask/) is the Android malware sandbox that recovers the C2. Pay
only for results. It extracts the command-and-control (C2) servers of Android malware, including
servers hidden behind packers, dead-drop resolvers and encrypted strings. Every candidate is checked
by a verifier and probed for liveness.

This analyzer has one flavor:

- **PrivaraUnmask_Analyze**: submit a file observable (APK, XAPK, APKM or .apks) and report the
  outcome, the malware family and the C2 servers.

#### Cost

Unmask is billed per result from a prepaid wallet on tajapps.com: **$25** when a live C2 is
found, **$9** for a C2 that did not answer, **free** when nothing is found or when the analysis
fails on the Privara side. The same file within 30 days returns the earlier charged (live or
dead) result for free; after a `none` or `void` result it is analysed again (free unless a C2 is
found; each `none` counts towards the monthly fair use of 30). Refused files cost nothing. A
trial covers samples until the first C2 result (at most 10).

Before uploading, the analyzer looks the file's SHA-256 up (`GET /jobs?sha256=`, free): a charged
result from the last 30 days is reused as it is and a running job is waited for, so running the
analyzer again never charges twice. Uploads carry the `Idempotency-Key` `cortex-<sha256>` (after
an earlier `none` / `void` / failed job, with a suffix derived from that job, so the file really
runs again). Job ids are opaque and used exactly as the API returns them. Do not add this
analyzer to automatic analysis rules unless you want every Android file analysed.

#### Requirements

Sign up at [tajapps.com/unmask](https://tajapps.com/unmask/) ("Try free"), top up the wallet and
create an API key on the [API keys page](https://app.tajapps.com/dashboard/unmask/api)
(Dashboard > Unmask API) with the `submit` and `read` scopes.

| Setting | Required | Default | Description |
|---|---|---|---|
| `api_key` | yes | | Unmask API key (`pvu_...`). Cortex hides it in error output. |
| `api_url` | no | `https://app.tajapps.com/api/unmask/v1` | HTTPS only. |
| `max_wait` | no | `1500` | Seconds to wait for the result. Keep it **below the Cortex job timeout** (raise the analyzer's job timeout to 30 min or more). |
| `poll_interval` | no | `30` | Delay between status checks when the API sends no `Retry-After` (grows to 120 s, never below 15 s). |
| `max_file_size_mb` | no | API limit | Optional lower cap; by default the API's own limit (`GET /balance`) is used. |

The analyzer checks locally that the file is an Android package before uploading it: other
files are never sent to Privara.

#### Report

- **Short report (taxonomies)**: `PrivaraUnmask:Outcome` (`live` red, `dead` orange, `none` /
  `void` blue), `PrivaraUnmask:C2` (number of C2 servers) and `PrivaraUnmask:Family` when known.
  Without an outcome the summary is `PrivaraUnmask:Status`: `running` (still running after
  `max_wait`; run the analyzer again later), `failed` or `canceled` (never charged).
- **Long report**: outcome, charge, family, package, SHA-256, Android versions, the C2 table
  (**defanged**) with each C2's liveness check (did it answer, and why: the API's `liveness`
  explanation, including the AI review's sentence when it lowered a result) and whether abuse.ch
  already lists it (information only, never changes the charge), the number of candidates
  rejected by the verifier, and a link to the job on your tajapps.com dashboard (`web_url`,
  after sign-in).
- **Artifacts**: each C2 as an observable with its **raw** value, from the API's `kind`, `host`
  and `port` fields: `url`, `ip` or `domain` (a `host_port` C2 gives the host, with a `port:<n>`
  tag), tagged `privara-unmask`, `c2` and
  `c2-live` / `c2-dead`. Rejected candidates are never returned.

#### Errors

The analyzer fails with a clear message, and nothing is charged, when the wallet is too low
(HTTP 402, with the top-up link), the monthly fair-use limit is reached (HTTP 403
`fair_use_reached`), the API is still rate limiting after the analyzer's own retries (HTTP 429,
which honour `Retry-After`), Privara refuses the file (with the reason: `not_apk`, `bad_archive`,
`manifest_unreadable`, `too_large`, `zip_bomb`, `unsafe_entry`, `known_clean`,
`duplicate_in_batch`), the file is not an Android package or too large, the key is invalid or
revoked (401 `invalid_key`), lacks a scope (403 `missing_scope`), or the account has no Unmask
API plan (404 on upload). An upload answered 409 `idempotency_in_progress` is retried after its
`Retry-After` with the same key. Files above the analyzer's `max_tlp` / `max_pap` are refused by
Cortex before anything is sent.
