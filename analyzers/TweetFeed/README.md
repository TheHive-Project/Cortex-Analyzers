### TweetFeed

[TweetFeed](https://tweetfeed.live) is a free feed of indicators of compromise (IOCs). Security
researchers post these IOCs on X (Twitter). TweetFeed collects the posts and publishes the IOCs
with their tags, the reporting user and a link to the post. This analyzer looks up IPs, domains,
URLs and hashes (MD5, SHA256) with the TweetFeed `/v1/ioc` API endpoint.

#### Requirements

None. The API is free and needs no key. The analyzer has no configuration item.

#### Verdict

TweetFeed IOCs are community reports. TweetFeed does not vet them. For this reason the analyzer
never reports `malicious`.

| Result | Taxonomy | Level |
|--------|----------|-------|
| IOC found (live 365 day window or archive) | `TweetFeed:Reports="<count>"` | `suspicious` |
| IOC found, with tags | `TweetFeed:Tags="<top 3 tags>"` | `info` |
| IOC not found | `TweetFeed:Reports="0"` | `info` |

`Reports` is the number of times researchers reported the IOC. A report of the same IOC under
two types (for example a domain and the URL of its home page) counts once.

The long report also shows the AI summary of the post (TweetFeed adds it with a language model,
so treat it as untrusted text), the campaign the IOC belongs to, other feeds that list the same
IOC (URLhaus, ThreatFox, MalwareBazaar, USOM, IPsum) and registration or network data.
Related IOCs from the same post (up to 50) are available as artifacts.

#### Rate limit and cache

The analyzer sends one request for each observable. It never retries. The TweetFeed API
limits the requests for each IP address. On HTTP 429 the job fails with the `Retry-After`
value in the error message.

To keep the load low on a free service:

- Use the Cortex job cache. Cortex reuses the report of a finished job for the same analyzer
  and observable during the cache period (the Cortex default is 10 minutes, and you can set
  it for each analyzer in the Cortex UI). Raise it if your analysts run the same observables
  often.
- Use the Cortex rate limit setting for the analyzer, if your Cortex version has it.
- Do not run the analyzer on bulk observable lists. Download the free bulk exports instead
  (<https://tweetfeed.live/api/>).

The analyzer sends only the observable to `api.tweetfeed.live`. It never connects to the
observable itself.

#### Known limitations

- The lookup covers the last 365 days and, for older IOCs, an archive. IOCs older than one year
  appear only in the `archive` part of the report.
- TweetFeed indexes MD5 and SHA256 hashes. A SHA1 hash returns an error.
- "Not found" is not a clean verdict. It means that no researcher reported the IOC on X, or that
  TweetFeed does not follow the account that did.
- New reports can take some minutes to appear. The API caches a negative answer for up to
  60 seconds and a positive answer for up to 15 minutes.
