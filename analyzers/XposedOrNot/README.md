# XposedOrNot Analyzer

Check a `mail` observable against the [XposedOrNot](https://xposedornot.com) data-breach
database. XposedOrNot is a free, open data-breach search service; its community API needs
**no API key** and no registration.

## Flavors

### XposedOrNot_CheckEmail

Fast lookup returning the list of breaches the email address appears in, with a
`XON:Breaches=<count>` taxonomy (`safe` at 0, `suspicious` at 1+).

### XposedOrNot_BreachAnalytics

Detailed report: per-breach date, records exposed, affected domain, exposed data classes
and password-storage risk, plus first/latest exposure year, total records and an overall
risk score. Adds `XON:Risk=<label>` and, when any breach stored passwords in plaintext, a
`malicious`-level `XON:PlaintextPwd=yes` taxonomy. Breached-site domains are extracted as
`domain` artifacts.

## Configuration

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `key` | Optional XposedOrNot API key from [console.xposedornot.com](https://console.xposedornot.com). Switches both flavors to the commercial Plus API with higher rate limits and detailed responses. | no | |

The analyzer is fully functional without any configuration.

## Rate limits

The keyless community API allows 2 requests/second, 25/hour and 100/day per IP. When the
limit is hit the analyzer returns a clear error suggesting the optional key. The
commercial key raises these limits.

## Data sent to a third party

Only the observable's email address is sent, over TLS, to xposedornot.com — nothing else
leaves your instance. Breach exposure tied to an email address is personal information;
both flavors are TLP- and PAP-gated (`max_tlp: 2`, `max_pap: 2` by default) accordingly.
See the [XposedOrNot privacy policy](https://xposedornot.com/privacy).
