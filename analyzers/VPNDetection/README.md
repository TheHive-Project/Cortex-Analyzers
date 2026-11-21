### VPNDetection

Check an IP address with [VPNDetection](https://vpndetection.io): whether it is a VPN, a privacy relay such as iCloud Private Relay, a Tor exit, a residential, datacenter, mobile or public proxy, a hosting or CDN address, or a known bot, with the provider behind each where one is known, a confidence and the date the address was last seen as such.

No API key is needed ([terms](https://vpndetection.io/terms#no-key)): without one the analyzer reports the VPN, relay, Tor and bot flags, the country, the ASN and the reverse DNS hostname. An API key, set as `key`, adds the proxy, hosting and CDN flags, the providers, the region and city, the organization the address is registered to and its abuse contact. It is sent in the `Authorization` header, never in the URL. Private and reserved addresses are not looked up.

The short report shows one taxonomy per detection, `suspicious` for a VPN, relay, Tor exit or proxy and `info` for hosting, CDN and bots, each valued with its provider, or `VPNDetection:Detection="None"` when nothing is detected. Without a key that reads `None (partial)`, since the keyed flags were not checked, and the raw report's `partial` is `true`.

The raw report is the API's JSON answer plus `partial`, e.g. for a Tor exit without a key:

```json
{
  "ip": "185.220.101.1",
  "is_bogon": false,
  "is_vpn": false,
  "is_relay": false,
  "is_tor": true,
  "is_bot": false,
  "is_anycast": false,
  "relay": {},
  "tor": {"provider": "", "provider_name": "", "confidence": "high", "last_seen": "2026-11-21"},
  "location": {"continent": "EU", "country": "DE", "country_name": "Germany", "timezone": "Europe/Berlin"},
  "asn": {"asn": 60729, "name": "Stiftung Erneuerbare Freiheit", "prefix": "185.220.101.0/24", "country": "DE"},
  "hostname": "berlin01.tor-exit.artikel10.org",
  "partial": true
}
```

API reference: [vpndetection.io/api](https://vpndetection.io/api). Privacy: [vpndetection.io/privacy](https://vpndetection.io/privacy).
