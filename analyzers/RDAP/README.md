### RDAP

[RDAP](https://about.rdap.org/) (Registration Data Access Protocol) is the IETF
successor to WHOIS, standardised in RFC 7480 through RFC 7484. It returns registration
data as structured JSON over HTTPS instead of the unstructured text WHOIS returns over
port 43, and it is now the protocol registries are required to support.

The analyzer takes a domain or an IP address and returns its registration record:
registrar, registration and expiry events, registry status codes, and nameservers.
Nameservers are extracted as observables.

Queries go through https://rdap.org/, which resolves the authoritative RDAP server for
the object and redirects to it, so a single endpoint covers every TLD and regional
internet registry.

#### Requirements

None. RDAP is an open protocol and requires no account, key or subscription.

The only configuration item is an optional HTTP `timeout` in seconds, which defaults
to 15.
