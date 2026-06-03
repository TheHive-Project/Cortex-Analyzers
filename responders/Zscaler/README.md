# Zscaler ZIA Responders

Cortex responders to manage Zscaler Internet Access (ZIA) directly from TheHive observables. All responders run on `thehive:case_artifact` observables.

## Responders

### ATP Denylist (Policy > Security > Advanced Threat Protection > Blocked Malicious URLs)

| Responder | What it does |
|-----------|-------------|
| `ZscalerZIA_AddToATPDenylist` | Block a domain, FQDN, or URL |
| `ZscalerZIA_RemoveFromATPDenylist` | Unblock a domain, FQDN, or URL |
| `ZscalerZIA_AddToATPDenylistWildcard` | Block a domain and all its subdomains. When given a URL observable, the path is ignored and only the parent domain is blocked. |
| `ZscalerZIA_RemoveFromATPDenylistWildcard` | Unblock a domain and all its subdomains. When given a URL observable, the path is ignored and only the parent domain is removed. |

### ATP Security Exceptions (Policy > Security > Advanced Threat Protection > Security Exceptions)

| Responder | What it does |
|-----------|-------------|
| `ZscalerZIA_AddToATPSecurityExceptions` | Add a domain, FQDN, or URL to bypass ATP content scanning |
| `ZscalerZIA_RemoveFromATPSecurityExceptions` | Remove a domain, FQDN, or URL from ATP Security Exceptions |

### Custom URL Category (Policy > URL & Cloud App Control > Custom URL Categories)

| Responder | What it does |
|-----------|-------------|
| `ZscalerZIA_AddToURLCategory` | Add a domain, FQDN, URL, IP, or CIDR to a custom category |
| `ZscalerZIA_RemoveFromURLCategory` | Remove from a custom category |
| `ZscalerZIA_AddToURLCategoryWildcard` | Add a domain and all its subdomains to a custom category. When given a URL observable, the path is ignored and only the parent domain is added. |
| `ZscalerZIA_RemoveFromURLCategoryWildcard` | Remove a domain and all its subdomains from a custom category. When given a URL observable, the path is ignored and only the parent domain is removed. |

### Cloud Firewall (Policy > Cloud Firewall)

| Responder | What it does |
|-----------|-------------|
| `ZscalerZIA_AddToCloudFirewallRule` | Add an IP or CIDR to the destination address list of a pre-existing Cloud Firewall block rule (network-layer, all ports/protocols) |
| `ZscalerZIA_RemoveFromCloudFirewallRule` | Remove an IP or CIDR from the destination address list of a Cloud Firewall rule |

---

## Authentication

All responders support two authentication methods via `auth_type`.

### OneAPI OAuth2 (default, `auth_type=oneapi`)

For tenants migrated to ZIdentity. Go to ZIdentity Admin UI > Integrations > API Clients and create an OAuth2 client with the appropriate ZIA scopes.

| Parameter | Description |
|-----------|-------------|
| `zia_vanity_domain` | Your org's vanity domain — the prefix before `.zslogin.net` (for `acme.zslogin.net` use `acme`) |
| `zia_client_id` | OAuth Client ID |
| `zia_client_secret` | OAuth Client Secret |

### Legacy API (`auth_type=legacy`)

For tenants not yet on ZIdentity.

| Parameter | Description |
|-----------|-------------|
| `zia_username` | Admin email address |
| `zia_password` | Admin password |
| `zia_api_key` | API key (obfuscated) |
| `zia_cloud` | Cloud name: `zscaler`, `zscalerone`, `zscalertwo` |

---

## Configuration

In Cortex, go to **Organization > Responders**, find the Zscaler responder you want to enable, and click **Enable**. All parameters below are set through the Cortex UI. Credentials are shared across responders using the `ZscalerZIA` base configuration.

### All responders

| Parameter | Default | Description |
|-----------|---------|-------------|
| `dry_run` | `false` | Validate and read ZIA but make no changes |
| `activate_changes` | `true` | Push changes live immediately after modification |
| `allow_risky_iocs` | `false` | Allow bare TLDs (like `com`) and oversized CIDRs |
| `allow_wildcards` | `false` | Allow wildcard domains (like `*.example.com`) — not applicable to Wildcard variants |

Proxy settings are taken from the Cortex standard `proxy_http` / `proxy_https` configuration (set at the Cortex organization or instance level). `proxy_https` takes precedence since all Zscaler API calls are HTTPS.

---

## ZIA prerequisites

### URL Category responders

Create a custom URL category in ZIA (Policy > URL & Cloud App Control > Custom URL Categories) and make sure it is blocked in your URL Filtering policy. Note the category ID from the URL when editing it.

### Cloud Firewall responders

The responder expects an existing Cloud Firewall rule with a block action (`BLOCK_DROP`, `BLOCK_RESET`, or `BLOCK_ICMP`). It will not run against an ALLOW rule. Pre-create the rule in Policy > Cloud Firewall.

---

## Notes

- All operations are idempotent: adding something already present, or removing something not there, returns success with an `already-present` or `not-found` status rather than an error.
- Wildcard responders use the [Mozilla Public Suffix List](https://publicsuffix.org/) via `tldextract` to safely compute the registrable domain. For example, `api.app.evil.co.uk` becomes `.evil.co.uk`, not `.co.uk`.
- Changes are activated immediately by default (`activate_changes=true`). Set to `false` to batch-activate manually from the ZIA portal.

