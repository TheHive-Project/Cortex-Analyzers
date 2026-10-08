# Macadress

Enriches a MAC address observable with data from
[macadress.com](https://macadress.com): the registering vendor, an inferred
device category, virtualization / container-network detection, special-use
address classification (broadcast, multicast, VRRP, HSRP, STP, LACP,
802.1X, LLDP, ...), and MAC-randomization confidence. It calls the same
lookup that backs the macadress.com JSON API, MCP server and website.

## Supported data types

- `mac`
- `other` (for deployments that store MAC addresses as `other`)

## Configuration

| Item | Required | Description |
|---|---|---|
| `api_key` | yes | macadress.com API key (Bearer token, starts with `mk_`). The free tier is 1,000 lookups/month with no card. Sign up at <https://macadress.com/signup>, then copy the key from the account page. |

The analyzer honours `check_tlp` / `max_tlp` (default `max_tlp: 2`, i.e.
TLP:RED observables are not sent off-box) and the PAP equivalents.

## Output

`full` is the raw macadress.com `Result` object
(<https://macadress.com/docs>). The `summary` taxonomies are:

| Taxonomy | Example | Level |
|---|---|---|
| `macadress:Vendor` | `Apple, Inc.` / `locally-administered` / `unregistered` | info |
| `macadress:Device` | `smartphone` (omitted when `unknown`) | info |
| `macadress:Virtualization` | `VMware` (only when detected) | info |
| `macadress:SpecialUse` | `VRRP` (only when detected) | info |
| `macadress:Randomized` | `possible` / `likely` | info / suspicious |

`artifacts` surfaces the macadress.com vendor page URL(s) as `url`
observables.

## Errors

Explicit `errorMessage` is returned for a missing API key, an
unparseable MAC (HTTP 400), a rejected key (401), an exhausted quota or
rate limit (429), any other non-200, and network failures.
