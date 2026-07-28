### Zscaler

#### General requirements

You will need to have an active Zscaler ZIA subscription to be able to utilize this analyzer. For reference, you may use this supporting documentation in case of issues with the API: [Getting started with ZIA API](https://help.zscaler.com/zia/getting-started-zia-api).

#### ZscalerZIA_URLLookup configuration

The analyzer supports two authentication modes, set via `auth_type`.

**OneAPI (recommended, `auth_type: oneapi`)**

1. In the ZIdentity Admin Portal, create an **API Client** and assign it the **ZIA** API role.
2. Please make sure you have a correct role matching your needs, you may need to [create a ZIA API role](https://console.zscaler.com/internet-saas#administration/role-management) (see https://help.zscaler.com/zia/adding-api-roles for help) with, at the very least, **view-only** for URL Categories.
3. Configure in Cortex:
   - `zia_vanity_domain`: only the short label before `.zslogin.net`. If your org's login page is `companyname.zslogin.net`, this value is `companyname` — **not** `companyname.zslogin.net` and not the full URL.
   - `zia_client_id` / `zia_client_secret`: from the API Client created above.
   - `zia_cloud`: leave **blank** for standard/production tenants.

If you get `401 invalid_client` please, make sure to review step 2.

**Legacy (`auth_type: legacy`)**

Requires `zia_username`, `zia_password`, `zia_api_key`, and `zia_cloud` (your ZIA cloud name, it may be `zscaler`, `zscalerone`, `zscalertwo`).
