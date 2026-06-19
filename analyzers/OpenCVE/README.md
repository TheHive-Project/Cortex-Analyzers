# OpenCVE Analyzer

Enrich a `cve` observable with vulnerability data from [OpenCVE](https://www.opencve.io).

OpenCVE aggregates CVE information from several providers (NVD, Red Hat, CISA, FIRST, ...)
and exposes it through a REST API. This analyzer queries that API for a given CVE and
reports its CVSS metrics, CISA KEV status, EPSS score, CWE weaknesses and the affected
vendors and products. Unlike the existing Vulners analyzer, OpenCVE is free to use and can
also be self-hosted.

### Supported observable

- `cve` (for example `CVE-2021-44228`)

### Requirements

You need an OpenCVE account and an organization API token:

1. Create a free account at [app.opencve.io](https://app.opencve.io). The Free plan includes API access (100 calls/hour).
2. Open your organization settings and generate an API token.
3. Provide it to the analyzer through the `token` configuration option.

If you run your own OpenCVE instance, set `base_url` to its API endpoint. The default is
`https://app.opencve.io/api`.

### Configuration

| Name | Description | Required | Default |
|------|-------------|----------|---------|
| `token` | OpenCVE organization API token (Bearer). | yes | |
| `base_url` | OpenCVE API base URL. | no | `https://app.opencve.io/api` |
