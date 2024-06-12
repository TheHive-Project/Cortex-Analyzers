 Look up domain names, IP addresses, e-mail addresses, and SSL hashes using the popular
 [DomainTools Iris](https://www.domaintools.com/resources/api-documentation/iris-investigate/) service API.

 The analyzer comes in 2 flavors:

 - DomainToolsIris_**Investigate**: Use DomainTools Iris API to investigate a domain.
 - DomainToolsIris_**Pivot**: Use DomainTools Iris API to pivot on ssl_hash, ip, or email.

#### Requirements
 You need a [valid DomainTools API integration subscription](https://www.domaintools.com/products/api-integration/) to use the analyzer:

- Provide your username as a value for the `username` parameter and API key as
 a value for the `key` parameter.
- Set the `pivot_count_threshold` parameter to highlight any item below that value as being of interest in the
 report's template.
