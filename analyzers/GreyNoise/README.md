### GreyNoise 
[GreyNoise](https://viz.greynoise.io/) collect and analyze untargeted, widespread, and opportunistic scan and attack 
activity that reaches every server directly connected to the Internet. Mass scanners (such as Shodan and Censys), 
search engines, bots, worms, and crawlers generate logs and events omnidirectionally on every IP address in the IPv4 
space. GreyNoise gives you the ability to filter this useless noise out.

The analyzer comes in a single flavour, but supports both the GreyNoise Paid and Community APIs, that will return 
GreyNoise additional information categorization for provided ip.

#### Requirements
You need a valid GreyNoise API integration subscription or Community account to use the analyzer.

- Provide your API key as values for the `key` parameter.
- Provide your API key type as "enterprise" (the default) or "community" for the `api_type` parameter