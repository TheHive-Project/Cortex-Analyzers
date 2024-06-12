### NERD 


[NERD](https://nerd.cesnet.cz/) is a service provided by CESNET which collects information about malicious IP addresses
from CESNET's own detection systems as well as several public sources.
It keeps a profile of each known malicious IP address, containing all security-relevant information about the
address, and it summarizes it into a *reputation score* - a number from 0.0 (good) to 1.0 (bad) representing the amount
and confidence of recently received reports about that address.

The analyzer comes in a single flavour that will return the reputation score and various tags for provided IP.

#### Requirements
You need a valid NERD API integration subscription to use the analyzer.

- Provide your API key as values for the `key` parameter.
- Default url of NERD instance is provided for `url` parameter, but you could override it.