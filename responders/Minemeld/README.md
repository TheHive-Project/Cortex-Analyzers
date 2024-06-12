### Palo Alto Minemeld

This responder sends observables you select to a [Palo Alto Minemeld](https://www.paloaltonetworks.com/products/secure-the-network/subscriptions/minemeld) instance.

#### Requirements
The following options are required in the Palo Alto Minemeld Responder configuration:

- `minemeld_url` : URL of the Minemeld instance to which you will be posting indicators   
- `minemeld_user`: user accessing the Minemeld instance
- `minemeld_password`:  password for the user accessing the Minemeld instance
- `minemeld_indicator_list`: name of Minemeld indicator list (already created in Minemeld)
- `minemeld_share_level`: share level for indicators (defaults to `red`)
- `minemeld_confidence`: confidence level for indicators (defaults to `100`)
- `minemeld_ttl`: TTL for indicators (defaults to `86400` seconds)