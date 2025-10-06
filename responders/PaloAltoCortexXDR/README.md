Palo Alto Cortex XDR: Extended Detection and Response

Cortex XDR is the industry’s first extended detection and response platform that integrates network, endpoint, cloud, and third-party data to stop sophisticated attacks. Cortex XDR has been designed from the ground up to help organizations secure their digital assets and users while simplifying operations. Using behavioral analytics, it identifies unknown and highly evasive threats targeting your network. Machine learning and AI models uncover threats from any source, including managed and unmanaged devices.

This responder interacts with the Cortex XDR API to support three actions:
* Isolate an endpoint from the network. Prevents a suspected compromised system from causing any further harm to the network.
* Unisolate an endpoint that was previously isolated.
* Scan: initial a full scan of an endpoint.

The responder operates on a 'fqdn' or 'ip' case artifact (observable) from TheHive. The value of the FQDN should be the endpoint name as it appears in the Cortex XDR console.

The responder accepts multiple inputs at once if your observable is multi-line value with one entry per line.
