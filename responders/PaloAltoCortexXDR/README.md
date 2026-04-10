Palo Alto Cortex XDR: Extended Detection and Response

Cortex XDR is the industry’s first extended detection and response platform that integrates network, endpoint, cloud, and third-party data to stop sophisticated attacks. Cortex XDR has been designed from the ground up to help organizations secure their digital assets and users while simplifying operations. Using behavioral analytics, it identifies unknown and highly evasive threats targeting your network. Machine learning and AI models uncover threats from any source, including managed and unmanaged devices.

This responder interacts with the Cortex XDR API to support the following actions:

**Endpoint actions** — operate on a `fqdn` or `ip` case artifact. The FQDN value should match the endpoint name as it appears in the Cortex XDR console.
* **Isolate**: isolate an endpoint from the network to prevent a suspected compromised system from causing further harm.
* **Unisolate**: reverse the isolation of a previously isolated endpoint.
* **Scan**: initiate a full scan of an endpoint. Accepts multiple inputs at once if your observable is a multi-line value with one entry per line.
* **Cancel Scan**: abort a running scan on an endpoint (only possible if the scan is in Pending or In Progress status).
* **Initiate Forensics Triage**: trigger forensics collection on an endpoint. Requires the Forensics add-on license. An optional triage configuration preset UUID can be specified, otherwise the XDR default is used.

**Hash actions** — operate on a `hash` case artifact (SHA256).
* **Block List**: add a file hash to the Cortex XDR block list. Accepts multiple inputs at once if your observable is a multi-line value with one hash per line.
* **Allow List**: add a file hash to the Cortex XDR allow list. Accepts multiple inputs at once if your observable is a multi-line value with one hash per line.
* **Restore File**: restore a quarantined file on all endpoints where it was quarantined. Operates on a single hash observable.

For Isolate and Unisolate, the responder can be configured to accept multi-line observables (one entry per line) by enabling `allow_multiple_isolation_targets` in the responder configuration. This is disabled by default as a safety mechanism.
