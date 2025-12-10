### Velociraptor
This responder can be used to run a flow for a Velociraptor artifact.  This could include gathering data, or performing initial response, as the artifact (or artifact "pack") could encompass any number of actions.  The responder can be run on an observable type of `ip`, `fqdn`, or `other`, and will look for a matching client via the Velociraptor server.  If a client match is found for the last seen IP, or the hostname, the responder will kick off the flow, the results will be returned, and the client ID will be added as a tag to the case and the observable.

#### Requirements
The following options are required in the Velociraptor Responder configuration:

**API Client Configuration** (choose one):
- `velociraptor_client_config`: The path to the Velociraptor API client config file.
- `velociraptor_client_config_content_base64`: Base64-encoded API client config (recommended for SaaS/containerized deployments).

To generate an API client config, see: https://www.velocidex.com/docs/user-interface/api/
Ensure the appropriate ACLs are granted to the API user.

For SaaS deployments, encode your API client config:
```bash
cat api_client.yaml | base64
```
Then paste the output into the `velociraptor_client_config_content_base64` parameter.

**Other Parameters**:
- `velociraptor_artifact`: The name of the artifact you wish to collect (as you would see it in the Velociraptor GUI). **Required**.
- `query_max_duration`: Max query duration in seconds (default: 600). **Optional**.
