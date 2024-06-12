### Velociraptor
This responder can be used to run a flow for a Velociraptor artifact.  This could include gathering data, or performing initial response, as the artifact (or artifact "pack") could encompass any number of actions.  The responder can be run on an observable type of `ip`, `fqdn`, or `other`, and will look for a matching client via the Velociraptor server.  If a client match is found for the last seen IP, or the hostname, the responder will kick off the flow, the results will be returned, and the client ID will be added as a tag to the case and the observable.

#### Requirements
The following options are required in the Velociraptor Responder configuration:   

- `velociraptor_client_config`: The path to the Velociraptor API client config.  
(See the following for generating an API client config: https://www.velocidex.com/docs/user-interface/api/, and ensure the appropriate ACLs are granted to the API user).  
- `velociraptor_artifact`: The name artifact you which to collect (as you would see it in the Velociraptor GUI).
- `upload_flow_results`: Upload flow results to TheHive case (bool).
- `thehive_url`: URL of your TheHive installation (e.g. 'http://127.0.0.1:9000').
- `thehive_apikey`: TheHive API key used to add flow results/file(s) to a case.
