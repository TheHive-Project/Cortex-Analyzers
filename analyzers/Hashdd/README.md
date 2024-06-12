### Hashdd 
[Hashdd](https://www.hashdd.com/)  search engine for file hashes which automatically queries 3rd party services like VirusTotal and enriches the information provided based on the 3rd party data. 

The analyzer includes two flavors: Status and Detail. The first one is used to query hashdd without an API key for the threat level only. The latter produces additional meta information about the sample, but requires an API key.

#### Requirements
A valid Hashdd API is necessary just for detail flavour, for status can still be added.

- Provide your API key as values for the `key` parameter.