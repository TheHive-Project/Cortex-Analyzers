### VirusTotalDownloader

This responder comes in only 1 flavor that lets you download a sample of malware from VirusTotal by submitting a hash.

#### Requirements

This responder need a valid Premium API key from VirusTotal as the `virustotal_apikey` parameter in the configuration. 
To add the sample in Observables in TheHive, the responder also requires the URL of TheHive as the `thehive_url` paramenter and a valid API key as the `thehive_apikey` parameter.