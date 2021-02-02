### AnyRun
[ANY.RUN](https://any.run/) is a malware sandbox service in the cloud. By using this analyzer, an analyst can submit a suspicious file or URL to the service for analysis and get a report. The report can contain various information such as:

- Interactive access
- Research threats by filter in public submissions
- File and URL dynamic analysis
- Mitre ATT&CK mapping
- Detailed malware reports

#### Requirements
You need a valid AnyRun API integration subscription to use the analyzer. Free plan does not provide API access.

- Provide your API token as a value for the `token` parameter.
- Define the privacy setting in `privacy_type` parameter.
- Set `verify_ssl` parameter as false if you connection requires it