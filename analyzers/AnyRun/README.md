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

#### Optional Parameters
AnyRun provides a number of parameters that can be modified to do additional/different analysis.
- Set the "bitness" of your runtime environment with the `env_bitness` parameter.
- Select which version of Windows to use by setting `env_version` parameter.
- Select which products to install by default with `env_type` parameter.
- Enable/disable networking with `opt_network_connect` parameter.
- Enable/disable "FakeNet" with `opt_network_fakenet` parameter.
- Enable/disable the TOR network with `opt_network_tor` parameter.
- Enable/disable MITM for https connections with `opt_network_mitm` parameter.
- Need a specific geolocation? use `opt_network_geo` parameter.
- Need to analyze something with evasion tactics? `opt_kernel_heavyevasion`
- Change the timeout settings with `opt_timeout` parameter.
- Select which folder the analysis starts in with `obj_ext_startfolder` parameter.
- Select which browser to use for analysis with `obj_ext_browser` parameter.
