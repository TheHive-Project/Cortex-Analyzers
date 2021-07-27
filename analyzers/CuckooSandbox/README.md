### CuckooSandbox

[CuckooSandbox](https://cuckoosandbox.org/)  is an advanced, extremely modular, and 100% open source automated malware analysis system with infinite application opportunities. 

- Analyze many different malicious files (executables, office documents, pdf files, emails, etc) as well as malicious websites under Windows, Linux, macOS, and Android virtualized environments.
- Trace API calls and general behavior of the file and distill this into high level information and signatures comprehensible by anyone.
- Dump and analyze network traffic, even when encrypted with SSL/TLS. With native network routing support to drop all traffic or route it through InetSIM, a network interface, or a VPN.
- Perform advanced memory analysis of the infected virtualized system through Volatility as well as on a process memory granularity using YARA.

The analyzer comes in two different flavour to analzye url or file with internet access.

#### Requirements

You need to have your cuckoosandox deployed in your infrastructure. You can download it and follow installation instructions.

The address of the machine must be se as `url` parameter and relative token as the value for the `token` parameter.
Depending on your network configuration you can configure `verifyssl` and `cert_path` accordingly.