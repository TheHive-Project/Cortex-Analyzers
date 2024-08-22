### CrowdSec

Check [CrowdSec](https://www.crowdsec.net/) Threat Intelligence about an ip address.

For further information, please consult the [official documentation](https://doc.crowdsec.net/u/cti_api/integration_thehive/).

Running the analyzer will expose the result as taxonomies in the short report displayed in the ip observable.

![short result example](./assets/crowdsec-analyzer-result-example.png)

The raw report contains the whole json response from CrowdSec.

e.g.:

```json
{
  "ip": "192.42.116.218",
  "reputation": "malicious",
  "ip_range": "192.42.116.0/22",
  "background_noise": "high",
  "confidence": "high",
  "background_noise_score": 10,
  "ip_range_score": 5,
  "as_name": "SURF B.V.",
  "as_num": 1101,
  "ip_range_24": "192.42.116.0/24",
  "ip_range_24_reputation": "malicious",
  "ip_range_24_score": 5,
  "location": {
    "country": "NL",
    "city": null,
    "latitude": 52.3824,
    "longitude": 4.8995
  },
  "reverse_dns": "44.tor-exit.nothingtohide.nl",
  "behaviors": [
    {
      "name": "tcp:scan",
      "label": "TCP Scan",
      "description": "IP has been reported for performing TCP port scanning.",
      "references": [],
      "$$hashKey": "object:984"
    },
    {
      "name": "http:bruteforce",
      "label": "HTTP Bruteforce",
      "description": "IP has been reported for performing a HTTP brute force attack (either generic HTTP probing or applicative related brute force).",
      "references": [],
      "$$hashKey": "object:985"
    },
    {
      "name": "http:exploit",
      "label": "HTTP Exploit",
      "description": "IP has been reported for attempting to exploit a vulnerability in a web application.",
      "references": [],
      "$$hashKey": "object:986"
    },
    {
      "name": "http:scan",
      "label": "HTTP Scan",
      "description": "IP has been reported for performing actions related to HTTP vulnerability scanning and discovery.",
      "references": [],
      "$$hashKey": "object:987"
    },
    {
      "name": "http:spam",
      "label": "Web form spam",
      "description": "IP has been reported trying to perform spam via web forms/forums.",
      "references": [],
      "$$hashKey": "object:988"
    },
    {
      "name": "generic:exploit",
      "label": "Exploitation attempt",
      "description": "IP has been reported trying to exploit known vulnerability/CVE on unspecified protocols.",
      "references": [],
      "$$hashKey": "object:989"
    },
    {
      "name": "ssh:bruteforce",
      "label": "SSH Bruteforce",
      "description": "IP has been reported for performing brute force on ssh services.",
      "references": [],
      "$$hashKey": "object:990"
    }
  ],
  "history": {
    "first_seen": "2022-12-26T01:15:00+00:00",
    "last_seen": "2024-07-31T10:00:00+00:00",
    "full_age": 585,
    "days_age": 584
  },
  "classifications": {
    "false_positives": [],
    "classifications": [
      {
        "name": "proxy:tor",
        "label": "TOR exit node",
        "description": "IP is being flagged as a TOR exit node.",
        "references": [],
        "$$hashKey": "object:1021"
      },
      {
        "name": "crowdsec:ai_vpn_proxy",
        "label": "VPN or Proxy",
        "description": "IP is identified as a VPN or a Proxy by CrowdSec AI Detection Algorithm.",
        "references": [],
        "$$hashKey": "object:1022"
      },
      {
        "name": "community-blocklist",
        "label": "CrowdSec Community Blocklist",
        "description": "IP belongs to the CrowdSec Community Blocklist",
        "$$hashKey": "object:1023"
      }
    ]
  },
  "attack_details": [
    {
      "name": "firewallservices/pf-scan-multi_ports",
      "label": "PF Scan Multi Ports",
      "description": "ban IPs that are scanning us",
      "references": [],
      "$$hashKey": "object:1027"
    },
    {
      "name": "crowdsecurity/http-path-traversal-probing",
      "label": "HTTP Path Traversal Exploit",
      "description": "Detect path traversal attempt",
      "references": [],
      "$$hashKey": "object:1028"
    },
    {
      "name": "crowdsecurity/grafana-cve-2021-43798",
      "label": "CVE-2021-43798",
      "description": "Detect cve-2021-43798 exploitation attemps",
      "references": [],
      "$$hashKey": "object:1029"
    },
    {
      "name": "crowdsecurity/http-admin-interface-probing",
      "label": "HTTP Admin Interface Probing",
      "description": "Detect generic HTTP admin interface probing",
      "references": [],
      "$$hashKey": "object:1030"
    },
    {
      "name": "crowdsecurity/http-open-proxy",
      "label": "HTTP Open Proxy Probing",
      "description": "Detect scan for open proxy",
      "references": [],
      "$$hashKey": "object:1031"
    },
    {
      "name": "crowdsecurity/http-cve-probing",
      "label": "HTTP CVE Probing",
      "description": "Detect generic HTTP cve probing",
      "references": [],
      "$$hashKey": "object:1032"
    },
    {
      "name": "LePresidente/http-generic-403-bf",
      "label": "HTTP Bruteforce",
      "description": "Detect generic 403 Forbidden (Authorization) error brute force",
      "references": [],
      "$$hashKey": "object:1033"
    },
    {
      "name": "crowdsecurity/http-sqli-probbing-detection",
      "label": "SQL Injection Attempt",
      "description": "A scenario that detects SQL injection probing with minimal false positives",
      "references": [],
      "$$hashKey": "object:1034"
    },
    {
      "name": "crowdsecurity/http-sensitive-files",
      "label": "Access to sensitive files over HTTP",
      "description": "Detect attempt to access to sensitive files (.log, .db ..) or folders (.git)",
      "references": [],
      "$$hashKey": "object:1035"
    },
    {
      "name": "crowdsecurity/http-bad-user-agent",
      "label": "Bad User Agent",
      "description": "Detect usage of bad User Agent",
      "references": [],
      "$$hashKey": "object:1036"
    },
    {
      "name": "crowdsecurity/suricata-major-severity",
      "label": "Suricata Severity 1 Event",
      "description": "Detect exploit attempts via emerging threat rules",
      "references": [],
      "$$hashKey": "object:1037"
    },
    {
      "name": "crowdsecurity/ssh-bf",
      "label": "SSH Bruteforce",
      "description": "Detect ssh bruteforce",
      "references": [],
      "$$hashKey": "object:1038"
    },
    {
      "name": "crowdsecurity/apache_log4j2_cve-2021-44228",
      "label": "Log4j CVE-2021-44228",
      "description": "Detect cve-2021-44228 exploitation attemps",
      "references": [],
      "$$hashKey": "object:1039"
    },
    {
      "name": "crowdsecurity/http-bf-wordpress_bf_xmlrpc",
      "label": "WP XMLRPC bruteforce",
      "description": "detect wordpress bruteforce on xmlrpc",
      "references": [],
      "$$hashKey": "object:1040"
    },
    {
      "name": "crowdsecurity/ssh-slow-bf",
      "label": "SSH Slow Bruteforce",
      "description": "Detect slow ssh bruteforce",
      "references": [],
      "$$hashKey": "object:1041"
    },
    {
      "name": "crowdsecurity/http-bf-wordpress_bf",
      "label": "WordPress Bruteforce",
      "description": "Detect WordPress bruteforce on admin interface",
      "references": [],
      "$$hashKey": "object:1042"
    },
    {
      "name": "crowdsecurity/http-wordpress_wpconfig",
      "label": "Access to WordPress wp-config.php",
      "description": "Detect WordPress probing: variations around wp-config.php by wpscan",
      "references": [],
      "$$hashKey": "object:1043"
    },
    {
      "name": "crowdsecurity/http-xss-probbing",
      "label": "XSS Attempt",
      "description": "A scenario that detects XSS probing with minimal false positives",
      "references": [],
      "$$hashKey": "object:1044"
    },
    {
      "name": "crowdsecurity/modsecurity",
      "label": "Modsecurity Alert",
      "description": "Web exploitation via modsecurity",
      "references": [],
      "$$hashKey": "object:1045"
    },
    {
      "name": "crowdsecurity/http-probing",
      "label": "HTTP Probing",
      "description": "Detect site scanning/probing from a single ip",
      "references": [],
      "$$hashKey": "object:1046"
    }
  ],
  "target_countries": {
    "US": 38,
    "DE": 20,
    "JP": 10,
    "FR": 8,
    "GB": 7,
    "NL": 5,
    "PL": 3,
    "CA": 2,
    "RU": 2,
    "DK": 2
  },
  "mitre_techniques": [
    {
      "name": "T1595",
      "label": "Active Scanning",
      "description": "Adversaries may execute active reconnaissance scans to gather information that can be used during targeting.",
      "references": [],
      "$$hashKey": "object:1009"
    },
    {
      "name": "T1018",
      "label": "Remote System Discovery",
      "description": "Adversaries may attempt to get a listing of other systems by IP address, hostname, or other logical identifier on a network that may be used for Lateral Movement from the current system.",
      "references": [],
      "$$hashKey": "object:1010"
    },
    {
      "name": "T1046",
      "label": "Network Service Discovery",
      "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation.",
      "references": [],
      "$$hashKey": "object:1011"
    },
    {
      "name": "T1110",
      "label": "Brute Force",
      "description": "Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.",
      "references": [],
      "$$hashKey": "object:1012"
    },
    {
      "name": "T1190",
      "label": "Exploit Public-Facing Application",
      "description": "Adversaries may attempt to exploit a weakness in an Internet-facing host or system to initially access a network.",
      "references": [],
      "$$hashKey": "object:1013"
    },
    {
      "name": "T1589",
      "label": "Gather Victim Identity Information",
      "description": "Adversaries may gather information about the victim's identity that can be used during targeting.",
      "references": [],
      "$$hashKey": "object:1014"
    }
  ],
  "cves": [
    "CVE-2021-43798",
    "CVE-2021-44228"
  ],
  "scores": {
    "overall": {
      "aggressiveness": 5,
      "threat": 4,
      "trust": 5,
      "anomaly": 1,
      "total": 5
    },
    "last_day": {
      "aggressiveness": 5,
      "threat": 4,
      "trust": 5,
      "anomaly": 1,
      "total": 5
    },
    "last_week": {
      "aggressiveness": 5,
      "threat": 4,
      "trust": 5,
      "anomaly": 1,
      "total": 5
    },
    "last_month": {
      "aggressiveness": 5,
      "threat": 4,
      "trust": 5,
      "anomaly": 1,
      "total": 5
    }
  },
  "references": [
    {
      "name": "list:crowdsec_high_background_noise",
      "label": "CrowdSec High Background Noise List",
      "description": "Contains all IPs in our database that are considered as background noise. These IPs are not necessarily malicious, but they are considered as a potential threat. Proactively block these IPs if you want to reduce the noise on your systems.",
      "references": [],
      "$$hashKey": "object:1077"
    },
    {
      "name": "list:crowdsec_intelligence_blocklist",
      "label": "CrowdSec Intelligence List",
      "description": "Contains all IPs in our database that have been identified as actively aggressive, performing a wide variety of attacks. Proactively block these IPs if you don’t want to take any chances with malicious IPs potentially reaching your systems.",
      "references": [],
      "$$hashKey": "object:1078"
    },
    {
      "name": "list:firehol_botscout_7d",
      "label": "Firehol BotScout list",
      "description": "BotScout helps prevent automated web scripts, known as bots, from registering on forums, polluting databases, spreading spam, and abusing forms on web sites. They do this by tracking the names, IPs, and email addresses that bots use and logging them as unique signatures for future reference. This list is composed of the most recently-caught bots.",
      "references": [
        "https://iplists.firehol.org/?ipset=botscout_7d"
      ],
      "$$hashKey": "object:1079"
    }
  ]
}
```


#### Requirements

Provide a [CrowdSec CTI Api key](https://docs.crowdsec.net/u/cti_api/getting_started/#getting-an-api-key)
as a value for the `api_key` parameter.
