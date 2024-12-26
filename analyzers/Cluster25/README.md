# Cluster25 Cortex Analyzer

Allows to query Cluster25's CTI API investigation service.
Running the analyzer will return a short report with taxonomies,
as well as a long report and extracted artefacts.

## Requirements:
* C25 API KEY
* C25 CLIENT ID
* C25 BASE URL

Raw investigate result query example:
```json
{
  "indicator": "211.56.98.146",
  "indicator_type": "ipv4",
  "whitelisted": false,
  "tags": [],
  "score": 70,
  "is_known": false,
  "actors": [],
  "related_indicators": {
    "by_file": [],
    "by_content": []
  },
  "related_contexts": [],
  "created_dt": null,
  "modified_dt": null,
  "attacker_activities": [],
  "targeted_sectors": [],
  "targeted_countries": [],
  "file_info": null,
  "cve_info": null,
  "asn_info": null,
  "btcaddress_info": null,
  "family_info": null,
  "stats": {
    "harmless": 61,
    "malicious": 5,
    "suspicious": 0,
    "undetected": 23
  },
  "communicating_files": [],
  "contacted_ips": [],
  "contacted_domains": [],
  "contacted_urls": [],
  "dropped_files": [],
  "passive_dns": {
    "resolutions": [
      {
        "record_name": "c3kr.simonxu.cc",
        "record_value": "211.56.98.146",
        "record_type": "A",
        "first_seen": "2021-03-26T14:16:15",
        "last_seen": "2021-03-26T14:16:55",
        "country_name": "South Korea",
        "$$hashKey": "object:64"
      },
      {
        "record_name": "counter.yadro.ru",
        "record_value": "211.56.98.146",
        "record_type": "A",
        "first_seen": "2018-10-19T22:00:00",
        "last_seen": "2018-10-19T22:00:00",
        "country_name": "South Korea",
        "$$hashKey": "object:65"
      }
    ]
  },
  "whois": {
    "ip": null,
    "created_date": null,
    "updated_date": "hostmaster@nic.or.kr",
    "expires_date": null,
    "registrant": {
      "name": "IP Manager",
      "organization": "Korea Telecom",
      "street1": "Gyeonggi-do Bundang-gu, Seongnam-si Buljeong-ro 90",
      "street2": null,
      "city": null,
      "state": null,
      "country": null,
      "country_code": null,
      "postal_code": "13606",
      "raw_text": null,
      "unparsable": null
    },
    "registrar_name": null,
    "name_servers_hostnames": null,
    "name_servers_ips": null,
    "email_provider": null,
    "email_registrant": null,
    "status": null
  },
  "guessed_types": [],
  "intelligence": null,
  "first_seen": null,
  "last_seen": null,
  "dns_resolutions": null
}
```
