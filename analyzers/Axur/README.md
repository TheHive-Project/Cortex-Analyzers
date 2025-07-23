### Axur Ioc's analyzer

The Axur IOC Analyzer is a tool for identifying and value potential threats in your data. It uses Axur's services and databases to perform analysis on a variety of data types.

The Analyzer provides an efficient solution to evaluate potential threats by examining various data types including:

* _domain_
* _url_
* _ip_
* _fqdn_
* _hash_

With the Axur IOC Analyzer, Axur clients have an easy way to make their data environment safer and more secure.

#### Requirements
You need a valid Axur API key to use the analyzer. Available exclusively to our Axur clients.

- Provide your API key as values for the `api_key` header.

### Return example

```
{
    "success": true,
    "summary": {
        "taxonomies": [
            {
                "level": "suspicious",
                "namespace": "Axur",
                "predicate": "IOC_FEED",
                "value": 2
            },
            {
                "level": "suspicious",
                "namespace": "Axur",
                "predicate": "EXPLORE",
                "value": 1
            },
            {
                "level": "suspicious",
                "namespace": "Axur",
                "predicate": "MALICIOUS_URL",
                "value": 1
            }
        ]
    },
    "artifacts": [],
    "operations": [],
    "full": {
        "type": "URL",
        "value": "https://sso.ecometrica.com/accounts/login",
        "results": [
            {
                "source": "IOC_FEED",
                "score": 2,
                "hits": 2,
                "context": [
                    {
                        "tags": [
                            "phishing"
                        ],
                        "detection": 1683945464000,
                        "risk": "UNDEFINED",
                        "platform": "AXUR"
                    },
                    {
                        "tags": [],
                        "detection": 1642009957000,
                        "risk": "MEDIUM",
                        "platform": "AXUR"
                    }
                ]
            },
            {
                "source": "EXPLORE",
                "score": 2,
                "hits": 1,
                "context": [
                    {
                       "content": "texto", 
                       "detection": 1687187006704,
                       "platform": "AXUR"
                    }
                ]
            },
            { 
                "source": "MALICIOUS_URL",
                "score": 2,
                "hits": 1,
                "context": [
                    {
                        "riskLevel": 0.49,
                        "collectorName": "urlscan",
                        "detection": 1687187006704,
                        "ticketStatus": "open",
                        "platform": "AXUR"
                }
            ]
            }
        ],
        "searchDate": 1687292305787
    }
}
```
