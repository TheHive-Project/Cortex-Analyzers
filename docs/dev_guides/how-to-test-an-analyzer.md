# How to test you analyzers/responder

## Pre-requisites

Create 2 folders named `input` and `output` in the folder of the neuron to test, and the file `input.json`: 

```
├── input
│   └── input.json
└── output
```

!!! "These path have been added to .gitignore file and thus are not tracked by git."

- `input/input.json`

```json
{
    "data": "185.162.131.25",
    "tlp": 0,
    "parameters": {},
    "dataType": "ip",
    "config": {
        "jobTimeout": 30,
        "service": "",
        "url": "",
        "api_key": "",
        "proxy_http": "",
        "proxy": {
            "http": "",
            "https": ""
        },
        "max_tlp": 2,
        "max_pap": 2,
        "check_tlp": true,
        "check_pap": true,
        "proxy_https": "",
        "cacerts": "",
        "auto_extract_artifacts": false,        
        "jobCache": 10
    },
    "pap": 2,
    "message": "1"
    }
```



## Running the program

- Using main program
```bash
 /path to/analyzers/DShield/DShield_lookup.py .
```

- Using docker image and docker-compose
```bash
docker run --rm -v ${PWD}:/job cortexneurons/dshield_lookup:devel
```


Running the program successfully should create at least a new file called `output.json` in the output directory: 

- `output/output.json`

```json
{
  "success": true,
  "summary": {
    "taxonomies": [
      {
        "level": "safe",
        "namespace": "DShield",
        "predicate": "Score",
        "value": "0 count(s) / 0 attack(s) / 1 threatfeed(s)"
      }
    ]
  },
  "artifacts": [
    {
      "type": "autonomous-system",
      "value": "14576"
    },
    {
      "type": "mail",
      "value": "abuse@king-servers.com"
    }
  ],
  "full": {
    "ip": "185.162.131.25",
    "count": 0,
    "attacks": 0,
    "lastseen": "None",
    "firstseen": "None",
    "updated": "None",
    "comment": "None",
    "asabusecontact": "abuse@king-servers.com",
    "as": 14576,
    "asname": "HOSTING-SOLUTIONS",
    "ascountry": "US",
    "assize": 11264,
    "network": "185.162.131.0/24",
    "threatfeedscount": 1,
    "threatfeeds": {
      "ciarmy": {
        "lastseen": "2018-10-06",
        "firstseen": "2018-10-06"
      }
    },
    "maxrisk": 0,
    "reputation": "Safe"
  }
}
```
