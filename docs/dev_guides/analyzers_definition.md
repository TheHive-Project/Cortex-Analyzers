# Definition of an analyzer

!!! warning ""

## Folder tree


```
./analyzers/DomainToolsIris/
├── DomainToolsIris_Investigate.json
├── DomainToolsIris_Pivot.json
├── README.md
├── assets
│   ├── DomainToolsIris_Investigate_long.png
│   ├── DomainToolsIris_Investigate_short.png
│   ├── DomainToolsIris_Pivot_long.png
│   ├── DomainToolsIris_Pivot_short.png
│   └── domaintools_logo.png
├── domaintoolsiris_analyzer.py
└── requirements.txt
``` 


### JSON files

An analyzers is composed of, on flavor at least, and can be defined with several flavors. One `JSON` file describes a flavor. 
#### Example of an Analyzer's flavor definition file (`DomainToolsIris_Investigate.json`)

```json
{
  "name": "DomainToolsIris_Investigate",
  "version": "1.0",
  "author": "DomainTools",
  "url": "https://github.com/TheHive-Project/Cortex-Analyzers",
  "license": "AGPL-V3",
  "description": "Use DomainTools Iris API to investigate a domain.",
  "dataTypeList": ["domain"],
  "command": "DomainToolsIris/domaintoolsiris_analyzer.py",
  "baseConfig": "DomainToolsIris",
  "config": {
      "service": "investigate-domain"
  },
  "configurationItems": [
    {
      "name": "username",
      "description": "DomainTools Iris API credentials",
      "type": "string",
      "multi": false,
      "required": true
    },
    {
      "name": "key",
      "description": "DomainTools Iris API credentials",
      "type": "string",
      "multi": false,
      "required": true
    },
    {
      "name": "pivot_count_threshold",
      "description": "Pivot count threshold.",
      "type": "number",
      "multi": false,
      "required": false,
      "defaultValue": 500
    }
  ],
  "registration_required": true,
  "subscription_required": true,
  "free_subscription": false,
  "service_homepage": "https://www.domaintools.com",
  "service_logo": {"path":"assets/domaintools_logo.png", "caption": "logo"},
  "screenshots": [
    {"path":"assets/DomainToolsIris_Investigate_long.png",
      "caption":"DomainToolsIris_Investigate long report sample"
    },
    {
      "path": "assets/DomainToolsIris_Investigate_short.png",
      "caption:":"DomainToolsIris_Investigate mini report sample"
    }]
}
```


### README.md

This file contains global information and requirements regarding the Analyzer. It can also contains additionnal developers notes. 

#### Formatting

This file is using Mardkown text formatting. There is no specific requirements except that if headers are inserted, they shouldn't  start lower than level 3.

```markdown hl_lines="1"

### header level 3

#### header level 4

#### header level 5
```



### programs (`name.py`)



### requirements.txt


