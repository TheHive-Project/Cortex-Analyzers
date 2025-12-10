# [Watcher](https://github.com/thalesgroup-cert/Watcher)

## Watcher Check Domain Analyzer

### Description
The Watcher Check Domain Analyzer is an Analyzer for TheHive/Cortex that checks if a given domain is already being monitored in the Watcher website monitoring system.

### Features
- **Check if a domain is monitored**: Verifies whether a specific domain is already being monitored in the Watcher system.

### Prerequisites
- Access to the Watcher API
- A valid API key for Watcher
- A functional instance of Cortex and TheHive

### Installation
- Add the configuration files for this analyzer to your Cortex configuration.

### Configuration
In Cortex, configure the following parameters for the Analyzer:

| Parameter          | Description                                                        | Required | Default Value |
|--------------------|--------------------------------------------------------------------|----------|----------------|
| `watcher_url`      | URL of Watcher (e.g. `https://example.watcher.local:9002`)         | Yes      | -              |
| `watcher_api_key`  | API key for authenticating                                         | Yes      | -              |

### Usage
When a domain artifact is submitted to this analyzer, it will:
1. Query the Watcher API to check if the domain is already monitored.
2. Return a report with either the monitoring status of the domain or an indication that it is not yet monitored.

### Example JSON Response
#### Domain is already monitored
```json
{
  "status": "Monitored",
  "Message": "Domain 'example.com' is already monitored in Watcher.",
  "ticket_id": "12345"
}
```

#### Domain is not monitored
```json
{
  "status": "Not Monitored",
  "Message": "Domain 'example.com' is not monitored in Watcher. You can add it using the Watcher responder."
}
```

### Template Setup in TheHive

To customize the display of analyzer results in TheHive, you can use **analyzer templates**. 

Follow these steps to install the templates for the `Watcher_CheckDomain` analyzer:

1. Navigate to **TheHive** web interface  
2. Go to **Admin** > **Entities Management** > **Analyzer templates**  
3. Click on **Import templates**  
4. Browse to the template directory  
5. Select both `short.html` and `long.html` files  
6. Click **Import**  
7. Make sure the templates are correctly associated with the `Watcher_CheckDomain` analyzer

Once done, TheHive will use these templates to display the analyzer output with better readability and style.

### Author

**Thales Group CERT** - [thalesgroup-cert on GitHub](https://github.com/thalesgroup-cert)  
**Ygal NEZRI** - [@ygalnezri](https://github.com/ygalnezri)