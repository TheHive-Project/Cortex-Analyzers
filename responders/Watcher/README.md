# [Watcher](https://github.com/thalesgroup-cert/Watcher)

## Watcher Monitor Manager Responder

### Description
Watcher Monitor Manager is a Responder for TheHive/Cortex that allows adding or removing a domain from monitoring in the Watcher website monitoring module.

### Features
- **Add a domain to monitoring** (`WatcherAddDomain`)
- **Remove a domain from monitoring** (`WatcherRemoveDomain`)

### Prerequisites
- Access to the Watcher API
- A valid API key of Watcher
- A functional instance of Cortex and TheHive

### Installation
- Add the configuration files (`Watcher_AddDomain.json` and `Watcher_RemoveDomain.json`) to the Cortex configurations.

### Configuration
In Cortex, configure the following parameters for the Responder:

| Parameter               | Description                                                              | Required | Default Value |
|-------------------------|--------------------------------------------------------------------------|----------|----------------|
| `watcher_url`           | URL of Watcher (e.g. `https://example.watcher.local:9002`)           | Yes      | -              |
| `watcher_api_key`       | API key for authentication                                               | Yes      | -              |
| `the_hive_custom_field` | Name of the custom field (same as .env variable)                         | Yes      | `watcher-id`   |

### Usage
When an artifact of type `domain` is submitted to this Responder, it will:
1. Extract the Watcher ID from the `customFieldValues` of the alert or case.
2. Perform the requested action (`add` or `remove`) based on the specified service.
3. Return a report indicating the success or failure of the operation.

### Example JSON Response
#### Adding a Domain
```json
{
  "Message": "Domain 'example.com' successfully added to monitoring with watcher-id: '12345'.",
  "WatcherResponse": {"status": "success"}
}
```

#### Removing a Domain
```json
{
  "Message": "Domain 'example.com' successfully removed from monitoring.",
  "WatcherResponse": {"status": "success"}
}
```

### Author

**Thales Group CERT** - [thalesgroup-cert on GitHub](https://github.com/thalesgroup-cert)  
**Ygal NEZRI** - [@ygalnezri](https://github.com/ygalnezri)