# [Watcher](https://github.com/thalesgroup-cert/Watcher) Analyzer

## Watcher Analyzer

### Description
Watcher Analyzer for TheHive/Cortex enables comprehensive domain presence checking across both Watcher modules:
- **Legitimate Domain Module** (`/api/common/legitimate_domains/`) - Check legitimate/repurchased domains
- **Website Monitoring Module** (`/api/site_monitoring/site/`) - Check monitored suspicious/malicious domains

The analyzer checks both modules simultaneously and provides a unified result.

---

### Features

#### Watcher_Check
Check if a domain is monitored in one or both Watcher modules and retrieve a unified status and details:

**From Legitimate Domain Module:**
- Domain name
- Ticket ID
- Repurchased status (Yes/No)
- Contact email
- Creation/update timestamps

**From Website Monitoring Module:**
- Domain name
- Ticket ID
- Legitimacy score (2-6)
- IP addresses (primary, secondary)
- MX records
- Mail server IP
- Takedown request status
- Legal team notification status
- Blocking request status
- Creation/update timestamps

---

### Prerequisites
- Access to the Watcher API
- A valid API key for Watcher
- A functional instance of Cortex and TheHive

---

### Installation

Add the configuration file to the Cortex configurations.

---

### Configuration

Configure the following parameters in Cortex:

| Parameter         | Description                                                        | Type   | Required |
|-------------------|--------------------------------------------------------------------|--------|----------|
| `watcher_url`     | Base URL of Watcher instance (e.g., `https://watcher.local:9002`) | String | Yes      |
| `watcher_api_key` | API authentication token for Watcher                               | String | Yes      |

**Example Configuration:**
```json
{
  "watcher_url": "https://watcher.example.com:9002",
  "watcher_api_key": "your-api-token-here"
}
```

---

### Usage

#### Check Domain Presence
1. In TheHive, create a domain observable: `example.com`
2. Run analyzer: **Watcher_Check**
3. View results with one of four possible taxonomies:
   - `Watcher:Check = FoundOnBoth` (green) - Domain found in both modules
   - `Watcher:Check = FoundOnLegitDomain` (green) - Domain found in Legitimate Domain only
   - `Watcher:Check = FoundOnWebsiteMonitoring` (green) - Domain found in Website Monitoring only
   - `Watcher:Check = NotFound` (blue) - Domain not found in any module

---

### API Endpoints Used

#### Legitimate Domain Module
```
GET /api/common/legitimate_domains/?search={domain}
```

#### Website Monitoring Module
```
GET /api/site_monitoring/site/
```

---

### Taxonomies

The analyzer uses a unified taxonomy system:

| Analyzer        | Namespace | Predicate | Values                                                                                    | Colors              |
|-----------------|-----------|-----------|-------------------------------------------------------------------------------------------|---------------------|
| **Watcher_Check** | Watcher   | Check     | FoundOnBoth / FoundOnLegitDomain / FoundOnWebsiteMonitoring / NotFound | safe / safe / safe / info |

**Examples in TheHive:**
- `Watcher:Check = "MonitoredOnBoth"` (Green badge) - Found in both modules
- `Watcher:Check = "MonitoredOnLegitDomain"` (Green badge) - Found in Legitimate Domain only
- `Watcher:Check = "MonitoredOnWebsiteMonitoring"` (Green badge) - Found in Website Monitoring only
- `Watcher:Check = "None"` (Blue badge) - Not found in any module

---

### Best Practices

1. **Single analyzer approach** - One analyzer checks both modules simultaneously
2. **Use results** to trigger appropriate responders based on the status
3. **Template files** provide rich visual feedback in TheHive interface with detailed information from both modules when available

---

### Support

For issues, questions, or feature requests:
- **GitHub Issues**: [Watcher Repository](https://github.com/thalesgroup-cert/Watcher/issues)

---

### Authors

**Thales Group CERT** - [thalesgroup-cert on GitHub](https://github.com/thalesgroup-cert)  
**Ygal NEZRI** - [@ygalnezri](https://github.com/ygalnezri)