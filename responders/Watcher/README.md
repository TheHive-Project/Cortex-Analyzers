# [Watcher](https://github.com/thalesgroup-cert/Watcher) Responders

## Watcher Responder Suite

### Description

Intelligent Watcher Responder Suite for TheHive/Cortex with unified tag-based routing.

**4 Responders** manage two Watcher modules:

- **Legitimate Domain Module** (`/api/common/legitimate_domains/`) - Company-owned domains
- **Website Monitoring Module** (`/api/site_monitoring/site/`) - Suspicious/malicious domains

All operations use a single Python file (`watcher.py`) with intelligent routing via the **`watcher:module`** tag.

---

### Features

#### Universal Operations (4 Responders)

| Responder | Description |
|----------------------|-------------------------------------------------------|
| **Watcher_Add** | Add domain to LegitDomain or WebsiteMonitoring |
| **Watcher_Update** | Update domain in LegitDomain or WebsiteMonitoring |
| **Watcher_Remove** | Remove domain from LegitDomain or WebsiteMonitoring |
| **Watcher_Transfer** | Transfer domain between modules |

---

### Prerequisites

- Access to the Watcher API
- A valid API key for Watcher
- A functional instance of Cortex and TheHive

---

### Installation

Add the configuration files to the Cortex configurations.

---

### Configuration

Configure the following parameters in Cortex for each responder:

| Parameter | Description | Type | Required | Default Value |
|-------------------------|-------------------------------------------------------------------|--------|----------|---------------|
| `watcher_url` | Base URL of Watcher instance (e.g., `https://watcher.local:9002`) | String | Yes | - |
| `watcher_api_key` | API authentication token for Watcher | String | Yes | - |
| `the_hive_custom_field` | Custom field name storing the Watcher ticket ID | String | Yes | `watcher-id` |

**Example Configuration:**

```json
{
  "watcher_url": "https://watcher.example.com:9002",
  "watcher_api_key": "your-api-token-here",
  "the_hive_custom_field": "watcher-id"
}
```

---

### Tag-Based Routing

#### **Required Tag for ALL Responders**

```
watcher:module = LegitDomain | WebsiteMonitoring
```

#### **Module-Specific Tags**

##### **LegitDomain Module**

| Tag | Values | Required | Description |
|---------------------------|-----------------|------------------|---------------------------------|
| `watcher:repurchased` | `Yes` / `No` | Add: ✅ Yes | Domain repurchase status |
| | | Update: ❌ No | |
| | | Transfer: ✅ Yes | |
| `watcher:contact` | Email address | ❌ No | Contact email |

##### **WebsiteMonitoring Module**

| Tag | Values | Required | Description |
|------------------------------|---------------|------------------|---------------------------------|
| `watcher:legitimacy` | `2` to `6` | Add: ✅ Yes | Threat level (see table below) |
| | | Update: ❌ No | |
| | | Transfer: ✅ Yes | |
| `watcher:takedown_request` | `Yes` / `No` | ❌ No | Request takedown |
| `watcher:legal_team` | `Yes` / `No` | ❌ No | Notify legal team |
| `watcher:blocking_request` | `Yes` / `No` | ❌ No | Request blocking |

**Legitimacy Score Values:**
| Score | Meaning | Color |
|-------|------------------------------------------------|-----------|
| `2` | Suspicious, not harmful | Yellow |
| `3` | Suspicious, likely harmful (registered) | Orange |
| `4` | Suspicious, likely harmful (available/disabled)| Orange |
| `5` | Malicious (registered) | Red |
| `6` | Malicious (available/disabled) | Red |

---

### API Endpoints Used

#### Legitimate Domain Module

```
GET    /api/common/legitimate_domains/?search={domain}  # Search domain
POST   /api/common/legitimate_domains/                  # Create new domain
PATCH  /api/common/legitimate_domains/{id}/             # Update domain
DELETE /api/common/legitimate_domains/{id}/             # Remove domain
```

#### Website Monitoring Module

```
GET    /api/site_monitoring/site/                       # List monitored sites
POST   /api/site_monitoring/site/                       # Add site to monitoring
PATCH  /api/site_monitoring/site/{id}/                  # Update monitored site
DELETE /api/site_monitoring/site/{id}/                  # Remove from monitoring
```

---

### Best Practices

1. **Always set `watcher:module` tag** before running responders
2. **Use taxonomy import** for consistent tag naming
3. **Transfer operations**: Tag indicates DESTINATION module
4. **Update operations**: Only include tags for fields you want to change
5. **Legitimacy scoring**: Choose appropriate level based on threat assessment

---

### Support

For issues, questions, or feature requests:

- **GitHub Issues**: [Watcher Repository](https://github.com/thalesgroup-cert/Watcher/issues)

---

### Authors

**Thales Group CERT** - [thalesgroup-cert on GitHub](https://github.com/thalesgroup-cert)
**Ygal NEZRI** - [@ygalnezri](https://github.com/ygalnezri)
