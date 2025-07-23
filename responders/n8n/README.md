# n8n Responder for Cortex

This responder sends data from [TheHive Cortex](https://github.com/TheHive-Project/Cortex) to an [n8n](https://n8n.io/) workflow via a webhook URL. It supports case, alert, observable, task, and task log data types.

## Overview

- Name: `n8n`
- License: AGPLv3
- Version: 1.0
- Repository: [Cortex-Analyzers](https://github.com/TheHive-Project/Cortex-Analyzers)

## Supported Data Types

- `thehive:case`
- `thehive:alert`
- `thehive:case_artifact`
- `thehive:case_task`
- `thehive:case_task_log`


## Configuration

In the Cortex UI:

1. Go to **Organization > Responders**.
2. Locate and enable `n8n`.
3. Set the required configuration parameter:

| Name            | Type   | Required | Description                          |
|-----------------|--------|----------|--------------------------------------|
| `webhook` | string | Yes      | The full URL of the n8n workflow webhook  |

Example value:  
`http(s)://your.n8n_instance.com/webhook/abc123`
