# Check Point Harmony Email & Collaboration (HEC) Responders

Take actions on emails in Check Point Harmony Email & Collaboration: quarantine or restore emails directly from TheHive.

---

## Pre-requisites

1. A Check Point Infinity Portal account with Harmony Email & Collaboration enabled.
2. An **Account API Key** (Client ID + Secret Key) created in the Infinity Portal:
   - Navigate to **Global Settings > API Keys**.
   - Create a key scoped to **Email & Collaboration**.
   - Note: **User API keys are not supported**; only account-level keys work with the HEC API.

---

## Configuration

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `client_id` | Infinity Portal API Client ID | Yes | N/A |
| `client_secret` | Infinity Portal API Secret Key | Yes | N/A |
| `region` | Portal region: `us`, `eu`, `ca`, `au`, `uk`, `uae`, `in`, `sg` | Yes | `eu` |
| `saas` | SaaS platform: `office365_emails` or `google_mail` | Yes | `office365_emails` |

---

## Responders Overview

### 1. Quarantine

- **Observable type**: `file` (.eml)
- **Description**: Extracts the Message-ID from an .eml file, finds the email in HEC, and quarantines it.

### 2. Restore

- **Observable type**: `file` (.eml)
- **Description**: Extracts the Message-ID from an .eml file, finds the email in HEC, and restores (resends) it to the recipient.

### 3. QuarantineByMessageId

- **Observable type**: `other` (text containing a Message-ID)
- **Description**: Quarantines an email by its raw Message-ID string such as `<abc@example.com>`. Useful when the Message-ID is available as a text observable rather than a full .eml file.

---

## Forwarded email handling

The Quarantine and Restore responders (which work from .eml files) **automatically detect** forwarded emails. When an email is reported by a user to a security mailbox and imported into TheHive, the .eml is a forwarded envelope where the reporter appears as the sender. The responder looks for an attached original email (`message/rfc822` MIME part) inside the .eml and uses the inner message's Message-ID to find the correct email in HEC. If no inner message is found, it falls back to the outer envelope. This requires no configuration.

---

## Action verification

HEC actions are **asynchronous**: the API queues a task and returns a task ID. Each responder polls the HEC task API (up to 60 seconds) and reports the real outcome:

- **completed**: the action finished; the report includes `succeed`/`failed` counts and any per-action messages from HEC, such as "Message is not quarantined".
- **failed**: if every email failed, the responder job fails with the HEC error messages.
- **queued**: the task did not finish within the polling window; the report says so explicitly and asks you to verify in the Infinity Portal.

---

## Operations

All responders tag the observable with the action performed:

- `CheckPointHEC:quarantine`
- `CheckPointHEC:restore`
- `CheckPointHEC:quarantine_by_message_id`

---

## Companion Analyzers

See `analyzers/CheckPointHEC/README.md` for the corresponding analyzers that retrieve security verdicts and email details from HEC.


