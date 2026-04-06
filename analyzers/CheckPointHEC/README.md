# Check Point Harmony Email & Collaboration (HEC) Analyzers

Query the Check Point Harmony Email & Collaboration platform to retrieve security verdicts, phishing classification, and scan results for emails.

---

## Pre-requisites

1. A Check Point Infinity Portal account with Harmony Email & Collaboration enabled.
2. An **Account API Key** (Client ID + Secret Key) created in the Infinity Portal:
   - Navigate to **Global Settings > API Keys**.
   - Create a key scoped to **Email & Collaboration**.
   - Note: **User API keys are not supported** — only account-level keys work with the HEC search API.

---

## Configuration

| Parameter | Description | Required | Default |
|-----------|-------------|----------|---------|
| `client_id` | Infinity Portal API Client ID | Yes | — |
| `client_secret` | Infinity Portal API Secret Key | Yes | — |
| `region` | Portal region: `us`, `eu`, `ca`, `au`, `uk`, `uae`, `in`, `sg` | Yes | `eu` |
| `saas` | SaaS platform to query: `office365_emails` or `google_mail` | Yes | `office365_emails` |

---

## Analyzers Overview

### 1. SearchEmail

- **Observable type**: `file` (.eml)
- **Description**: Extracts the Message-ID from an .eml file, searches for the email in HEC, and returns full details including security verdicts, email metadata, links, and status flags.

#### Forwarded email handling

When emails are reported by users to a security mailbox and then imported into TheHive, the .eml is typically a forwarded envelope where the reporter appears as the sender. This analyzer **automatically detects** if the .eml contains an attached original email (`message/rfc822` MIME part) and extracts the Message-ID from the inner message instead. If no inner message is found, it falls back to the outer envelope's Message-ID. This requires no configuration — it works transparently.

#### Report includes
- Email metadata: subject, sender, recipients, date, size, attachments
- Sender IPs (server and client)
- Email status: direction, quarantined, restored, deleted, user exposed
- Security verdicts from all engines: Anti-Phishing, Anti-Virus, DLP, Click-Time Protection, Shadow IT
- Anti-Phishing scan details with detection reasons
- SPF result and SaaS spam verdict
- Email links and link domains
- Available actions and action history

#### Extracted artifacts
- Sender email address (`mail`)
- Sender domain (`domain`)
- Sender server and client IPs (`ip`)
- URLs found in the email (`url`)
- Link domains (`domain`)

All artifacts are tagged with the HEC verdict (e.g. `CPHEC:verdict=phishing`).

---

### 2. SearchBySender

- **Observable type**: `mail` or `file` (.eml)
- **Description**: Searches HEC for all emails from a given sender address. Returns a count, verdict breakdown, and a list of all matching emails with their verdicts and status. When run on an .eml file, the sender address is extracted automatically (with forwarded email unwrapping).

Useful for assessing whether a sender is a repeat offender or broadly compromised.

---

### 3. SearchByDomain

- **Observable type**: `domain` or `file` (.eml)
- **Description**: Searches HEC for all emails from a given sender domain. Returns the same result structure as SearchBySender. When run on an .eml file, the sender domain is extracted automatically (with forwarded email unwrapping).

Useful for evaluating domain-level reputation across the mailbox estate.

---

### 4. SearchByURL

- **Observable type**: `url`
- **Description**: Searches HEC for all emails containing a specific URL. Returns matching emails with their verdicts and exposure status.

Critical during phishing campaigns to gauge blast radius — how many users received an email with that link, how many read it, how many are still exposed.

---

### 5. SearchBySenderIP

- **Observable type**: `ip` or `file` (.eml)
- **Description**: Searches HEC for all emails sent from a given server IP. When run on an .eml file, the sender IP is extracted from the first `Received` header (with forwarded email unwrapping), skipping private IPs when possible.

Useful when sender addresses rotate but the sending infrastructure stays the same.

---

## Resources

- [Check Point Harmony Email & Collaboration](https://www.checkpoint.com/harmony/email-collaboration/)
- [Infinity Portal API documentation](https://app.swaggerhub.com/apis/Check-Point/harmony-email-collaboration)
