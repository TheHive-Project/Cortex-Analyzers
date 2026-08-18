# Microsoft Defender for Office 365 Analyzers

This repository provides a set of **Cortex** analyzers related to Microsoft Defender for Office 365 (MDO).

---

## Overview of Analyzers

### SafeLinksDecoder

**Purpose**
Decodes Microsoft Office 365 ATP Safe Links to extract the original destination URL. Safe Links is Microsoft's URL-wrapping service: outbound/inbound links are rewritten to point through a `*.safelinks.protection.outlook.com` gateway so they can be checked at time of click.

**Key Points**
- No API call, no credentials, no registration required — purely local URL parsing/decoding.
- Detects a Safe Link by checking the URL's **host** (not just a substring anywhere in the URL) ends with `safelinks.protection.outlook.com`.
- Tries several known wrapping patterns (`?url=`, `?data=`) and handles double URL-encoding (common in forwarded emails).
- Creates `url` and `domain` artifacts for the decoded destination, so analysts can pivot on the real target.

**Required Permissions**
- None. This analyzer does not call any Microsoft API.

**Sample Usage**
- Run on TheHive's observable of type `url`.
- If the observable isn't a Safe Link, the analyzer reports that explicitly (not an error).
- If it is a Safe Link but no known wrapping pattern matches, the analyzer errors out.

---

## References

- [Safe Links overview](https://learn.microsoft.com/en-us/defender-office-365/safe-links-about)
