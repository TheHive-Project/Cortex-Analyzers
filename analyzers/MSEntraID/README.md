# Microsoft Entra ID / Azure AD Analyzers

This repository provides a set of **Cortex** analyzers to enrich your investigations in TheHive with data from Microsoft Entra ID (Azure AD). All analyzers use the **Microsoft Graph API** for data retrieval. Each analyzer requires an Azure AD **app registration** (client ID + secret) with **admin-consented** permissions (OAuth2 scopes).

---

## Table of Contents

1. [Overview of Analyzers](#overview-of-analyzers)  
2. [Global Configuration](#global-configuration)  
3. [Setup](#setup)  
        - [Prereqs](#prereqs)  
        - [Steps](#steps)  
4. [Analyzers](#analyzers)  
        - [getSignIns / Microsoft Entra ID Sign In Retriever](#getsignins--microsoft-entra-id-sign-in-retriever)  
        - [getUserInfo](#getuserinfo)  
        - [getDirectoryAuditLogs](#getdirectoryauditlogs)  
        - [getManagedDevicesInfo](#getmanageddevicesinfo-requires-ms-intune)  
5. [Customization](#customization)  
6. [General Notes on Permissions](#general-notes-on-permissions)  
7. [References](#references)

---

## Overview of Analyzers

These analyzers provide useful context for Incident Response teams, such as:

- **Sign-in logs** (location, risk, IP, etc.)
- **User profile details** (manager, licenses, groups, MFA methods)
- **Directory audit logs** (object changes in Azure AD)
- **Intune-managed devices** (compliance, OS, last sync)

---

## Global Configuration

All analyzers share these config fields:

- **`client_id`**: Application (client) ID of your Azure AD app registration  
- **`client_secret`**: Client Secret generated for that app  
- **`tenant_id`**: Azure AD Tenant ID  
- **`service`**: Which analyzer action to run, hardcoded (such as `getSignIns`, `getUserInfo`, `getDirectoryAuditLogs`, `getManagedDevicesInfo`)  

Additional parameters (such as **lookup_range**, **lookup_limit**, **state**, **country**) appear in certain analyzers. They allow you to define:

- **Time range** (how far back to query logs)
- **Max results** (number of records to retrieve)
- **Location-based taxonomies** (flag sign-ins from out-of-state/country)

---

## Setup

### Prereqs
- A user account with at least the **Cloud Application Administrator** role to create and manage app registrations.
- A user account with the **Global Administrator** role to grant admin consent to the required API permissions.

### Steps

#### 1. Creation
1. Navigate to the [Microsoft Entra ID Portal](https://entra.microsoft.com/) and sign in with an administrator account.  
2. Go to **App Registrations** and **create a new registration**.  
3. Provide a display name (any name you want, can be changed later). Click **Register**.

#### 2. Secret
4. Under **Certificates & secrets**, create a new **client secret**.  
5. Enter a relevant description and set an appropriate expiration date.  
6. Copy the **Value**. **This will only be fully visible once**, so store it in a safe place right away.

#### 3. API Permissions
7. Go to **API permissions**.  
8. Add the relevant permissions depending on which analyzers you plan to use, for example:  
   - **`Directory.Read.All`**  
   - **`AuditLog.Read.All`**  
   - **`DeviceManagementManagedDevices.Read.All`** (Intune analyzers)
   - **`UserAuthenticationMethod.Read.All`** (if fetching MFA)  
9. For each **Application** permission, use a **Global Administrator** account to **Grant admin consent**.  
10. Copy your **Tenant ID**, **Application (Client) ID**, and the **Client Secret** into the analyzer configuration in Cortex.

---

## Analyzers

### getSignIns / Microsoft Entra ID Sign In Retriever

**Purpose**  
Retrieves recent **sign-in logs** for a user (by UPN). Shows IP address, client app used, resource name, location, risk level, etc.

**Key Points**  
- **Graph Endpoint**  
- [`GET /auditLogs/signIns`](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0)  
- Filters sign-ins by user principal name (`startswith(userPrincipalName,'xxx')`) and time range.  
- You can specify a **`state`** and **`country`**; sign-ins from outside these will be flagged in **taxonomies**.

**Required Permissions**

- **`AuditLog.Read.All`** (Application permission)

**Example Configuration**

- **lookup_range** = 7 (past 7 days)  
- **lookup_limit** = 50  
- **state** = "New York" (to flag out-of-state sign-ins)  
- **country** = "US" (to flag out-of-country sign-ins)

**Sample Usage**

- Run on TheHive’s observable of type `mail`
- Analyzer returns sign-ins from the last 7 days, up to 50 entries.

### getUserInfo

**Purpose**  
Enriches context around a user with **user profile details** from Microsoft Entra ID: display name, job title, department, licenses, manager, group memberships, optional MFA methods.

**Key Points**  
- **Graph Endpoints**  
- [`GET /users/{id}`](https://learn.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0)  
- [`GET /users/{id}/manager`](https://learn.microsoft.com/en-us/graph/api/user-list-manager?view=graph-rest-1.0)  
- [`GET /users/{id}/licenseDetails`](https://learn.microsoft.com/en-us/graph/api/user-list-licensedetails?view=graph-rest-1.0)  
- [`GET /users/{id}/memberOf`](https://learn.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0)  
- (Optional) [`GET /users/{id}/authentication/methods`](https://learn.microsoft.com/en-us/graph/api/user-list-authenticationmethods?view=graph-rest-1.0) for MFA.

**Required Permissions**  
- **`Directory.Read.All`** or **`User.Read.All`** for user properties & group membership.  
- **`UserAuthenticationMethod.Read.All`** if retrieving MFA methods.

**Sample Usage**

- Run on TheHive’s observable of type `mail`
- Returns extensive user info, including manager info, assigned licenses, group memberships, etc.

### getDirectoryAuditLogs

**Purpose**  
Retrieves **Directory Audit** records—administrative and policy changes made within Azure AD (such as user updates, group changes, role assignments).

**Key Points**  
- **Graph Endpoint**  
- [`GET /auditLogs/directoryAudits`](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0)  
- Filters on **time range** via `activityDateTime ge <timestamp>`  
- Filters on specific user input as observable, thanks to `initiatedBy/user/userPrincipalName eq 'mail@observable.com'`.

**Required Permissions**  
- **`AuditLog.Read.All`** (Application permission)

**Sample Usage**

- Run on TheHive’s observable of type `mail` 
- Analyzer fetches directory audit logs for that user over the last X days.

### getManagedDevicesInfo (requires MS Intune)

**Purpose**  
Returns **Intune-managed devices** for a given user’s principal name or hostname, letting IR see device compliance, OS, last check-in, etc.

**Key Points**  
- **Graph Endpoint**  
- [`GET /deviceManagement/managedDevices`](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0)  
- Filters with `startswith(userPrincipalName,'xxx')` or an exact match (`eq`), with observable value.

**Required Permissions**  
- **`DeviceManagementManagedDevices.Read.All`** (Application permission)

**Sample Usage**

- Run on TheHive’s observable of type `mail` or `hostname`
- Analyzer returns a list of Intune devices assigned to that user.

---

## Customization

### Sign-Ins Table Color Coding

In **TheHive**, the analyzer’s *long report* can be customized to highlight sign-ins with certain risk or unusual locations. For instance:

- **Yellow** for out-of-state sign-ins  
- **Red** for foreign sign-ins  

To do this, modify **`long.html`** for the analyzer (Sign In). For example, use `ng-style` or custom logic to check values in the JSON (like `location.state` or `riskLevel`). A sample snippet might be commented out at line 34 of `long.html` (if provided in your code), which you can adapt to your color preferences.

---

## General Notes on Permissions

- **Application (Client Credentials) Flow**  
    - These analyzers typically use `.default` scope and **client credentials**.  
    - Ensure you **Grant admin consent** for the required permissions in Azure AD.

- **Minimal Scopes**  
    - If you want all analyzers to function, add each relevant scope (such as `AuditLog.Read.All`, `Directory.Read.All`, `DeviceManagementManagedDevices.Read.All`, `UserAuthenticationMethod.Read.All`) to the same app registration.  
    - Alternatively, create separate app registrations to follow least-privilege principles.

- **Licensing**  
    - Some features (such as Identity Protection, advanced audit logs) require Azure AD Premium licensing.

---

## References

- [Microsoft Graph Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference?view=graph-rest-1.0)  
- [Azure AD Permissions & Admin Consent](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-permissions-and-consent)  
- [Microsoft Graph Query Parameters](https://learn.microsoft.com/en-us/graph/query-parameters?view=graph-rest-1.0)  
- [Sign In Logs (auditLogs/signIns)](https://learn.microsoft.com/en-us/graph/api/signin-list?view=graph-rest-1.0)  
- [Directory Audits (auditLogs/directoryAudits)](https://learn.microsoft.com/en-us/graph/api/directoryaudit-list?view=graph-rest-1.0)  
- [Managed Devices (deviceManagement/managedDevices)](https://learn.microsoft.com/en-us/graph/api/intune-devices-manageddevice-list?view=graph-rest-1.0)