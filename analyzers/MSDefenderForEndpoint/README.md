# MSDefenderForEndpoint Analyzer

Queries Microsoft Defender for Endpoint (MDE) to enrich observables with endpoint telemetry:
device risk/exposure/health, and file hash prevalence and related alerts within your organization.

Two flavors share the same Azure AD app registration:

- **DeviceLookup**: `ip` or `fqdn` → device risk score, exposure level, health status, OS platform and related alerts.
- **HashReputation**: `hash` (SHA1 or SHA256 only) → organization prevalence and related alerts.

## Requirements

1. In Azure AD, register an application (App registrations).
2. Grant it **Application** permissions on the `WindowsDefenderATP` API:
   - `Machine.Read.All`
   - `Alert.Read.All`
   - `File.Read.All`
3. Grant admin consent for these permissions.
4. Create a client secret for the application.
5. Note the tenant ID, client (application) ID, and client secret.

## Configuration

| Parameter       | Description                                    | Required |
|-----------------|-------------------------------------------------|----------|
| `tenant_id`     | Azure AD tenant ID                              | Yes      |
| `client_id`     | Azure AD application (client) ID                | Yes      |
| `client_secret` | Azure AD application client secret              | Yes      |

## Supported Observable Types

- **DeviceLookup**: `ip`, `fqdn`
- **HashReputation**: `hash` (only SHA1/SHA256 — MD5 is not supported by the MDE files API)

## Output

### DeviceLookup

- `MDE:RiskScore="None|Low|Medium|High"` — mapped to `info`/`safe`/`suspicious`/`malicious`
- `MDE:Alerts="<count>"` (`suspicious`) when the device has related alerts
- `MDE:Device="NotFound"` (`info`) when no matching device is found

### HashReputation

- `MDE:Alerts="<count>"` — `malicious` if any related alert has High severity, `suspicious` for
  Medium/Low/Informational alerts, `safe` if the file was seen but has no alerts, `info` otherwise
- `MDE:OrgPrevalence="<count>"` — how many devices in your organization have seen this file
- `MDE:File="NotSeen"` (`info`) when the hash is unknown to Microsoft Defender for Endpoint
