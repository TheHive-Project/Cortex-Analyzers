## Azure Sign In Token Revoker Responder

This responder allows you to revoke the session tokens for an Azure AD user. Requires the UPN of the account in question, which should be entered as a "mail" oberservable in TheHive. 

### Config

To enable the responder, you need three values:
1. Azure Tenant ID
2. Application ID
3. Application Secret

The first two values can be found at any time in the application's Overview page in the Azure portal. The secret must be generated and then stored in a safe place, as it is only fully visible when you first make it. 

## Setup

### Prereqs
User account with the Cloud Application Administrator role.
User account with the Global Administrator Role (most of the steps can be done with only the Cloud App Administrator role, but the final authorization for its API permissions requires GA).

### Steps

#### Creation
1. Navigate to the [Azure Portal](https://portal.azure.com) and sign in with the relevant administrator account.
2. Navigate to App Registrations, and create a new registration.
3. Provide a display name (this can be anything, and can be changed later). Click Register.

#### Secret
4. Navigate to Certificates and Secrets.
5. Create a new client secret. Enter a relevant description and set a security-conscious expiration date.
6. Copy the Value. **This will only be fully visible for a short time, so you should immediately copy it and store it in a safe place**.

#### API Permissions
7. Navigate to API permissions.
8. Add the Directory.ReadWrite.All and User.ReadWrite.All permissions (Microsoft Graph API, application permissions).
9. Using a GA account, select the "Grant admin consent for *TENANTNAME*" button.

10. Place the relevant values into the config within Cortex.