## Microsoft Entra ID Responders

These responders provide various user management capabilities for Microsoft Entra ID, including revoking session tokens, enabling/disabling users, and enforcing password resets.

### Available Responders

- **Revoke Sign-In Sessions (`revokeSignInSessions`)** – Invalidates all the refresh tokens issued to applications for a Microsoft Entra ID user (as well as session cookies in a user's browser).

- **Password Reset (`forcePasswordReset`)** – Forces a password reset at the next login.

- **Password Reset with MFA (`forcePasswordResetWithMFA`)** – Forces a password reset at the next login, requiring multi-factor authentication (MFA) before changing the password.

- **Enable User (`enableUser`)** – Enables a previously disabled user account.

- **Disable User (`disableUser`)** – Disables a user account, preventing further sign-ins.


### Configuration

To enable the responder, you need three values:

1. **Microsoft Entra ID Tenant ID**
2. **Application ID**
3. **Application Secret**

The first two values can be found at any time in the application's ***Overview*** page in the [Microsoft Entra ID Portal](https://entra.microsoft.com/). The secret must be generated and then stored in a safe place, as it is only fully visible when you first make it.

## Setup

### Pre-requisites
 - User account with the **Cloud Application Administrator** role.
 - User account with the **Global Administrator Role** (most of the steps can be done with only the Cloud App Administrator role, but the final authorization for its API permissions requires GA).

### Steps

#### Creation
1. Navigate to the [Microsoft Entra ID Portal](https://entra.microsoft.com/) and sign in with the relevant administrator account.
2. Navigate to App Registrations, and create a new registration.
3. Provide a display name (this can be anything, and can be changed later). Click Register.

#### Secret
4. Navigate to **Certificates and Secrets**.
5. Create a new client secret. Enter a relevant description and set a security-conscious expiration date.
6. Copy the Value. **This will only be fully visible for a short time, so you should immediately copy it and store it in a safe place**.

#### API Permissions
7. Navigate to **API permissions**.
8. Add the following Microsoft Graph API application permissions:
   - **Option A (Broader Permissions):**
     - `Directory.ReadWrite.All`
     - `User.ReadWrite.All`
     
     *(These permissions cover all responder functionalities.)*
     
   - **Option B (Least Privileged – Recommended):**
     - For the **Revoke SignIn Sessions** responder: `User.RevokeSessions.All`
     - For the **Enable User** and **Disable User** responders:
       - `User.EnableDisableAccount.All`
       - `User.Read.All`
     - For the **Password Reset** responders: `User-PasswordProfile.ReadWrite.All`

9. Using a Global Administrator account, click the "`Grant admin consent for [TENANTNAME]`" button.
10. Enter the corresponding values (`tenant_id`, `client_id`, `client_secret`) into your responders Cortex configuration.

*Note: For enhanced security, it is recommended to use the least privileged permissions (Option B) that are sufficient for your use case. Please refer to the [Microsoft Graph Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference) for further details.*


### References

- [Microsoft Graph API - Revoke Sign-In Sessions](https://learn.microsoft.com/en-us/graph/api/user-revokesigninsessions?view=graph-rest-1.0)

- [Microsoft Graph API - Update User](https://learn.microsoft.com/en-us/graph/api/user-update?view=graph-rest-1.0&tabs=http)

- [Microsoft Graph Permissions Reference](https://learn.microsoft.com/en-us/graph/permissions-reference)