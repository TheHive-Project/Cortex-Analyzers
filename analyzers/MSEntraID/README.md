## Microsoft Entra ID Sign In Retriever

This responder allows you to revoke the session tokens for an Microsoft Entra ID user. Requires the UPN of the account in question, which should be entered as a "mail" oberservable in TheHive. 

### Config

To enable the responder, you *need* three values:
1. Microsoft Entra ID Tenant ID
2. Application ID
3. Application Secret

The first two values can be found at any time in the application's Overview page in the Microsoft Entra ID portal. The secret must be generated and then stored in a safe place, as it is only fully visible when you first make it. 

You can also specify the limits for how far back the analyzer requests sign ins. You can specify time and count for how many sign ins get returned.

Finally, you can specify a state and country/region. These are used as taxonomies. If you run a query on a particular user and they return a few out-of-state sign ins, a taxonomy label will be added to the observable to reflect that. Likewise for the country/region. By default, this analyzer does not support selecting multiple states or countries, so if you have more than one that users will be signing in to, feel free to leave them blank. If the value is not configured, then the analyzer will simply not use the taxonomies. 

## Setup

### Prereqs
User account with the Cloud Application Administrator role.
User account with the Global Administrator Role (most of the steps can be done with only the Cloud App Administrator role, but the final authorization for its API permissions requires GA).

### Steps

#### Creation
1. Navigate to the [Microsoft Entra ID Portal](https://entra.microsoft.com/) and sign in with the relevant administrator account.
2. Navigate to App Registrations, and create a new registration.
3. Provide a display name (this can be anything, and can be changed later). Click Register.

#### Secret
4. Navigate to Certificates and Secrets.
5. Create a new client secret. Enter a relevant description and set a security-conscious expiration date.
6. Copy the Value. **This will only be fully visible for a short time, so you should immediately copy it and store it in a safe place**.

#### API Permissions
7. Navigate to API permissions.
8. Add the Directory.Read.All, AuditLog.Read.All, and Policy.Read.ConditionalAccess permissions (Microsoft Graph API, application permissions).
9. Using a GA account, select the "Grant admin consent for *TENANTNAME*" button.

10. Place the relevant values into the config within Cortex.

## Customization

It is possible to add a color coding system to the long report as viewed from TheHive. Specifically, you can color code the Sign Ins table so that certain ones stand out.

### Example

Let's say you are in an organization where almost all of your users will be signing in from a single state. You could color code the table so that out-of-state sign ins are highlighted yellow, and out-of-country sign ins are highlighted in red. To enable customization like this, you must modify this analyzer's long.html to check for values within the full JSON report using the ng-style tag in the *table body > table row* element. An example exists as a comment in the long.html file at line 34.