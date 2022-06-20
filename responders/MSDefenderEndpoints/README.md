### Cortex responder for Microsoft Defender for Endpoints (formerly know as Microsoft ATP)

#### With this responder you can

* Isolate machine
* Unisolate machine
* Run full antivirus scan
* Push IoC to Microsoft defender
  * Alert
  * BlockAndAlert
* (future: Collect investigation package)

**NOTE: Microsft API for finding machines via IP-addresses is little bit limited "Find Machines seen with the requested internal IP in the time range of 15 minutes prior and after a given timestamp.", because of this "hostname" is preferable observable type"**

Responder needs one of the following licenses:

* Windows 10 Enterprise E5
* Microsoft 365 E5 (M365 E5) which includes Windows 10 Enterprise E5
* Microsoft 365 E5 Security

##### In general, you’ll need to take the following steps to use the responder

* Create an Azure AD application
* Grant permissions to App

##### Steps

With your Global administrator credentials, login to the Azure portal.   
* Azure Active Directory > App registrations > New registration.

In the registration form:

* Name - Name your application.
* Supported account type – leave the default setting.
* Redirect Uri – leave empty.

##### API permission

On your new application page, click API Permissions > Add permission > APIs my organization uses > type **WindowsDefenderATP** and click on WindowsDefenderATP
Choose Application permissions, select **Alert.Read.All** AND **TI.ReadWrite.All** AND **Machine.ReadAll** AND **Machine.Isolate** AND **Machine.Scan** > Click on Add permissions.

After clicking the Add Permissions button, on the next screen we need to grant consent for the permission to take effect.
Press the "Grant admin consent for {your tenant name}" button.

To get client credentials:

* In your application page, Click Certificate & Secrets
* Specify a key description and set an expiration for 1 year.
* Click Add and the application key will appear.

**IMPORTANT: Copy and store this key in a safe place. Treat it like a password.**

##### Detailed permissions:
![Permissions](assets/thehive_integration.jpg)

[How to create Azure App (link to MS blog)](https://techcommunity.microsoft.com/t5/microsoft-defender-for-endpoint/wdatp-api-hello-world-or-using-a-simple-powershell-script-to/ba-p/326813)
