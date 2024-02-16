### Gmail responder
This responder allows mailbox manipulation of Gsuite / Google Workspace accounts. The responder
can be used to implement message filters and delete message in a mailbox of a Gmail user.

**Usage:**
- You can block `mail` and `domain` observables
- Operations are carried out against all gmail addresses (dataType `mail`) in the case
  - Example: `john.doe@gmail.com` or `peter.parker@custom.domain`
  - Custom domain can be set in the responder config
- The _message ID_ of deleted messages is added as tag to the respective gmail address (dataType `mail`)
  - Messages can only be deleted via Gmail query syntax (datatype `other`); this enables one to bulk delete a lot of messages
- The _filter ID_ of a blocked `domain` or `mail` gets added as tag to respective gmail address (dataType `mail`)
- All observables that get blocked/unblocked get a `gmail:handled` tag

**Constrains:**
 - TheHive API key needs to provide **read** AND **write** permissions
 - The Gmail user **MUST** be part of a Gsuite domain.
 - Gsuite domain **MUST** have an _service account_ enabled with domain-wide delegation.
 - The _service account_ **MUST** be configured with the following OAuth Scopes:
    - `https://mail.google.com/`
    - `https://www.googleapis.com/auth/gmail.settings.basic`

#### How to setup a Gmail service account

The responder needs a Gmail _service account_ with domain-wide delegation. The rough setup steps are:
1. enable a _service account_ via GCP
2. enable Gmail API
3. get service account `client_id` (_oauth approval screens + domain-wide delegation needed_)
4. change to Gsuite Admin panel
5. add third party app (security->API controls) with `client_id`
6. add domain-wide delegation with `client_id`

A detailed guideline for a _service account_ setup can be found in the [Google OAuth Python Client Docs](https://github.com/googleapis/google-api-python-client/blob/master/docs/oauth-server.md).
