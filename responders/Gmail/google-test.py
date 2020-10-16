#!/usr/bin/env python3

from google.oauth2 import service_account

scopes = [
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/gmail.settings.basic",
]
subject = "thedelegatedemail@gmail.com"
def authenticate(service_account_file, scopes, subject):
    """Peforms OAuth2 auth for a given service account, scope and a delegated subject

    Args:
        service_account_file (str): Path to the service account file
        scopes (array): array of oauth2 scopes needed to operate
        subject (str): email adress of the user, whos data shall be accessed (delegation)

    Returns:
        google.auth.service_account.Credentials if valid otherwise None
    """
    credentials = service_account.Credentials.from_service_account_file(
        service_account_file,
        scopes=scopes,
       subject=subject
    )

    if (credentials.valid) and (credentials.has_scopes(scopes)):
        return credentials
    else:
        return None

check = authenticate("/path/to/service_account.json", scopes, subject)

if (check is not None):
    print("Authentication worked")
else:
    print(check)
