#!/usr/bin/env python3
# encoding: utf-8
import re
import requests
from cortexutils.responder import Responder

GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
                    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")


class MSExchangeOnline_RemoveInboxRule(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.client_id = self.get_param('config.client_id', None, 'Microsoft Entra ID Application ID/Client ID Missing')
        self.client_secret = self.get_param('config.client_secret', None, 'Microsoft Entra ID Registered Application Client Secret Missing')
        self.tenant_id = self.get_param('config.tenant_id', None, 'Microsoft Entra ID Tenant ID Missing')

        self.custom_field_name = self.get_param('config.custom_field_name', 'inbox-rule-input')

        raw_field = self.get_param(f'data.customFields.{self.custom_field_name}', None,
                                    f'Case custom field "{self.custom_field_name}" is missing')
        # Custom fields are delivered as {"string": "<value>"} (or another type key)
        self.rule_input = next(iter(raw_field.values())) if raw_field else None

    def authenticate(self):
        token_data = {
            "grant_type": "client_credentials",
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'scope': 'https://graph.microsoft.com/.default'
        }
        redirect_uri = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"
        token_r = requests.post(redirect_uri, data=token_data)
        if token_r.status_code != 200:
            self.error(f'Failure to obtain Azure access token: {token_r.content}')
        return token_r.json().get('access_token')

    def resolve_user_guid(self, identifier, headers, base_url):
        if GUID_RE.match(identifier):
            return identifier
        quoted = identifier.replace("'", "''")
        filter_q = f"(userPrincipalName eq '{quoted}') or (mail eq '{quoted}')"
        resp = requests.get(f"{base_url}users", headers=headers,
                             params={"$filter": filter_q, "$select": "id"})
        if resp.status_code != 200:
            self.error(f"[GUID-lookup] HTTP {resp.status_code}: {resp.text}")
        users = resp.json().get("value", [])
        if not users:
            self.error(f"No user matches '{identifier}'")
        return users[0]["id"]

    def run(self):
        Responder.run(self)

        if not self.rule_input or "|" not in self.rule_input:
            self.error(f'Custom field "{self.custom_field_name}" must be formatted as "<mailboxUPN>|<ruleId>"')

        upn, rule_id = self.rule_input.split("|", 1)
        upn, rule_id = upn.strip(), rule_id.strip()

        token = self.authenticate()
        headers = {
            'Authorization': f'Bearer {token}',
            'User-Agent': 'strangebee-thehive/1.0'
        }
        base_url = 'https://graph.microsoft.com/v1.0/'

        guid = self.resolve_user_guid(upn, headers, base_url)
        rule_url = f"{base_url}users/{guid}/mailFolders/inbox/messageRules/{rule_id}"

        get_r = requests.get(rule_url, headers=headers)
        if get_r.status_code == 404:
            self.report({'message': f'Rule {rule_id} no longer exists on {upn} (already removed?)'})
            return
        if get_r.status_code != 200:
            self.error(f"Failed to fetch rule {rule_id} for {upn}: {get_r.content}")

        rule_name = get_r.json().get('displayName', rule_id)

        del_r = requests.delete(rule_url, headers=headers)
        if del_r.status_code != 204:
            self.error(f"Failed to remove rule '{rule_name}' ({rule_id}) for {upn}: {del_r.content}")

        self.rule_name = rule_name
        self.upn = upn
        self.report({'message': f'Removed inbox rule {rule_name} ({rule_id}) from {upn}'})

    def operations(self, raw):
        upn = getattr(self, "upn", "unknown")
        rule_name = getattr(self, "rule_name", "unknown")
        return [self.build_operation('AddTagToCase', tag=f'MSExchangeOnline:RuleRemoved:{upn}:{rule_name}')]


if __name__ == '__main__':
    MSExchangeOnline_RemoveInboxRule().run()
