#!/usr/bin/env python3
# encoding: utf-8
import requests
import traceback
import re
from cortexutils.analyzer import Analyzer

GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
                    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")

# Keywords used by attackers to hide security warnings from the mailbox owner
SECURITY_KEYWORDS = [
    "phish", "hack", "spam", "suspicious", "fraud", "scam", "malware",
    "virus", "password", "compromise", "breach", "security", "do not reply",
    "helpdesk", "sign-in", "sign in", "signin", "unusual activity",
]

# Keywords used to intercept financial threads (invoice fraud)
FINANCIAL_KEYWORDS = [
    "invoice", "payment", "wire", "ach", "swift", "iban", "bank", "banking",
    "statement", "remittance", "payroll", "direct deposit", "deposit",
    "past due", "pastdue", "outstanding", "purchase order", "beneficiary",
    "billing", "wire transfer", "account number", "routing number",
]

# Security stems match any suffix (phish -> phishing); financial terms only an optional plural so "wire" doesn't match "wireless"
_KEYWORD_RES = {
    "security": [re.compile(r"\b" + re.escape(k) + r"\w*", re.IGNORECASE) for k in SECURITY_KEYWORDS],
    "financial": [re.compile(r"\b" + re.escape(k) + r"(s|es)?\b", re.IGNORECASE) for k in FINANCIAL_KEYWORDS],
}

# Folders commonly used to hide mail from the mailbox owner
HIDING_FOLDERS = {
    "rss feeds", "rss subscriptions", "conversation history",
    "junk email", "deleted items", "archive", "notes",
}

# messageRule predicates that can carry keyword filters
KEYWORD_CONDITION_FIELDS = (
    "subjectContains", "bodyContains", "bodyOrSubjectContains", "headerContains",
)


class NoGUIDException(Exception):
    pass


class MSExchangeOnline(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self._folder_cache = {}
        self.client_id = self.get_param('config.client_id', None, 'Microsoft Entra ID Application ID/Client ID Missing')
        self.client_secret = self.get_param('config.client_secret', None, 'Microsoft Entra ID Registered Application Client Secret Missing')
        self.tenant_id = self.get_param('config.tenant_id', None, 'Microsoft Entra ID Tenant ID Missing')
        self.service = self.get_param('config.service', None)
        self.extended_search = self.get_param('config.extended_search', True)

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

    def resolve_user_guid(self, identifier: str, headers: dict, base_url: str, extended_search: bool = False) -> str:
        """
        Robustly turn a user identifier into the user objectId (GUID).
        Works for cloud users, B2B guests, aliases, vanity domains, etc.
        """
        if GUID_RE.match(identifier):
            return identifier

        quoted = identifier.replace("'", "''")

        filter_q = (f"(userPrincipalName eq '{quoted}') "
                    f"or (mail eq '{quoted}')")

        if extended_search:
            filter_q += (f" or (onPremisesSamAccountName eq '{quoted}') "
                         f"or (employeeId eq '{quoted}')")

        req_headers = headers.copy()
        req_params = {"$filter": filter_q, "$select": "id,userPrincipalName"}

        if extended_search:
            req_headers["ConsistencyLevel"] = "eventual"
            req_params["$count"] = "true"

        resp = requests.get(
            f"{base_url}users",
            headers=req_headers,
            params=req_params,
        )
        if resp.status_code != 200:
            self.error(f"[GUID-lookup] HTTP {resp.status_code}: {resp.text}")

        users = resp.json().get("value", [])
        if not users:
            raise NoGUIDException(f"No user matches '{identifier}' in the tenant")

        return users[0]["id"]

    def ensure_user_guid(self, base_url, headers, extended_search: bool = False):
        if GUID_RE.match(self.user):
            return self.user
        return self.resolve_user_guid(self.user, headers, base_url, extended_search=extended_search)

    @staticmethod
    def _recipient_domains(recipients):
        domains = []
        for r in recipients or []:
            address = (r.get("emailAddress", {}) or {}).get("address", "")
            if "@" in address:
                domains.append(address.split("@", 1)[1].lower())
        return domains

    @staticmethod
    def _keyword_hits(conditions):
        """Match rule keyword filters against known BEC keyword lists."""
        terms = []
        for field in KEYWORD_CONDITION_FIELDS:
            terms.extend(conditions.get(field, []) or [])
        hits = {"security": set(), "financial": set()}
        for term in terms:
            for category, patterns in _KEYWORD_RES.items():
                if any(p.search(term) for p in patterns):
                    hits[category].add(term)
        return hits

    @staticmethod
    def _suspicious_name(name):
        """Empty, punctuation-only ('.', ',,') or repeated-character ('aaa') names."""
        n = (name or "").strip()
        if not n:
            return True
        if all(not c.isalnum() for c in n):
            return True
        if len(n) >= 2 and len(set(n.lower())) == 1:
            return True
        return False

    def _folder_display_name(self, folder_id, headers, base_url):
        """Resolve a moveToFolder/copyToFolder target ID to its display name."""
        if not folder_id:
            return None
        if folder_id in self._folder_cache:
            return self._folder_cache[folder_id]
        name = None
        try:
            r = requests.get(
                f"{base_url}users/{self.guid}/mailFolders/{folder_id}",
                headers=headers,
                params={"$select": "displayName"},
            )
            if r.status_code == 200:
                name = r.json().get("displayName")
        except requests.RequestException:
            pass
        self._folder_cache[folder_id] = name
        return name

    def _assess_rule(self, rule, own_domain, headers, base_url):
        """
        Flag rules matching known post-compromise tradecraft: external
        forwarding, delete-all rules, keyword filters combined with a hide or
        exfiltrate action, hiding folders, obfuscated rule names.
        """
        reasons = []
        actions = rule.get("actions", {}) or {}
        conditions = rule.get("conditions", {}) or {}

        forward_targets = (actions.get("forwardTo", []) or []) + \
                           (actions.get("forwardAsAttachmentTo", []) or []) + \
                           (actions.get("redirectTo", []) or [])
        external_domains = [d for d in self._recipient_domains(forward_targets) if own_domain and d != own_domain]
        if external_domains:
            reasons.append(f"forwards/redirects to external domain(s): {', '.join(sorted(set(external_domains)))}")

        has_conditions = any(v not in (None, [], "", False) for v in conditions.values())
        deletes = actions.get("delete") or actions.get("permanentDelete")
        moves = actions.get("moveToFolder")
        if not has_conditions and (deletes or moves):
            reasons.append("matches all mail (no conditions) and deletes/moves it")

        folder_name = self._folder_display_name(moves, headers, base_url) or \
            self._folder_display_name(actions.get("copyToFolder"), headers, base_url)
        moves_to_hiding_folder = bool(folder_name and folder_name.strip().lower() in HIDING_FOLDERS)
        if moves_to_hiding_folder:
            reasons.append(f"moves mail to a folder commonly used to hide messages: {folder_name}")

        hits = self._keyword_hits(conditions)
        if hits["security"] and (deletes or moves or actions.get("markAsRead") or forward_targets):
            reasons.append("filters security-warning keywords and hides/deletes/forwards matching mail: "
                           f"{', '.join(sorted(hits['security']))}")
        # Filing invoices into a folder is a normal workflow, so financial keywords are only flagged with a stronger action
        if hits["financial"] and (deletes or forward_targets or moves_to_hiding_folder):
            reasons.append("filters financial/BEC keywords and deletes/forwards/hides matching mail: "
                           f"{', '.join(sorted(hits['financial']))}")

        if self._suspicious_name(rule.get("displayName")):
            reasons.append("rule name is empty or obfuscated (punctuation-only or repeated characters)")

        return reasons, folder_name

    def handle_get_inbox_rules(self, headers, base_url):
        """
        Retrieve inbox message rules (mailFolders/inbox/messageRules) for a user.
        Reference: https://learn.microsoft.com/en-us/graph/api/mailfolder-list-messagerules
        """
        if self.data_type != 'mail':
            self.error('Incorrect dataType. "mail" expected.')

        try:
            self.user = self.get_data()
            if not self.user:
                self.error("No user supplied")
            self.guid = self.ensure_user_guid(base_url, headers, extended_search=self.extended_search)
            own_domain = self.user.split("@", 1)[1].lower() if "@" in self.user else None

            url = f"{base_url}users/{self.guid}/mailFolders/inbox/messageRules"
            rules = []
            while url:
                r = requests.get(url, headers=headers)
                if r.status_code != 200:
                    self.error(f"Failure to pull inbox rules for user {self.user}: {r.content}")
                data = r.json()
                rules.extend(data.get("value", []))
                url = data.get("@odata.nextLink")

            new_json = {"user": self.user, "rules": [], "suspiciousRuleCount": 0}

            for rule in rules:
                reasons, folder_name = self._assess_rule(rule, own_domain, headers, base_url)
                entry = {
                    "id": rule.get("id", "N/A"),
                    "displayName": rule.get("displayName", "N/A"),
                    "sequence": rule.get("sequence", "N/A"),
                    "isEnabled": rule.get("isEnabled", False),
                    "conditions": rule.get("conditions", {}),
                    "actions": rule.get("actions", {}),
                    "suspicious": bool(reasons),
                    "suspiciousReasons": reasons,
                }
                if folder_name:
                    entry["moveToFolderName"] = folder_name
                new_json["rules"].append(entry)
                if reasons:
                    new_json["suspiciousRuleCount"] += 1

            self.report(new_json)

        except NoGUIDException as ex:
            self.report({'message': str(ex)})
        except Exception:
            self.error(traceback.format_exc())

    def run(self):
        Analyzer.run(self)

        token = self.authenticate()
        headers = {
            'Authorization': f'Bearer {token}',
            'User-Agent': 'strangebee-thehive/1.0'
        }
        base_url = 'https://graph.microsoft.com/v1.0/'

        if self.service == "getInboxRules":
            self.handle_get_inbox_rules(headers, base_url)
        else:
            self.error("Unidentified service")

    def summary(self, raw):
        taxonomies = []

        if self.service == "getInboxRules" and "rules" in raw:
            rule_count = len(raw.get("rules", []))
            suspicious_count = raw.get("suspiciousRuleCount", 0)

            taxonomies.append(self.build_taxonomy('info', 'MSExchangeOnline', 'InboxRules', rule_count))
            if suspicious_count:
                taxonomies.append(self.build_taxonomy('malicious', 'MSExchangeOnline', 'SuspiciousRules', suspicious_count))
            else:
                taxonomies.append(self.build_taxonomy('safe', 'MSExchangeOnline', 'SuspiciousRules', 0))
        elif self.service == "getInboxRules" and "message" in raw:
            taxonomies.append(self.build_taxonomy('info', 'MSExchangeOnline', 'InboxRules', 'UserNotFound'))

        return {'taxonomies': taxonomies}

    def artifacts(self, raw):
        artifacts = []
        extracted_data = self.get_data()
        observed_type = self.data_type

        email_regex = r'[\w\.-]+@[\w\.-]+\.\w+'
        emails = re.findall(email_regex, str(raw))
        for email in set(emails):
            if not (observed_type == "mail" and extracted_data == email):
                artifacts.append(self.build_artifact('mail', email))

        return artifacts


if __name__ == '__main__':
    MSExchangeOnline().run()
