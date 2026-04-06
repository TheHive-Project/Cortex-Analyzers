#!/usr/bin/env python3
# encoding: utf-8

import email
import email.utils
import re
import time
import uuid

import requests
from cortexutils.analyzer import Analyzer


REGION_URLS = {
    "us": "https://cloudinfra-gw-us.portal.checkpoint.com",
    "eu": "https://cloudinfra-gw.portal.checkpoint.com",
    "ca": "https://cloudinfra-gw.ca.portal.checkpoint.com",
    "au": "https://cloudinfra-gw.ap.portal.checkpoint.com",
    "uk": "https://cloudinfra-gw.uk.portal.checkpoint.com",
    "uae": "https://cloudinfra-gw.me.portal.checkpoint.com",
    "in": "https://cloudinfra-gw.in.portal.checkpoint.com",
    "sg": "https://cloudinfra-gw.sg.portal.checkpoint.com",
}


class CheckPointHECAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "Service parameter is missing"
        )
        self.client_id = self.get_param(
            "config.client_id", None, "Client ID is missing"
        )
        self.client_secret = self.get_param(
            "config.client_secret", None, "Client Secret is missing"
        )
        region = self.get_param("config.region", "eu").lower()
        if region not in REGION_URLS:
            self.error(
                "Invalid region '{}'. Must be one of: {}".format(
                    region, ", ".join(REGION_URLS.keys())
                )
            )
        self.base_url = REGION_URLS[region]
        self.saas = self.get_param("config.saas", "office365_emails")
        self.portal_url = self.get_param("config.portal_url", "").rstrip("/")
        self.token = None
        self.token_expiry = 0

    def _authenticate(self):
        if self.token and time.time() < self.token_expiry:
            return
        url = "{}/auth/external".format(self.base_url)
        payload = {"clientId": self.client_id, "accessKey": self.client_secret}
        resp = requests.post(url, json=payload)
        if resp.status_code != 200:
            self.error(
                "Authentication failed (HTTP {}): {}".format(
                    resp.status_code, resp.text
                )
            )
        data = resp.json().get("data", resp.json())
        self.token = data.get("token")
        if not self.token:
            self.error("Authentication failed: no token in response")
        self.token_expiry = time.time() + float(data.get("expiresIn", 3600)) - 60

    def _headers(self):
        return {
            "Authorization": "Bearer {}".format(self.token),
            "x-av-req-id": str(uuid.uuid4()),
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

    def _api_url(self, path):
        return "{}/app/hec-api/v1.0/{}".format(self.base_url, path)

    def _find_inner_message(self, msg):
        """Walk MIME parts to find an attached original email (message/rfc822)."""
        for part in msg.walk():
            if part.get_content_type() == "message/rfc822":
                payload = part.get_payload()
                if isinstance(payload, list) and len(payload) > 0:
                    return payload[0]
                elif hasattr(payload, "get"):
                    return payload
        return None

    def _portal_link(self, entity_id):
        if not self.portal_url or not entity_id:
            return None
        return "{}/#/profile/email/{}_email/{}".format(
            self.portal_url, self.saas, entity_id
        )

    def _extract_message_id(self, filepath):
        msg = self._parse_eml(filepath)
        message_id = msg.get("Message-ID", "").strip()
        if not message_id:
            self.error("No Message-ID header found in the .eml file")
        if not message_id.startswith("<"):
            message_id = "<{}>".format(message_id)
        return message_id

    def _parse_eml(self, filepath):
        """Parse .eml file and return the relevant message (inner if forwarded)."""
        with open(filepath, "rb") as f:
            msg = email.message_from_binary_file(f)
        inner = self._find_inner_message(msg)
        if inner:
            msg = inner
        return msg

    def _extract_sender_email(self, filepath):
        msg = self._parse_eml(filepath)
        from_header = msg.get("From", "")
        addr = email.utils.parseaddr(from_header)[1]
        if not addr:
            self.error("No sender email found in the .eml file")
        return addr

    def _extract_sender_domain(self, filepath):
        addr = self._extract_sender_email(filepath)
        parts = addr.split("@")
        if len(parts) != 2 or not parts[1]:
            self.error("Could not extract domain from sender '{}'".format(addr))
        return parts[1]

    def _extract_sender_ip(self, filepath):
        """Extract the originating IP from the first Received header."""
        msg = self._parse_eml(filepath)
        received_headers = msg.get_all("Received", [])
        ip_pattern = re.compile(r"\[(\d{1,3}(?:\.\d{1,3}){3})\]")
        for header in received_headers:
            match = ip_pattern.search(header)
            if match:
                ip = match.group(1)
                if not ip.startswith(("10.", "192.168.", "127.")):
                    return ip
        # Fallback: return first IP found even if private
        for header in received_headers:
            match = ip_pattern.search(header)
            if match:
                return match.group(1)
        self.error("No sender IP found in the .eml Received headers")

    def _search_by_filter(self, extended_filters):
        self._authenticate()
        payload = {
            "requestData": {
                "entityFilter": {
                    "saas": self.saas,
                    "startDate": "2020-01-01T00:00:00Z",
                },
                "entityExtendedFilter": extended_filters,
            }
        }
        resp = requests.post(
            self._api_url("search/query"), headers=self._headers(), json=payload
        )
        if resp.status_code != 200:
            self.error(
                "Search query failed (HTTP {}): {}".format(resp.status_code, resp.text)
            )
        return resp.json()

    def _get_entity(self, entity_id):
        self._authenticate()
        resp = requests.get(
            self._api_url("search/entity/{}".format(entity_id)),
            headers=self._headers(),
        )
        if resp.status_code != 200:
            self.error(
                "Get entity failed (HTTP {}): {}".format(resp.status_code, resp.text)
            )
        return resp.json()

    def _build_email_summary(self, entity):
        info = entity.get("entityInfo", {})
        payload = entity.get("entityPayload", {})
        security = entity.get("entitySecurityResult", {})
        combined = security.get("combinedVerdict", {})
        entity_id = info.get("entityId")
        return {
            "entity_id": entity_id,
            "portal_link": self._portal_link(entity_id),
            "subject": payload.get("subject"),
            "from_email": payload.get("fromEmail"),
            "from_domain": payload.get("fromDomain"),
            "to": payload.get("to", []),
            "received": payload.get("received"),
            "internet_message_id": payload.get("internetMessageId"),
            "is_quarantined": payload.get("isQuarantined"),
            "is_read": payload.get("isRead"),
            "is_user_exposed": payload.get("isUserExposed"),
            "is_restored": payload.get("isRestored"),
            "is_junk": payload.get("isJunk"),
            "folder_name": payload.get("folderName"),
            "saas_spam_verdict": payload.get("saasSpamVerdict"),
            "combined_verdict": combined,
            "ap_verdict": combined.get("ap"),
            "sender_server_ip": payload.get("senderServerIp"),
            "sender_client_ip": payload.get("senderClientIp"),
            "links": payload.get("emailLinks", []),
            "links_domains": payload.get("emailLinksDomains", []),
        }

    def _verdict_stats(self, emails):
        stats = {}
        for e in emails:
            v = e.get("ap_verdict") or "unknown"
            stats[v] = stats.get(v, 0) + 1
        return stats

    def run(self):
        if self.service == "search_email":
            if self.data_type == "file":
                filepath = self.get_param("file", None, "File is missing")
                filename = self.get_param("filename", "")
                if not filename.lower().endswith(".eml"):
                    self.error("Only .eml files are supported")
                message_id = self._extract_message_id(filepath)
            elif self.data_type == "other":
                message_id = self.get_param("data", "").strip()
                if not (message_id.startswith("<") and message_id.endswith(">")):
                    self.error(
                        "Invalid Message-ID format. Expected '<...@...>' but got '{}'".format(
                            message_id
                        )
                    )
            else:
                self.error(
                    "Unsupported data type '{}'. Use 'file' (.eml) or 'other' (Message-ID).".format(
                        self.data_type
                    )
                )

            search_result = self._search_by_filter([{
                "saasAttrName": "entityPayload.internetMessageId",
                "saasAttrOp": "is",
                "saasAttrValue": message_id,
            }])
            response_data = search_result.get("responseData", [])

            if not response_data:
                self.report({
                    "message_id": message_id,
                    "found": False,
                    "message": "Email not found in Check Point HEC",
                })
                return

            entity = response_data[0]
            entity_id = entity.get("entityInfo", {}).get("entityId")

            if entity_id:
                entity_details = self._get_entity(entity_id)
                entity_data = entity_details.get("responseData", [{}])
                if entity_data:
                    entity = entity_data[0]

            entity_info = entity.get("entityInfo", {})
            entity_payload = entity.get("entityPayload", {})
            security_result = entity.get("entitySecurityResult", {})
            combined_verdict = security_result.get("combinedVerdict", {})
            available_actions = entity.get("entityAvailableActions", [])
            actions = entity.get("entityActions", [])

            result = {
                "message_id": message_id,
                "found": True,
                "entity_id": entity_info.get("entityId"),
                "portal_link": self._portal_link(entity_info.get("entityId")),
                "entity_info": {
                    "saas": entity_info.get("saas"),
                    "created": entity_info.get("entityCreated"),
                    "updated": entity_info.get("entityUpdated"),
                    "action_state": entity_info.get("entityActionState"),
                },
                "email": {
                    "subject": entity_payload.get("subject"),
                    "from_email": entity_payload.get("fromEmail"),
                    "from_name": entity_payload.get("fromName"),
                    "from_domain": entity_payload.get("fromDomain"),
                    "to": entity_payload.get("to", []),
                    "cc": entity_payload.get("cc", []),
                    "received": entity_payload.get("received"),
                    "internet_message_id": entity_payload.get("internetMessageId"),
                    "size": entity_payload.get("size"),
                    "links": entity_payload.get("emailLinks", []),
                    "links_domains": entity_payload.get("emailLinksDomains", []),
                    "attachment_count": entity_payload.get("attachmentCount"),
                    "is_read": entity_payload.get("isRead"),
                    "is_deleted": entity_payload.get("isDeleted"),
                    "is_incoming": entity_payload.get("isIncoming"),
                    "is_internal": entity_payload.get("isInternal"),
                    "is_outgoing": entity_payload.get("isOutgoing"),
                    "is_quarantined": entity_payload.get("isQuarantined"),
                    "is_restored": entity_payload.get("isRestored"),
                    "is_user_exposed": entity_payload.get("isUserExposed"),
                    "saas_spam_verdict": entity_payload.get("saasSpamVerdict"),
                    "is_junk": entity_payload.get("isJunk"),
                    "folder_name": entity_payload.get("folderName"),
                    "spf_result": entity_payload.get("SpfResult"),
                    "sender_server_ip": entity_payload.get("senderServerIp"),
                    "sender_client_ip": entity_payload.get("senderClientIp"),
                },
                "security": {
                    "combined_verdict": combined_verdict,
                    "ap": security_result.get("ap"),
                    "dlp": security_result.get("dlp"),
                    "click_time_protection": security_result.get(
                        "clicktimeProtection"
                    ),
                    "av": security_result.get("av"),
                    "shadow_it": security_result.get("shadowIt"),
                },
                "available_actions": available_actions,
                "actions": actions,
            }
            self.report(result)

        elif self.service in ("search_by_sender", "search_by_domain", "search_by_url", "search_by_sender_ip"):

            if self.service == "search_by_sender":
                if self.data_type == "file":
                    filepath = self.get_param("file", None, "File is missing")
                    filename = self.get_param("filename", "")
                    if not filename.lower().endswith(".eml"):
                        self.error("Only .eml files are supported")
                    data = self._extract_sender_email(filepath)
                elif self.data_type == "mail":
                    data = self.get_param("data", None, "Data is missing")
                else:
                    self.error("Unsupported data type '{}'. Use 'mail' or 'file' (.eml).".format(self.data_type))
                filters = [{
                    "saasAttrName": "entityPayload.fromEmail",
                    "saasAttrOp": "is",
                    "saasAttrValue": data,
                }]
                query_type = "sender"

            elif self.service == "search_by_domain":
                if self.data_type == "file":
                    filepath = self.get_param("file", None, "File is missing")
                    filename = self.get_param("filename", "")
                    if not filename.lower().endswith(".eml"):
                        self.error("Only .eml files are supported")
                    data = self._extract_sender_domain(filepath)
                elif self.data_type == "domain":
                    data = self.get_param("data", None, "Data is missing")
                else:
                    self.error("Unsupported data type '{}'. Use 'domain' or 'file' (.eml).".format(self.data_type))
                filters = [{
                    "saasAttrName": "entityPayload.fromDomain",
                    "saasAttrOp": "is",
                    "saasAttrValue": data,
                }]
                query_type = "domain"

            elif self.service == "search_by_sender_ip":
                if self.data_type == "file":
                    filepath = self.get_param("file", None, "File is missing")
                    filename = self.get_param("filename", "")
                    if not filename.lower().endswith(".eml"):
                        self.error("Only .eml files are supported")
                    data = self._extract_sender_ip(filepath)
                elif self.data_type == "ip":
                    data = self.get_param("data", None, "Data is missing")
                else:
                    self.error("Unsupported data type '{}'. Use 'ip' or 'file' (.eml).".format(self.data_type))
                filters = [{
                    "saasAttrName": "entityPayload.senderServerIp",
                    "saasAttrOp": "is",
                    "saasAttrValue": data,
                }]
                query_type = "sender_ip"

            else:
                if self.data_type != "url":
                    self.error("Only url data type is supported")
                data = self.get_param("data", None, "Data is missing")
                filters = [{
                    "saasAttrName": "entityPayload.emailLinks",
                    "saasAttrOp": "contains",
                    "saasAttrValue": data,
                }]
                query_type = "url"

            search_result = self._search_by_filter(filters)
            response_data = search_result.get("responseData", [])
            emails = [self._build_email_summary(e) for e in response_data]

            self.report({
                "query": data,
                "query_type": query_type,
                "found": len(emails) > 0,
                "total_count": len(emails),
                "verdict_summary": self._verdict_stats(emails),
                "emails": emails,
            })

        else:
            self.error("Unknown service: {}".format(self.service))

    def _verdict_level(self, verdict):
        if verdict in ("malicious", "phishing"):
            return "malicious"
        elif verdict in ("suspicious", "spam"):
            return "suspicious"
        elif verdict in ("clean", "legitimate"):
            return "safe"
        return "info"

    def summary(self, raw):
        taxonomies = []
        namespace = "CPHEC"

        if "message_id" in raw:
            if not raw.get("found"):
                taxonomies.append(
                    self.build_taxonomy("info", namespace, "Status", "Not found")
                )
                return {"taxonomies": taxonomies}

            ap_scans = raw.get("security", {}).get("ap")
            if ap_scans and isinstance(ap_scans, list) and len(ap_scans) > 0:
                verdict = ap_scans[0].get("verdict", "unknown")
                taxonomies.append(
                    self.build_taxonomy(
                        self._verdict_level(verdict), namespace, "AntiPhishing", verdict
                    )
                )

            combined = raw.get("security", {}).get("combined_verdict", {})
            if combined and isinstance(combined, dict):
                ap_verdict = combined.get("ap")
                if ap_verdict:
                    taxonomies.append(
                        self.build_taxonomy(
                            self._verdict_level(ap_verdict), namespace, "Verdict", ap_verdict
                        )
                    )

            spf = raw.get("email", {}).get("spf_result")
            if spf:
                level = "safe" if spf == "pass" else "suspicious"
                taxonomies.append(
                    self.build_taxonomy(level, namespace, "SPF", spf)
                )

            is_quarantined = raw.get("email", {}).get("is_quarantined")
            if is_quarantined is not None:
                taxonomies.append(
                    self.build_taxonomy(
                        "malicious" if is_quarantined else "info",
                        namespace,
                        "Quarantined",
                        str(is_quarantined),
                    )
                )

        elif "query_type" in raw:
            total = raw.get("total_count", 0)
            if not raw.get("found"):
                taxonomies.append(
                    self.build_taxonomy("info", namespace, "Emails", "0")
                )
                return {"taxonomies": taxonomies}

            taxonomies.append(
                self.build_taxonomy("info", namespace, "Emails", str(total))
            )
            verdict_summary = raw.get("verdict_summary", {})
            for verdict, count in verdict_summary.items():
                if verdict in ("malicious", "phishing", "suspicious", "spam"):
                    taxonomies.append(
                        self.build_taxonomy(
                            self._verdict_level(verdict),
                            namespace,
                            verdict.capitalize(),
                            str(count),
                        )
                    )

        return {"taxonomies": taxonomies}

    def _extract_artifacts_from_email(self, email_data, verdict_tag, artifacts, seen):
        from_email = email_data.get("from_email")
        if from_email and from_email not in seen:
            seen.add(from_email)
            artifacts.append(self.build_artifact(
                "mail", from_email,
                tags=["CheckPointHEC", "src:CheckPointHEC", "sender", verdict_tag],
            ))

        from_domain = email_data.get("from_domain")
        if from_domain and from_domain not in seen:
            seen.add(from_domain)
            artifacts.append(self.build_artifact(
                "domain", from_domain,
                tags=["CheckPointHEC", "src:CheckPointHEC", "sender-domain", verdict_tag],
            ))

        for ip_field, tag in [
            ("sender_server_ip", "sender-server-ip"),
            ("sender_client_ip", "sender-client-ip"),
        ]:
            ip = email_data.get(ip_field)
            if ip and ip not in seen:
                seen.add(ip)
                artifacts.append(self.build_artifact(
                    "ip", ip,
                    tags=["CheckPointHEC", "src:CheckPointHEC", tag, verdict_tag],
                ))

        for link in email_data.get("links", []):
            if link and link not in seen:
                seen.add(link)
                artifacts.append(self.build_artifact(
                    "url", link,
                    tags=["CheckPointHEC", "src:CheckPointHEC", "email-link", verdict_tag],
                ))

        for domain in email_data.get("links_domains", []):
            if domain and domain not in seen:
                seen.add(domain)
                artifacts.append(self.build_artifact(
                    "domain", domain,
                    tags=["CheckPointHEC", "src:CheckPointHEC", "link-domain", verdict_tag],
                ))

    def artifacts(self, raw):
        artifacts = []
        seen = set()

        if "message_id" in raw and raw.get("found"):
            email_data = raw.get("email", {})
            security = raw.get("security", {})
            combined = security.get("combined_verdict", {})
            verdict_tag = "CPHEC:verdict={}".format(combined.get("ap", "unknown"))
            self._extract_artifacts_from_email(email_data, verdict_tag, artifacts, seen)

        elif "query_type" in raw and raw.get("found"):
            for email_entry in raw.get("emails", []):
                combined = email_entry.get("combined_verdict", {})
                verdict_tag = "CPHEC:verdict={}".format(combined.get("ap", "unknown"))
                self._extract_artifacts_from_email(email_entry, verdict_tag, artifacts, seen)

        return artifacts


if __name__ == "__main__":
    CheckPointHECAnalyzer().run()
