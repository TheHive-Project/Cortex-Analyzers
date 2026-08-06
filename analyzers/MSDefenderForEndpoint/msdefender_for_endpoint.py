#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from cortexutils.analyzer import Analyzer


class MSDefenderForEndpointAnalyzer(Analyzer):

    LOGIN_URL = "https://login.microsoftonline.com/{}/oauth2/v2.0/token"
    API_BASE = "https://api.security.microsoft.com/api"
    # MDE tokens must be issued for the legacy "securitycenter" resource even when
    # calling the api.security.microsoft.com host, otherwise requests fail with
    # 403 Forbidden. See "Get an access token" in:
    # https://learn.microsoft.com/en-us/defender-endpoint/api/exposed-apis-create-app-webapp
    TOKEN_SCOPE = "https://api.securitycenter.microsoft.com/.default"
    SEVERITY_RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFORMATIONAL": 0}

    def __init__(self):
        Analyzer.__init__(self)
        self.tenant_id = self.get_param("config.tenant_id", None, "Missing tenant_id")
        self.client_id = self.get_param("config.client_id", None, "Missing client_id")
        self.client_secret = self.get_param("config.client_secret", None, "Missing client_secret")
        self.service = self.get_param("config.service", None, "Missing service")

    def _get_token(self):
        body = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.TOKEN_SCOPE,
        }
        try:
            response = requests.post(self.LOGIN_URL.format(self.tenant_id), data=body, timeout=30)
        except requests.RequestException as e:
            self.error("Unable to reach Azure AD login endpoint: {}".format(e))

        if response.status_code != 200:
            self.error("Azure AD authentication failed (HTTP {}): check tenant_id, client_id and client_secret".format(response.status_code))

        token = response.json().get("access_token")
        if not token:
            self.error("Azure AD authentication response did not contain an access token")
        return token

    def _call_api(self, token, path, params=None):
        headers = {"Authorization": "Bearer {}".format(token)}
        try:
            response = requests.get("{}{}".format(self.API_BASE, path), headers=headers, params=params, timeout=30)
        except requests.RequestException as e:
            self.error("Unable to reach Microsoft Defender for Endpoint API: {}".format(e))

        if response.status_code == 404:
            return None
        if response.status_code == 403:
            self.error("Access denied by Microsoft Defender for Endpoint API: check the app's API permissions")
        if response.status_code >= 400:
            try:
                api_error = response.json().get("error", {})
                detail = "{}: {}".format(api_error.get("code"), api_error.get("message"))
            except ValueError:
                detail = response.text
            self.error("Microsoft Defender for Endpoint API error (HTTP {}): {}".format(response.status_code, detail))
        return response.json()

    def _max_severity(self, alerts):
        best = None
        best_rank = -1
        for alert in alerts:
            severity = (alert.get("severity") or "").upper()
            rank = self.SEVERITY_RANK.get(severity, -1)
            if rank > best_rank:
                best_rank = rank
                best = alert.get("severity")
        return best

    def _device_lookup(self, token, data, data_type):
        if data_type == "ip":
            # lastExternalIpAddress is not a filterable Machine property in the MDE API
            # (see https://learn.microsoft.com/en-us/defender-endpoint/api/get-machines)
            odata_filter = "lastIpAddress eq '{}'".format(data)
        else:
            odata_filter = "computerDnsName eq '{}'".format(data)

        result = self._call_api(token, "/machines", params={"$filter": odata_filter})
        machines = result.get("value", []) if result else []

        report = {"found": bool(machines), "machines": []}
        for machine in machines:
            alerts_result = self._call_api(token, "/machines/{}/alerts".format(machine.get("id")))
            machine["alerts"] = alerts_result.get("value", []) if alerts_result else []
            report["machines"].append(machine)

        return report

    def _hash_reputation(self, token, data, data_type):
        file_info = self._call_api(token, "/files/{}".format(data))
        if file_info is None:
            return {"found": False, "file": {}, "stats": {}, "alerts": [], "maxSeverity": None}

        stats = self._call_api(token, "/files/{}/stats".format(data)) or {}
        alerts_result = self._call_api(token, "/files/{}/alerts".format(data)) or {"value": []}
        alerts = alerts_result.get("value", [])

        return {
            "found": True,
            "file": file_info,
            "stats": stats,
            "alerts": alerts,
            "maxSeverity": self._max_severity(alerts),
        }

    def run(self):
        data = self.get_data()
        data_type = self.get_param("dataType")

        if self.service == "device_lookup":
            if data_type not in ["ip", "fqdn"]:
                return self.notSupported()
        elif self.service == "hash_reputation":
            if data_type != "hash":
                return self.notSupported()
            if len(data) not in (40, 64):
                return self.error("MSDefenderForEndpoint only supports SHA1 or SHA256 hashes for file lookups")
        else:
            return self.error("Unknown service: {}".format(self.service))

        token = self._get_token()

        if self.service == "device_lookup":
            result = self._device_lookup(token, data, data_type)
        else:
            result = self._hash_reputation(token, data, data_type)

        self.report(result)

    def summary(self, raw):
        taxonomies = []

        if self.service == "device_lookup":
            if not raw.get("found"):
                taxonomies.append(self.build_taxonomy("info", "MDE", "Device", "NotFound"))
                return {"taxonomies": taxonomies}

            for machine in raw.get("machines", []):
                risk = (machine.get("riskScore") or "None").upper()
                if risk == "HIGH":
                    level = "malicious"
                elif risk == "MEDIUM":
                    level = "suspicious"
                elif risk == "LOW":
                    level = "safe"
                else:
                    level = "info"
                taxonomies.append(self.build_taxonomy(level, "MDE", "RiskScore", risk.capitalize()))

                alert_count = len(machine.get("alerts", []))
                if alert_count > 0:
                    taxonomies.append(self.build_taxonomy("suspicious", "MDE", "Alerts", str(alert_count)))

        elif self.service == "hash_reputation":
            if not raw.get("found"):
                taxonomies.append(self.build_taxonomy("info", "MDE", "File", "NotSeen"))
                return {"taxonomies": taxonomies}

            alerts = raw.get("alerts", [])
            max_severity = (raw.get("maxSeverity") or "").upper()

            if max_severity == "HIGH":
                level = "malicious"
            elif max_severity in ("MEDIUM", "LOW", "INFORMATIONAL"):
                level = "suspicious"
            else:
                org_prevalence = raw.get("stats", {}).get("orgPrevalence", 0)
                level = "safe" if org_prevalence else "info"

            taxonomies.append(self.build_taxonomy(level, "MDE", "Alerts", str(len(alerts))))

            org_prevalence = raw.get("stats", {}).get("orgPrevalence")
            if org_prevalence is not None:
                taxonomies.append(self.build_taxonomy("info", "MDE", "OrgPrevalence", str(org_prevalence)))

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []

        if self.service == "device_lookup":
            for machine in raw.get("machines", []):
                ip = machine.get("lastIpAddress")
                if ip:
                    artifacts.append(self.build_artifact("ip", ip))

        return artifacts


if __name__ == "__main__":
    MSDefenderForEndpointAnalyzer().run()
