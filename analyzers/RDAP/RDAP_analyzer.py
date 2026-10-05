#!/usr/bin/env python3
import requests
from cortexutils.analyzer import Analyzer

# rdap.org resolves the authoritative RDAP server for a given object and
# redirects to it, so a single endpoint covers every TLD and RIR.
BASEURL = "https://rdap.org"

# Registry statuses that indicate the object is restricted, held or in the
# middle of a transfer. Worth surfacing in triage.
NOTABLE_STATUSES = [
    "client hold",
    "server hold",
    "pending delete",
    "pending transfer",
    "redemption period",
]


class RDAPAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.timeout = int(self.get_param("config.timeout", 15))

    def query(self, object_type, value):
        url = "{}/{}/{}".format(BASEURL, object_type, value)

        try:
            response = requests.get(
                url,
                headers={"Accept": "application/rdap+json"},
                timeout=self.timeout,
            )
        except requests.exceptions.RequestException as e:
            self.error("Could not reach RDAP service: {}".format(e))

        if response.status_code == 404:
            return {"found": False}

        if response.status_code == 429:
            self.error("RDAP service rate limited the request.")

        if not 200 <= response.status_code < 300:
            self.error("RDAP service returned HTTP {}".format(response.status_code))

        try:
            result = response.json()
        except ValueError:
            self.error("RDAP service returned a non-JSON response.")

        result["found"] = True
        return result

    def run(self):
        data = self.get_data()
        if not data:
            self.error("No observable given.")

        if self.data_type == "domain":
            result = self.query("domain", data)
        elif self.data_type == "ip":
            result = self.query("ip", data)
        else:
            self.error("Data type {} not supported.".format(self.data_type))

        result["queried_type"] = self.data_type
        self.report(result)

    def _events(self, raw):
        events = {}
        for event in raw.get("events") or []:
            action = event.get("eventAction")
            date = event.get("eventDate")
            if action and date:
                events[action] = date
        return events

    def _registrar(self, raw):
        for entity in raw.get("entities") or []:
            roles = entity.get("roles") or []
            if "registrar" not in roles:
                continue
            for item in entity.get("vcardArray", [None, []])[1] or []:
                if item and item[0] == "fn":
                    return item[3]
        return None

    def summary(self, raw):
        taxonomies = []
        namespace = "RDAP"

        if not raw.get("found"):
            taxonomies.append(
                self.build_taxonomy("info", namespace, "Registration", "Not found")
            )
            return {"taxonomies": taxonomies}

        statuses = [s.lower() for s in (raw.get("status") or [])]
        flagged = [s for s in statuses if s in NOTABLE_STATUSES]
        if flagged:
            taxonomies.append(
                self.build_taxonomy(
                    "suspicious", namespace, "Status", ", ".join(flagged)
                )
            )

        events = self._events(raw)
        registered = events.get("registration")
        if registered:
            taxonomies.append(
                self.build_taxonomy(
                    "info", namespace, "Registered", registered[:10]
                )
            )

        registrar = self._registrar(raw)
        if registrar:
            taxonomies.append(
                self.build_taxonomy("info", namespace, "Registrar", registrar)
            )

        if not taxonomies:
            taxonomies.append(
                self.build_taxonomy("info", namespace, "Registration", "Found")
            )

        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []
        seen = set()

        for ns in raw.get("nameservers") or []:
            name = ns.get("ldhName")
            if name and name.lower() not in seen:
                seen.add(name.lower())
                artifacts.append(self.build_artifact("domain", name.lower()))

        return artifacts


if __name__ == "__main__":
    RDAPAnalyzer().run()
