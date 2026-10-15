#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.analyzer import Analyzer


class GeoIPCustom(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.flagged_countries = self.get_param("config.flagged_countries", "") or ""

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "GeoIP_Custom"

        country = raw.get("country", "Unknown")
        country_code = raw.get("countryCode", "Unknown")

        # Add basic country taxonomy
        taxonomies.append(self.build_taxonomy(level, namespace, "Country", country))

        # Add IOC taxonomy if the country matches the flagged list
        if raw.get("flagged", False):
            taxonomies.append(
                self.build_taxonomy(
                    "suspicious", namespace, "IOC", f"{country} ({country_code})"
                )
            )

        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.data_type == "ip":
            data = self.get_data()
            url = f"http://ip-api.com/json/{data}"

            try:
                with requests.Session() as session:
                    response = session.get(url, timeout=10)
                    response.raise_for_status()
                    result = response.json()

                    if result.get("status") == "success":
                        country_code = result.get("countryCode", "").strip().upper()

                        # Parse flagged countries (comma-separated, case-insensitive)
                        flagged_list = [
                            c.strip().upper()
                            for c in self.flagged_countries.split(",")
                            if c.strip()
                        ]

                        # Check if the returned country code is flagged
                        result["flagged"] = country_code in flagged_list

                        self.report(result)
                    else:
                        self.error(result.get("message", "Failed to lookup IP info"))
            except requests.RequestException as e:
                self.error(f"HTTP request failed: {e}")
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == "__main__":
    GeoIPCustom().run()
