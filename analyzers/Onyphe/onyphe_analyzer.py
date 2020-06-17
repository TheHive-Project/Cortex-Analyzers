#!/usr/bin/env python3

from cortexutils.analyzer import Analyzer
from onyphe_api import Onyphe
from datetime import datetime


class OnypheAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param(
            "config.service", None, "Service parameter is missing"
        )
        self.onyphe_key = self.get_param("config.key", None, "Missing Onyphe API key")
        self.onyphe_client = None
        self.verbose_taxonomies = self.get_param("config.verbose_taxonomies", False)
        self.polling_interval = self.get_param("config.polling_interval", 60)

    def summary(self, raw):
        taxonomies = []
        namespace = "Onyphe"

        if not self.verbose_taxonomies:

            threatlist = list(
                set(
                    [
                        r["threatlist"]
                        for r in raw["results"]
                        if r["@category"] == "threatlist"
                    ]
                )
            )

            if len(threatlist) > 0:
                taxonomies.append(
                    self.build_taxonomy(
                        "malicious",
                        namespace,
                        "Threat",
                        "{} threat found".format(len(threatlist)),
                    )
                )
            else:
                taxonomies.append(
                    self.build_taxonomy("info", namespace, "Threat", "No threat found",)
                )
        else:

            output_data = {
                "threatlist": {},
                "subnet": {},
                "port": {},
                "reverse": {},
                "forward": {},
                "resolver": {},
            }

            for r in raw["results"]:

                if r["@category"] == "threatlist":
                    threatlist = r["threatlist"]
                    if threatlist not in output_data["threatlist"]:
                        output_data["threatlist"][threatlist] = {
                            "dates": [],
                            "subnets": [],
                            "count": 0,
                        }
                    if (
                        r["seen_date"]
                        not in output_data["threatlist"][threatlist]["dates"]
                    ):
                        output_data["threatlist"][threatlist]["dates"].append(
                            r["seen_date"]
                        )
                        output_data["threatlist"][threatlist]["count"] += 1
                    if (
                        r["subnet"]
                        not in output_data["threatlist"][threatlist]["subnets"]
                    ):
                        output_data["threatlist"][threatlist]["subnets"].append(
                            r["subnet"]
                        )

                elif r["@category"] == "geoloc":
                    taxonomies.append(
                        self.build_taxonomy(
                            "info",
                            namespace,
                            "Geolocate",
                            "country: {}, {}".format(
                                r["country"],
                                "location: {}".format(r["location"])
                                if not r.get("city", None)
                                else "city: {}".format(r["city"]),
                            ),
                        )
                    )

                elif r["@category"] == "inetnum":
                    subnet = r["subnet"]
                    if subnet not in output_data["subnet"]:
                        output_data["subnet"][subnet] = {"dates": []}
                    if r["seen_date"] not in output_data["subnet"][subnet]["dates"]:
                        output_data["subnet"][subnet]["dates"].append(r["seen_date"])

                elif r["@category"] in ["ports", "datascan"]:
                    port = r["port"]
                    if port not in output_data["port"]:
                        output_data["port"][port] = {"dates": []}
                    if r["seen_date"] not in output_data["port"][port]["dates"]:
                        output_data["port"][port]["dates"].append(r["seen_date"])

                elif r["@category"] == "reverse":
                    reverse = r["domain"]
                    if reverse not in output_data["reverse"]:
                        output_data["reverse"][reverse] = {"dates": []}
                    if r["seen_date"] not in output_data["reverse"][reverse]["dates"]:
                        output_data["reverse"][reverse]["dates"].append(r["seen_date"])

                elif r["@category"] == "forward":
                    forward = r["domain"]
                    if forward not in output_data["forward"]:
                        output_data["forward"][forward] = {"dates": []}
                    if r["seen_date"] not in output_data["forward"][forward]["dates"]:
                        output_data["forward"][forward]["dates"].append(r["seen_date"])

                elif r["@category"] == "resolver":
                    resolver = r["hostname"]
                    if resolver not in output_data["resolver"]:
                        output_data["resolver"][resolver] = {"dates": []}
                    if r["seen_date"] not in output_data["resolver"][resolver]["dates"]:
                        output_data["resolver"][resolver]["dates"].append(
                            r["seen_date"]
                        )

            for threatlist, threat_data in output_data["threatlist"].items():
                taxonomies.append(
                    self.build_taxonomy(
                        "malicious",
                        namespace,
                        "Threat",
                        "threatlist: {}, event count: {}".format(
                            threatlist, threat_data["count"]
                        ),
                    )
                )

            for topic in ["subnet", "port", "forward", "reverse", "resolver"]:
                for item, item_data in output_data[topic].items():
                    taxonomies.append(
                        self.build_taxonomy(
                            "info",
                            namespace,
                            item.capitalize(),
                            "{} {} last seen {}".format(
                                topic,
                                item,
                                max(
                                    datetime.strptime(x, "%Y-%m-%d")
                                    for x in item_data["dates"]
                                ),
                            ),
                        )
                    )

        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)
        try:
            self.onyphe_client = Onyphe(self.onyphe_key)
            data = self.get_param("data", None, "Data is missing")
            results = self.onyphe_client.summary(data, self.data_type)
            results["totals_category"] = {
                k: len(
                    [x for x in results["results"] if x["@category"] == k]
                )
                for k in [
                    "threatlist",
                    "threats",
                    "geoloc",
                    "inetnum",
                    "ports",
                    "reverse",
                    "datascan",
                    "forward",
                ]
            }

            self.report(results)

        except Exception:
            pass


if __name__ == "__main__":
    OnypheAnalyzer().run()
