#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
import tor_project


class TorProjectAnalyzer(Analyzer):
    """Cortex analyzer to query TorProject for exit nodes IP addresses"""

    def __init__(self):
        Analyzer.__init__(self)
        self.ttl = self.get_param("config.ttl", 86400)
        self.cache_duration = self.get_param("config.cache.duration", 3600)
        self.cache_root = self.get_param("config.cache.root", "/tmp/cortex/tor_project")
        self.proxies = {
            "https": self.get_param("config.proxy_https"),
            "http": self.get_param("config.proxy_http"),
        }
        self.client = tor_project.TorProjectClient(
            ttl=self.ttl,
            cache_duration=self.cache_duration,
            cache_root=self.cache_root,
            proxies=self.proxies,
        )

    def summary(self, raw):
        taxonomies = []
        level = "info"
        value = False
        if "node" in raw:
            level = "suspicious"
            value = True
        taxonomies.append(self.build_taxonomy(level, "TorProject", "Node", value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type != "ip":
            return self.error("Not an IP address")
        report = self.client.search_tor_node(self.get_data())
        self.report(report)


if __name__ == "__main__":
    TorProjectAnalyzer().run()
