#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2021 Pierre LALET <pierre@droids-corp.org>


"""Cortex Analyzer that queries an IVRE instance.

"""


from datetime import datetime


from cortexutils.analyzer import Analyzer
from ivre import config
from ivre.db import MetaDB
from ivre import utils


DATABASES = [
    ("data", "data"),
    ("passive", "passive"),
    ("scans", "nmap"),
]


class Processor:

    databases = []

    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.data = analyzer.get_data()

    def flt(self, dbase):
        raise NotImplementedError()

    def run(self):
        result = {}
        for dbname in self.databases:
            if not self.analyzer.get_param("config.use_%s" % dbname, True):
                continue
            res = self.get(dbname)
            if res:
                result[dbname] = res
        return result

    def get(self, dbase):
        # By default, report all IP addresses
        result = sorted(
            self.analyzer.databases[dbase].distinct("addr", flt=self.flt(dbase)),
            key=utils.ip2int,
        )
        self.analyzer._artifacts.update(("ip", addr) for addr in result)
        return result

    @staticmethod
    def from_analyzer(analyzer):
        return {
            "autonomous-system": ProcessorAsnum,
            "certificate_hash": ProcessorCert,
            "domain": ProcessorDomain,
            "fqdn": ProcessorFqdn,
            "ip": ProcessorIp,
            "network": ProcessorNet,
            "port": ProcessorPort,
            "user-agent": ProcessorUserAgent,
        }[analyzer.data_type](analyzer)


class ProcessorIp(Processor):
    """IP addresses processor

    output contains intelligence about the IP address; the format is
    different from one database to another.

    """

    databases = ["data", "passive", "scans"]
    keep_addresses = False

    def flt(self, dbase):
        return self.analyzer.databases[dbase].searchhost(self.data)

    def get_scans(self, dbase):
        if self.keep_addresses:
            all_results = {}
        else:
            result = {}
        for rec in self.analyzer.databases[dbase].get(self.flt(dbase)):
            if self.keep_addresses:
                result = all_results.setdefault(rec["addr"], {})
                self.analyzer._artifacts.add(("ip", rec["addr"]))
            firstseen = rec.get("starttime", rec.get("endtime"))
            lastseen = rec.get("endtime", rec.get("starttime"))
            if firstseen:
                if "firstseen" in result:
                    result["firstseen"] = min(result["firstseen"], firstseen)
                else:
                    result["firstseen"] = firstseen
            if lastseen:
                if "lastseen" in result:
                    result["lastseen"] = min(result["lastseen"], firstseen)
                else:
                    result["lastseen"] = firstseen
            if rec.get("categories"):
                result.setdefault("categories", set()).update(
                    c for c in rec["categories"] if not c.startswith("_")
                )
            if rec.get("source"):
                result.setdefault("sources", set()).add(rec["source"])
            if rec.get("hostnames"):
                result.setdefault("hostnames", set()).update(
                    hn["name"] for hn in rec["hostnames"]
                )
            for port in rec.get("ports", []):
                if port.get("state_state") == "open":
                    result.setdefault("openports", set()).add(
                        "%(protocol)s/%(port)d" % port
                    )
                if port.get("service_name"):
                    result.setdefault("services", set()).add(port["service_name"])
                if port.get("service_product"):
                    result.setdefault("products", set()).add(port["service_product"])
                for script in port.get("scripts", []):
                    result.setdefault("categories", set()).add(script["id"])
                    if script["id"] == "ssl-cert":
                        for cert in script.get("ssl-cert", []):
                            result.setdefault("certs", set()).add(
                                (
                                    cert["subject_text"],
                                    cert["issuer_text"],
                                    cert["md5"],
                                    cert["sha1"],
                                    cert["sha256"],
                                )
                            )
                        continue
                    if "vulns" in script:
                        for vuln in script["vulns"]:
                            if vuln["state"] == "VULNERABLE":
                                result.setdefault("vulnerabilities", set()).add(
                                    "/".join(sorted(vuln["ids"]))
                                )
        for subr in all_results.values() if self.keep_addresses else [result]:
            self.clean_results(subr)
        if self.keep_addresses:
            return [{"addr": addr, "data": data} for addr, data in all_results.items()]
        return result

    def get_passive(self, dbase):
        if self.keep_addresses:
            all_results = {}
        else:
            result = {}
        for rec in self.analyzer.databases[dbase].get(self.flt(dbase)):
            if self.keep_addresses:
                result = all_results.setdefault(rec["addr"], {})
            firstseen = rec.get("firstseen", rec.get("lastseen"))
            lastseen = rec.get("lastseen", rec.get("firstseen"))
            if firstseen:
                if "firstseen" in result:
                    result["firstseen"] = min(result["firstseen"], firstseen)
                else:
                    result["firstseen"] = firstseen
            if lastseen:
                if "lastseen" in result:
                    result["lastseen"] = min(result["lastseen"], firstseen)
                else:
                    result["lastseen"] = firstseen
            recontype = rec["recontype"]
            result.setdefault("categories", set()).add(recontype)
            if rec.get("sensor"):
                result.setdefault("sources", set()).add(rec["sensor"])
            if recontype == "DNS_ANSWER":
                result.setdefault("hostnames", set()).add(rec["value"])
                self.analyzer._artifacts.add(("fqdn", rec["value"]))
                continue
            if recontype == "OPEN_PORT":
                port = rec["value"]
                try:
                    protocol, port = port.split("/", 1)
                except ValueError:
                    protocol = "tcp"
                port = int(port)
                result.setdefault("openports", set()).add("%s/%d" % (protocol, port))
                continue
            if recontype in {"TCP_SERVER_BANNER", "SSH_SERVER", "HTTP_SERVER_HEADER"}:
                result.setdefault("openports", set()).add("tcp/%(port)d" % rec)
                if "infos" not in rec:
                    continue
                info = rec["infos"]
                if info.get("service_name"):
                    result.setdefault("services", set()).add(info["service_name"])
                if info.get("service_product"):
                    result.setdefault("products", set()).add(info["service_product"])
                continue
            if recontype == "HTTP_CLIENT_HEADER":
                if rec["source"] != "USER-AGENT":
                    result.setdefault("useragents", set()).add(rec["value"])
                    self.analyzer._artifacts.add(("user-agent", rec["value"]))
                continue
            if recontype == "SSL_SERVER":
                if recontype != "cert":
                    # not handled yet
                    continue
                if "infos" not in rec:
                    continue
                cert = rec["infos"]
                result.setdefault("certs", set()).add(
                    (
                        cert["subject_text"],
                        cert["issuer_text"],
                        cert["md5"],
                        cert["sha1"],
                        cert["sha256"],
                    )
                )
                self.analyzer._artifacts.add(("certificate_hash", cert["sha1"]))
                continue
        for subr in all_results.values() if self.keep_addresses else [result]:
            self.clean_results(subr)
        if self.keep_addresses:
            return [{"addr": addr, "data": data} for addr, data in all_results.items()]
        return result

    @staticmethod
    def clean_results(result):
        for key, value in result.items():
            if isinstance(value, datetime):
                result[key] = str(value)
            if isinstance(value, set):
                if key == "openports":
                    result[key] = sorted(
                        value,
                        key=lambda x: [
                            [str, int][i](y) for i, y in enumerate(x.split("/", 1))
                        ],
                    )
                elif key == "certs":
                    result[key] = [
                        dict(zip(["subject", "issuer", "md5", "sha1", "sha256"], cert))
                        for cert in sorted(value)
                    ]
                else:
                    result[key] = sorted(value)

    def get(self, dbase):
        if dbase == "data":
            result = self.analyzer.databases[dbase].infos_byip(self.data)
            if "as_num" in result:
                self.analyzer._artifacts.add(("autonomous-system", result["as_num"]))
            return result
        if dbase == "scans":
            return self.get_scans(dbase)
        if dbase == "passive":
            return self.get_passive(dbase)
        raise ValueError()


class ProcessorNet(ProcessorIp):
    """Network processor

    data is a network, output is similar to ProcessorIp.

    """

    databases = ["passive", "scans"]
    keep_addresses = True

    def flt(self, dbase):
        return self.analyzer.databases[dbase].searchnet(self.data)


class ProcessorAsnum(ProcessorNet):
    """AS number processor

    data is an AS number, output is similar to ProcessorIp.

    """

    def flt(self, dbase):
        return self.analyzer.databases[dbase].searchasnum(int(self.data))


class ProcessorPort(Processor):

    databases = ["passive", "scans"]

    def flt(self, dbase):
        if "/" in self.data:
            proto, port = self.data.split("/", 1)
            port = int(port)
        else:
            proto = "tcp"
            port = int(self.data)
        if proto != "udp" and dbase == "passive":
            return self.analyzer.databases[dbase].searchnonexistent()
        return self.analyzer.databases[dbase].searchport(port, protocol=proto)


class ProcessorCert(Processor):

    databases = ["passive", "scans"]

    def flt(self, dbase):
        return self.analyzer.databases[dbase].searchcert(
            **{{32: "md5", 40: "sha1", 64: "sha256"}[len(self.data)]: self.data}
        )


class ProcessorFqdn(Processor):

    databases = ["passive", "scans"]

    def flt(self, dbase):
        if dbase == "passive":
            return self.analyzer.databases[dbase].searchdns(name=self.data)
        return self.analyzer.databases[dbase].searchhostname(self.data)

    def rev_flt(self, dbase):
        return self.analyzer.databases[dbase].searchdns(name=self.data, reverse=True)

    def get(self, dbase):
        if dbase == "passive":
            # specific case: two filters (w/ & w/o reverse=True)
            addresses = set()
            names = set()
            for rec in self.analyzer.databases[dbase].get(
                self.flt(dbase), fields=["addr", "value", "targetval"]
            ):
                if rec.get("addr"):
                    addresses.add(rec["addr"])
                if rec.get("targetval"):
                    names.add(rec["targetval"])
                names.add(rec["value"])
            self.analyzer._artifacts.update(("ip", value) for value in addresses)
            self.analyzer._artifacts.update(("fqdn", value) for value in names)
            return sorted(addresses, key=utils.ip2int) + sorted(
                names, key=lambda v: v.strip().split(".")[::-1]
            )
        return super().get(dbase)


class ProcessorDomain(ProcessorFqdn):
    def flt(self, dbase):
        if dbase == "passive":
            return self.analyzer.databases[dbase].searchdns(
                name=self.data, subdomains=True
            )
        return self.analyzer.databases[dbase].searchdomain(self.data)

    def rev_flt(self, dbase):
        return self.analyzer.databases[dbase].searchdns(
            name=self.data, subdomains=True, reverse=True
        )


class ProcessorUserAgent(Processor):

    databases = ["passive"]

    def flt(self, dbase):
        return dbase.searchuseragent(self.data)


class IVREAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self._artifacts = set()
        self.db = MetaDB(
            self.get_param(
                "config.db_url", default=config.DB if hasattr(config, "DB") else None
            ),
            urls={
                attr: url
                for attr, url in (
                    (
                        attr,
                        self.get_param(
                            "config.db_url_%s" % name,
                            default=(
                                getattr(config, "DB_%s" % attr.upper())
                                if hasattr(config, "DB_%s" % attr.upper())
                                else None
                            ),
                        ),
                    )
                    for name, attr in DATABASES
                )
                if url
            },
        )
        self.databases = {name: getattr(self.db, attr) for name, attr in DATABASES}

    def summary(self, raw):
        taxonomies = []
        if "data" in raw:
            cur = raw["data"]
            if "as_num" in cur:
                if "as_name" in cur:
                    value = "AS%(as_num)d-%(as_name)s" % (cur)
                else:
                    value = "AS%d" % cur["as_num"]
                taxonomies.append(self.build_taxonomy("info", "IVRE", "AS", value))
            if "country_code" in cur:
                if "country_name" in cur:
                    value = "%(country_code)s - %(country_name)s" % cur
                else:
                    value = cur["country_code"]
                taxonomies.append(self.build_taxonomy("info", "IVRE", "Country", value))
        for subrec in ["passive", "scans"]:
            if subrec not in raw:
                continue
            cur = raw[subrec]
            if not isinstance(raw[subrec], list):
                cur = [{"data": cur}]
            vulnerabilities = set()
            openports = set()
            for data in cur:
                res = data["data"]
                vulnerabilities.update(res.get("vulnerabilities", []))
                openports.update(res.get("openports", []))
            for vuln in vulnerabilities:
                taxonomies.append(
                    self.build_taxonomy("malicious", "IVRE", "Vulns", vuln)
                )
            taxonomies.append(
                self.build_taxonomy(
                    "info", "IVRE", "Distinct open ports", str(len(openports))
                )
            )
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        return [
            {"type": atype, "value": value}
            for atype, value in sorted(self._artifacts)
            if (atype, value) != (self.data_type, self.get_data())
        ]

    def run(self):
        self.report(Processor.from_analyzer(self).run())


if __name__ == "__main__":
    IVREAnalyzer().run()
