#!/usr/bin/env python3
import io
import json
import requests
import ipaddress

from cortexutils.analyzer import Analyzer
from cortexutils.extractor import Extractor
from glob import glob
from os.path import exists

try:
    import sqlalchemy as db
    from tld import get_tld

    USE_DB = True
except ImportError:
    USE_DB = False


class MISPWarninglistsAnalyzer(Analyzer):
    """
    This analyzer compares given data to the MISP warning lists obtainable via
    https://github.com/MISP/misp-warninglists.
    Configuration options are:

    ```
    MISPWarningLists {
      path = "/path/to/misp-warninglists/repository"  # Default: "misp-warninglists"
    }
    ```
    """

    def __init__(self):
        Analyzer.__init__(self)

        self.data = self.get_data()
        self.path = self.get_param("config.path", "misp-warninglists")
        conn = self.get_param("config.conn", None)
        self.warninglists = self.readwarninglists() if not conn or not USE_DB else None
        self.engine = db.create_engine(conn) if conn and USE_DB else None
        if not exists(self.path) and not self.engine:
            self.error("wrong configuration settings.")

    def readwarninglists(self):
        files = glob("{}/lists/*/*.json".format(self.path))
        listcontent = []
        for file in files:
            with io.open(file, "r") as fh:
                content = json.loads(fh.read())
                values = Extractor().check_iterable(content.get("list", []))
                obj = {
                    "name": content.get("name", "Unknown"),
                    "values": [value["data"] for value in values],
                    "dataTypes": [value["dataType"] for value in values],
                }
                listcontent.append(obj)
        return listcontent

    def lastlocalcommit(self):
        try:
            with io.open("{}/.git/refs/heads/master".format(self.path), "r") as fh:
                return fh.read().strip("\n")
        except Exception as e:
            return "Error: could not get local commit hash ({}).".format(e)

    @staticmethod
    def lastremotecommit():
        url = "https://api.github.com/repos/misp/misp-warninglists/branches/master"
        try:
            result_dict = requests.get(url).json()
            return result_dict["commit"]["sha"]
        except Exception as e:
            return "Error: could not get remote commit hash ({}).".format(e)

    def run(self):
        results = []
        data = self.data

        if self.data_type == "ip":
            try:
                data = ipaddress.ip_address(self.data)
            except ValueError:
                return self.error(
                    "{} is said to be an IP address but it isn't".format(self.data)
                )

        if not self.engine:
            for list in self.warninglists:
                if self.data_type not in list.get("dataTypes"):
                    continue

                if self.data_type == "ip":
                    for net in list.get("values", []):
                        try:
                            if data in ipaddress.ip_network(net):
                                results.append({"name": list.get("name")})
                                break
                        except ValueError:
                            # Ignoring if net is not a valid IP network since we want to compare ip addresses
                            pass
                else:
                    if data.lower() in list.get("values", []):
                        results.append({"name": list.get("name")})

                self.report(
                    {
                        "results": results,
                        "mode": "json",
                        "is_uptodate": self.lastlocalcommit()
                        == self.lastremotecommit(),
                    }
                )
        else:
            field = None
            if self.data_type == "ip":
                sql = (
                    "SELECT list_name, list_version, address as value FROM warninglists WHERE address >>= inet '%s'"
                    % data
                )
            elif self.data_type == "hash":
                sql = (
                    "SELECT list_name, list_version, hash as value FROM warninglists WHERE hash='%s'"
                    % data
                )
            else:
                ext = get_tld(data, fix_protocol=True, as_object=True)
                subdomain = ext.subdomain if ext.subdomain != "" else None
                domain = ext.domain
                tld = ext.tld
                query = ext.parsed_url[2] if ext.parsed_url[2] != "" else None

                if not domain or not tld:
                    return self.error(
                        "{} is not a valid url/domain/fqdn".format(self.data)
                    )

                if query:
                    if subdomain and subdomain != "*":
                        sql = (
                            "SELECT list_name, list_version, concat(subdomain, '.', domain, '.', tld, query) as value FROM warninglists WHERE subdomain = '%s' and domain = '%s' and tld = '%s' and query = '%s'"
                            % (subdomain, domain, tld, query)
                        )
                    else:
                        sql = (
                            "SELECT list_name, list_version, concat(domain, '.', tld, query) as value FROM warninglists WHERE domain = '%s' and tld = '%s' and query = '%s'"
                            % (domain, tld, query)
                        )
                elif not subdomain:
                    sql = (
                        "SELECT list_name, list_version, concat(domain, '.', tld) as value FROM warninglists WHERE subdomain is null and domain = '%s' and tld = '%s'"
                        % (domain, tld)
                    )
                elif subdomain == "*":
                    sql = (
                        "SELECT list_name, list_version, concat(subdomain, '.', domain, '.', tld) as value FROM warninglists WHERE subdomain is not null and domain = '%s' and tld = '%s'"
                        % (domain, tld)
                    )
                else:
                    sql = (
                        "SELECT list_name, list_version, concat(subdomain, '.', domain, '.', tld) as value  FROM warninglists WHERE (subdomain = '%s' or subdomain = '*') and domain = '%s' and tld = '%s'"
                        % (subdomain, domain, tld)
                    )
            values = self.engine.execute(sql)
            self.engine.dispose()
            if values.rowcount > 0:
                for row in values:
                    results.append(
                        {
                            key: value
                            for (key, value) in zip(
                                ["list_name", "list_version", "value"], row
                            )
                        }
                    )
            self.report({"results": results, "mode": "db", "is_uptodate": "N/A"})

    def summary(self, raw):
        taxonomies = []
        if len(raw["results"]) > 0:
            taxonomies.append(
                self.build_taxonomy(
                    "suspicious", "MISP", "Warninglists", "Potential fp"
                )
            )
        else:
            taxonomies.append(
                self.build_taxonomy("info", "MISP", "Warninglists", "No hits")
            )

        if raw.get("mode", None) == "json" and not raw.get("is_uptodate", False):
            taxonomies.append(
                self.build_taxonomy("info", "MISP", "Warninglists", "Outdated")
            )

        return {"taxonomies": taxonomies}


if __name__ == "__main__":
    MISPWarninglistsAnalyzer().run()
