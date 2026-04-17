#!/usr/bin/env python3
# encoding: utf-8
import tempfile
import json
from os.path import basename
from cortexutils.analyzer import Analyzer
from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
from datetime import datetime

from anyrun import RunTimeException

from tools import catch_exceptions, connectors, extract_sandbox_iocs


class AnyRunAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.version = "Cortex:1.0"

        self.api_key = self.get_param("config.api_key", None, "ANY.RUN API key is missing")
        self.verify_ssl = self.get_param("config.verify_ssl", None, "Verify SSL option is missing")
        self.get_iocs = self.get_param("config.get_iocs", None, "Get IOCs option is missing")
        self.extract_malicious_iocs = self.get_param(
            "config.extract_malicious_iocs", None, "Extract Malicious IOCs option is missing"
        )

        self.get_html_report = self.get_param("config.get_html_report", None, None)
        self.get_network_traffic_dump = self.get_param("config.get_network_traffic_dump", None, None)

        self.os = self.get_param("config.os", None, None)
        self.analysis_type = self.get_param("config.analysis_type", None, None)

        if not self.api_key:
            raise RunTimeException(f"ANY.RUN API key is not specified.")

        if not self.verify_ssl:
            disable_warnings(InsecureRequestWarning)


    def summary(self, raw):
        taxonomies = []
        level = "safe"
        namespace = "AnyRun"

        if self.os:
            predicate = "Sandbox"

            if 50 < self.score < 100:
                level = "suspicious"
            elif self.score == 100:
                level = "malicious"
        else:
            predicate = "TI Lookup"
            level = self.verdict.lower() if self.verdict in ("Suspicious", "Malicious") else None

        taxonomies.append(
            self.build_taxonomy(level, namespace, predicate, self.verdict)
        )

        return {"taxonomies": taxonomies}


    def artifacts(self, raw):
        artifacts = list()

        if self.get_html_report:
            self.attach_file(
                artifacts,
                self.html_report,
                f"ANYRUN_analysis_report_{datetime.now().strftime(f'%Y_%m_%d_%H_%M_%S')}.html",
                "ANY.RUN Analysis report"
            )

        if self.get_network_traffic_dump:
            self.attach_file(
                artifacts,
                self.network_traffic_dump,
                f"ANYRUN_analysis_network_traffic_dump_{datetime.now().strftime(f'%Y_%m_%d_%H_%M_%S')}.pcap",
                "ANY.RUN Analysis network traffic dump"
            )

        if self.get_iocs:
            self.create_sandbox_observables(artifacts) if self.os else self.create_ti_lookup_observables(artifacts)

        return artifacts

    def attach_file(
        self,
        artifacts: list,
        report_content: str | bytes,
        report_name: str,
        observable_message: str
    ) -> None:
        """
        Saves a file as observable

        :param artifacts: The list of Artifacts
        :param report_content: Report payload
        :param report_name: Report name
        :param observable_message: Description
        """
        report_path = f"{tempfile.gettempdir()}/{report_name}"

        with open(report_path, 'wb') as file:
            file.write(report_content.encode() if isinstance(report_content, str) else report_content)

        artifacts.append(
            self.build_artifact(
                "file",
                report_path,
                message=observable_message,
                tags=["anyrun"]
            )
        )

    def create_sandbox_observables(self, artifacts: list):
        """
        Adds related Suspicious and Malicious indicators to the artifacts list

        :param artifacts: Artifacts list
        """
        for ioc in self.iocs:
            artifacts.append(
                self.build_artifact(
                    "hash" if ioc.get("type") == "sha256" else ioc.get("type"),
                    ioc.get("ioc"),
                    message="Detected by ANY.RUN Sandbox",
                    tags=["anyrun"]
                )
            )

    def create_ti_lookup_observables(self, artifacts: list):
        self.extract_lookup_iocs(self.related_urls, artifacts, "url", "url")
        self.extract_lookup_iocs(self.related_ips, artifacts, "ip", "destinationIP")
        self.extract_lookup_iocs(self.related_domains, artifacts, "domain", "domainName")
        self.extract_lookup_iocs(self.related_files, artifacts, "hash", "sha256")

    def extract_lookup_iocs(self, collection: list[str], artifacts: list, ioc_type: str, ioc_field: str) -> None:
        """
        Adds related Suspicious and Malicious indicators to the artifacts list

        :param collection: IOCs collection
        :param artifacts: Artifacts list
        :param ioc_type: IOC type
        :param ioc_field: IOC field name
        """
        for obj in collection:
            ioc = json.loads(obj)

            if self.extract_malicious_iocs and ioc.get("threatLevel") not in (1, 2):
                continue

            if ioc.get("threatLevel") not in (0, 1, 2):
                continue

            artifacts.append(
                self.build_artifact(
                    ioc_type,
                    ioc.get(ioc_field) if ioc_type != "hash" else ioc.get("hashes").get(ioc_field),
                    message="Detected by ANY.RUN TI Lookup",
                    tags=["anyrun"]
                )
            )

    @catch_exceptions
    def run(self):
        Analyzer.run(self)

        self.check_authorization()

        if self.os:
            self.run_analysis(connectors.get(self.os))
        else:
            self.get_reputation(connectors.get("ti_lookup"))


    def run_analysis(self, connector):
        """
        ANY.RUN Sandbox implementation. Sends data to ANY.RUN Sandbox, then parses the report

        :param connector: Sandbox connector
        """
        final_report = dict()

        with connector(self.api_key, self.version, self.verify_ssl) as connector:
            if self.analysis_type == "url":
                analysis_uuid = connector.run_url_analysis(**self.get_params())
            else:
                filepath = self.get_param("file", None, "File is missing")
                filename = self.get_param("filename", basename(filepath), None)
                with open(filepath, "rb") as file_content:
                    analysis_uuid = connector.run_file_analysis(file_content, filename, **self.get_params())

            for status in connector.get_task_status(analysis_uuid):
                print(status)

            report = connector.get_analysis_report(analysis_uuid)

            self.score = report.get("data").get("analysis").get("scores").get("verdict").get("score", 0)
            self.verdict = connector.get_analysis_verdict(analysis_uuid)
            self.html_report = connector.get_analysis_report(analysis_uuid, report_format="html")
            self.network_traffic_dump = connector.download_pcap(analysis_uuid)
            self.iocs = connector.get_analysis_report(
                analysis_uuid,
                report_format="ioc",
                ioc_reputation="suspicious" if self.extract_malicious_iocs else "all"
            )

            final_report["mainObject"] = report.get("data").get("analysis").get("content").get("mainObject")
            final_report["permanentUrl"] = report.get("data").get("analysis").get("permanentUrl")
            final_report["reports"] = report.get("data").get("analysis").get("reports")
            final_report["verdict"] = self.verdict
            final_report["related_domains"] = extract_sandbox_iocs(report, "dnsRequests", "domain")
            final_report["related_ips"] = extract_sandbox_iocs(report, "connections", "ip")
            final_report["related_urls"] = extract_sandbox_iocs(report, "httpRequests", "url")
            final_report["counters"] = report.get("data").get("counters")
            final_report["tags"] = (
                ",".join([tag.get("tag") for tag in tags])
                if (tags := report.get("data").get("analysis").get("tags")) else ""
            )
            final_report["mitre"] = (
                ",".join((set([obj.get("id") for obj in mitre])))
                if (mitre := report.get("data").get("mitre")) else ""
            )

            self.report(final_report)

    def get_reputation(self, connector) -> None:
        """
        ANY.RUN TI Lookup implementation. Sends data to ANY.RUN TI Lookup, then parses the report

        :param connector: Lookup connector
        """
        final_report = dict()

        entity_type = self.get_param("dataType", None, "Data Type option is missing")
        entity_value = self.extract_data()
        lookup_depth = self.get_param("config.lookup_depth", 180, None)

        if entity_type == "hash":
            hash_type = {32: "md5", 40: "sha1", 64: "sha256"}.get(len(entity_value))
            if not hash_type:
                raise RunTimeException("Unsupported hash type. Allowed: SHA1, SHA256, MD5")
            query_params = {hash_type: entity_value}
        else:
            entity_type = {"url": "url", "ip": "destination_ip", "domain": "domain_name"}.get(entity_type)
            query_params = {entity_type: entity_value}

        with connector(self.api_key, self.version, self.verify_ssl) as connector:
            summary = connector.get_intelligence(**query_params, lookup_depth=lookup_depth, parse_response=True)
            self.verdict = summary.verdict()

        final_report["treat_level"] = summary.verdict()
        final_report["ti_lookup_url"] = summary.intelligence_url(entity_value)
        final_report["last_seen"] = summary.last_modified()
        final_report["industries"] = summary.industries()
        final_report["tags"] = summary.tags()
        final_report["asn"] = summary.asn()
        final_report["geo"] = summary.country()
        final_report["asn"] = summary.country()
        final_report["detected_type"] = entity_value

        self.related_urls = [url.json() for url in summary.related_urls]
        self.related_ips = [ip.json() for ip in summary.related_ips]
        self.related_domains = [domain.json() for domain in summary.related_dns]
        self.related_files = [file.json() for file in summary.related_files]

        final_report["related_urls"] = self.related_urls
        final_report["related_ips"] = self.related_ips
        final_report["related_domains"] = self.related_domains
        final_report["related_files"] = self.related_files

        if tasks := summary.tasks(tasks_range=20):
            final_report["last_tasks"] = tasks

        if file_meta := summary.file_meta():
            final_report["file_extension"] = file_meta.filepath.split(".")[-1]
            final_report["filename"] = file_meta.filename
            final_report["filepath"] = file_meta.filepath
            final_report["sha1"] = file_meta.hashes.sha1
            final_report["sha256"] = file_meta.hashes.sha256
            final_report["md5"] = file_meta.hashes.md5
            final_report["ssdeep"] = file_meta.hashes.ssdeep

        self.report(final_report)

    def get_params(self) -> dict:
        """
        Prepares Sandbox analysis parameters

        :return: Prepared parameters
        """
        params = {
            "env_locale": self.get_param("config.env_locale", None, None),
            "opt_network_connect": self.get_param("config.opt_network_connect", None, None),
            "opt_network_fakenet": self.get_param("config.opt_network_fakenet", None, None),
            "opt_network_tor": self.get_param("config.opt_network_tor", None, None),
            "opt_network_geo": self.get_param("config.opt_network_geo", None, None),
            "opt_network_mitm": self.get_param("config.opt_network_mitm", None, None),
            "opt_network_residential_proxy": self.get_param("config.opt_network_residential_proxy", None, None),
            "opt_network_residential_proxy_geo": self.get_param("config.opt_network_residential_proxy_geo", None, None),
            "opt_privacy_type": self.get_param("config.opt_privacy_type", None, None),
            "opt_auto_delete_after": self.get_param("config.opt_auto_delete_after", None, None),
            "obj_ext_extension": self.get_param("config.obj_ext_extension", None, None),
            "user_tags": self.get_param("config.user_tags", None, None),
            "opt_timeout": self.get_param("config.opt_timeout", None, None),
            "env_os": self.get_param("config.env_os", None, None),
            "env_version": self.get_param("config.env_version", None, None),
            "env_bitness": self.get_param("config.env_bitness", None, None),
            "env_type": self.get_param("config.env_type", None, None),
            "obj_ext_cmd": self.get_param("config.obj_ext_cmd", None, None),
            "obj_ext_startfolder": self.get_param("config.obj_ext_startfolder", None, None),
            "obj_force_elevation": self.get_param("config.obj_force_elevation", None, None),
            "auto_confirm_uac": self.get_param("config.auto_confirm_uac", None, None),
            "run_as_root": self.get_param("config.run_as_root", None, None),
            "lookup_depth": self.get_param("config.lookup_depth", None, None),
            "obj_type": self.get_param("config.obj_type", None, None),
            "obj_value": self.get_param("config.obj_value", None, None),
        }

        if self.analysis_type == "url":
            params["obj_url"] = self.extract_data()

        return {key: value for key, value in params.items() if value is not None}

    @catch_exceptions
    def check_authorization(self) -> None:
        """
        Checks connection to ANY.RUN services.
        """
        connector = connectors.get("ti_lookup") if self.analysis_type == "ti_lookup" else connectors.get("base")

        with connector(self.api_key, self.version, self.verify_ssl) as connector:
            connector.check_authorization()

    def extract_data(self) -> str:
        """
        Extracts data from parameters, prepares it for sending to ANY.RUN

        :return: Prepared data
        """
        data = self.get_param("data", None, "Data option is missing")
        data = data.replace("[", "").replace("]", "").replace("hxxp", "http")
        return data

if __name__ == "__main__":
    AnyRunAnalyzer().run()
