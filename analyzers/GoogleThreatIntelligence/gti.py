import hashlib
import os
import json
from typing import Dict, List, Any
from cortexutils.analyzer import Analyzer
from gti_get_ioc_report import GTIGetReportAnalyzer
from gti_scan import GTIScanAnalyzer
from gti_private_scan import GTIPrivateScanAnalyzer


class GoogleThreatIntelligenceAnalyzer(Analyzer):
    """
    Cortex Analyzer for Google Threat Intelligence (GTI).

    This analyzer acts as a router, directing analysis requests to one of three
    specialized GTI services based on the user's configuration:
    1.  **get**: Retrieves a report for an existing IOC (IP, domain, hash, URL).
    2.  **scan**: Submits a URL or file for a public scan.
    3.  **privateScan**: Submits a URL or file for a private scan.

    It inherits from the base Cortex Analyzer and implements the required
    `run`, `summary`, and `artifacts` methods.
    """

    def __init__(self) -> None:
        """
        Initializes the analyzer.

        Retrieves and validates the 'service' (scan, privateScan, get) and
        'gti_api_key' from the Cortex configuration.
        """
        Analyzer.__init__(self)
        self.service = self.get_param("config.service", None, "Please specify a service type")
        self.gti_api_key = self.get_param("config.gti_api_key", None, "Please provide your Google Threat Intelligence API key")
        if self.service not in ["scan", "privateScan", "get"]:
            self.error("Please select a valid service: scan, privateScan, or get.")

    def artifacts(self, raw: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Generates Cortex artifacts from the raw report data.

        This method extracts Indicators of Compromise (IOCs) from the 'iocs'
        field of the raw response (which is populated by the helper analyzers)
        and formats them as standard Cortex artifacts.

        Args:
            raw: The raw JSON report from the analyzer's run method.

        Returns:
            A list of Cortex artifact dictionaries.
        """
        artifacts = []
        iocs = raw.get("iocs", {})
        for ioc_type, ioc_list in iocs.items():
            if not isinstance(ioc_list, list):
                continue
            for ioc in ioc_list:
                if not isinstance(ioc, dict):
                    continue
                data = ioc.get("data", "")
                if data:
                    artifacts.append(self.build_artifact(ioc_type, data, tags=ioc.get("tags", [])))
        return artifacts

    def summary(self, raw: Dict[str, Any]) -> Dict[str, List[Dict[str, str]]]:
        """
        Creates a summary (taxonomies) for the Cortex UI.

        This method generates a "short report" based on key findings like
        threat score, severity, and analysis statistics (for 'get' and 'scan').

        Args:
            raw: The raw JSON report from the analyzer's run method.

        Returns:
            A dictionary containing a list of taxonomies.
        """
        taxonomies = []
        if raw is None or "errorMessage" in raw:
            return {"taxonomies": taxonomies}

        namespace = "GTI"
        predicate = "IOCReport"
        stats_field = "last_analysis_stats"
        if self.service == "scan":
            predicate = "Scan"
        elif self.service == "privateScan":
            predicate = "PrivateScan"

        attributes = raw.get("attributes", {})
        gti_threat_score = (
            attributes.get("gti_assessment", {}).get("threat_score", {}).get("value", 0)
        )
        value = f"Threat Score={gti_threat_score}"
        if gti_threat_score >= 80:
            level = "malicious"
        elif 60 <= gti_threat_score <= 79:
            level = "suspicious"
        elif 41 <= gti_threat_score <= 59:
            level = "info"
        else:
            level = "safe"
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        gti_threat_severity = (
            attributes.get("gti_assessment", {})
            .get("severity", {})
            .get("value", "SEVERITY_UNKNOWN")
        )
        severity_display = gti_threat_severity.replace("SEVERITY_", "").title()
        value = f"Severity={severity_display}"
        if gti_threat_severity == "SEVERITY_HIGH":
            level = "malicious"
        elif gti_threat_severity == "SEVERITY_MEDIUM":
            level = "suspicious"
        elif gti_threat_severity == "SEVERITY_LOW":
            level = "info"
        else:
            level = "safe"
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        if self.service in ["get", "scan"]:
            result: Dict[str, int] = {
                "malicious": 0,
                "suspicious": 0,
                "timeout": 0,
                "harmless": 0,
                "undetected": 0,
                "confirmed-timeout": 0,
                "failure": 0,
                "type-unsupported": 0,
                "total": 0,
            }

            if stats_field in attributes:
                stats = attributes[stats_field]
                for category in result.keys():
                    if category != "total":
                        result[category] = stats.get(category, 0)
                        result["total"] += result[category]
            value = f"{result['malicious'] + result['suspicious']}/{result['total']}"
            if result["malicious"] > 0:
                level = "malicious"
            elif result["suspicious"] > 0:
                level = "suspicious"
            elif any(
                result.get(cat, 0) > 0
                for cat in [
                    "timeout",
                    "harmless",
                    "undetected",
                    "confirmed-timeout",
                    "failure",
                    "type-unsupported",
                ]
            ):
                level = "info"
            else:
                level = "safe"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self) -> None:
        """
        Main entry point for the analyzer.

        This method determines which GTI service to call ('get', 'scan', 'privateScan')
        based on the analyzer's configuration and the input data type. It then
        delegates the actual API call to the appropriate helper class
        (GTIGetReportAnalyzer, GTIScanAnalyzer, GTIPrivateScanAnalyzer).
        """
        iocs: Dict[str, List[Dict[str, Any]]] = {
            "ip": [],
            "domain": [],
            "url": [],
            "hash": [],
        }
        results = None

        if self.service == "scan":
            gti_scan_report_analyzer = GTIScanAnalyzer(self.gti_api_key)
            if self.data_type == "url":
                input_url = self.get_param("data", None, "Please provide a URL to scan")
                results = gti_scan_report_analyzer.get_scan_url_report(url=input_url, iocs=iocs)
            elif self.data_type == "file":
                filepath = self.get_param("file", None, "Please provide a file to scan")
                results = gti_scan_report_analyzer.get_scan_file_report(file_path=filepath, iocs=iocs)
            else:
                self.error(f"The scan service does not support the selected data type: {self.data_type}")

        elif self.service == "privateScan":
            gti_private_scan_report_analyzer = GTIPrivateScanAnalyzer(self.gti_api_key)
            if self.data_type == "url":
                input_url = self.get_param("data", None, "Please provide a URL to scan")
                results = gti_private_scan_report_analyzer.get_scan_private_url_report(url=input_url)
            elif self.data_type == "file":
                filepath = self.get_param("file", None, "Please provide a file to scan")
                results = gti_private_scan_report_analyzer.get_scan_private_file_report(file_path=filepath)
            else:
                self.error(f"The private scan service does not support the selected data type: {self.data_type}")

        elif self.service == "get":
            gti_get_report_analyzer = GTIGetReportAnalyzer(self.gti_api_key)
            if self.data_type == "ip":
                ip_address = self.get_param("data", None, "Please provide an IP address")
                results = gti_get_report_analyzer.get_ip_address_report(ip_address=ip_address, iocs=iocs)
            elif self.data_type in ["domain", "fqdn"]:
                domain = self.get_param("data", None, "Please provide a domain name")
                results = gti_get_report_analyzer.get_domain_report(domain=domain, iocs=iocs)
            elif self.data_type == "hash":
                file_hash = self.get_param("data", None, "Please provide a file hash")
                results = gti_get_report_analyzer.get_file_report(file_hash=file_hash, iocs=iocs)
            elif self.data_type == "file":
                filepath = self.get_param("file", None, "Please provide a file")
                file_hash = self.compute_file_hash(filepath)
                results = gti_get_report_analyzer.get_file_report(file_hash=file_hash, iocs=iocs)
            elif self.data_type == "url":
                url = self.get_param("data", None, "Please provide a URL")
                results = gti_get_report_analyzer.get_url_report(url=url, iocs=iocs)
            else:
                self.error(f"The get service does not support the selected data type: {self.data_type}")

        report_data = {}

        if results is None:
            self.error("Unable to retrieve Google Threat Intelligence data.")
            
        results = json.loads(
            json.dumps(results), 
            object_hook=lambda d: {k.lower(): v for k, v in d.items()}
        )
        if "response" in results and "data" in results["response"]:
            report_data = results["response"]["data"]
            report_data["iocs"] = iocs
            self.report(report_data, ensure_ascii=True)
        else:
            self.error("Received incomplete data from the Google Threat Intelligence service.")

    def compute_file_hash(self, filepath: str) -> str:
        """
        Computes the SHA256 hash of a file.

        Performs validation (exists, is file, not empty) before
        reading the file and computing the hash. Reports an error
        if validation fails or the file cannot be read.

        Args:
            filepath: The path to the file provided by Cortex.

        Returns:
            The SHA256 hash (hex digest) of the file.
        """
        if not os.path.exists(filepath):
            self.error(f"File not found: {filepath}")
        if not os.path.isfile(filepath):
            self.error(f"The selected path does not point to a valid file: {filepath}")
        if os.path.getsize(filepath) == 0:
            self.error("The file is empty. Please provide a valid file.")
        try:
            with open(filepath, "rb") as file:
                return self.file_to_sha256(file)
        except IOError:
            self.error("Unable to read the file. Please check file permissions.")
        return ""
    
    def file_to_sha256(self, file) -> str:
        """
        Utility function to compute SHA256 from a file object.

        Reads the file in chunks to handle large files efficiently.

        Args:
            file: A file object opened in binary read mode ('rb').

        Returns:
            The SHA2S256 hash (hex digest) as a string.
        """
        sha256_hash = hashlib.sha256()
        while chunk := file.read(4096):
            sha256_hash.update(chunk)
        return sha256_hash.hexdigest()


if __name__ == "__main__":
    GoogleThreatIntelligenceAnalyzer().run()
