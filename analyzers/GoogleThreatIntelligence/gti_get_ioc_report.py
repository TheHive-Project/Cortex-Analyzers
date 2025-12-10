from typing import Dict, List, Optional, Tuple
from gti_api_helper import GoogleThreatIntelligenceClient
from cortexutils.analyzer import Analyzer
from constants import (
    ATTRIBUTES,
    RELATIONSHIP_ATTRIBUTES_MAP,
    IOC_ENDPOINT_MAP,
    IOC_RELATIONSHIP_KEYS,
    IOC_EXTRACTION_MAP,
    REGION_AND_INDUSTRY_RELATIONSHIPS,
    MAX_PAGINATION_ITERATIONS,
    DEFAULT_LIMIT,
)


class GTIGetReportAnalyzer(Analyzer):
    """
    Retrieves and enriches “get” reports from Google Threat Intelligence (GTI).

    This analyzer:
    - Fetches base IOC reports (IP, domain, hash, URL, file)
    - Fetches paginated relationships for each IOC
    - Extracts related IOCs for Cortex artifacts
    - Extracts and formats MITRE ATT&CK details for file hashes
    """

    def __init__(self, api_key: str) -> None:
        """
        Initialize the GTI client.

        Args:
            api_key: Google Threat Intelligence API key.
        """
        try:
            self.gti_client = GoogleThreatIntelligenceClient(api_key) if api_key else None
            super().__init__()
        except Exception:
            self.gti_client = None

    def _handle_api_error(self, api_response: Optional[Dict]) -> Optional[str]:
        """
        Validates the response returned by GTI.

        Returns:
            A string error message if the API response contains errors,
            otherwise None.
        """
        try:
            if not api_response:
                return "Unable to connect to the threat intelligence service. Please try again."
            if not isinstance(api_response, dict):
                return "Unexpected response format received from the service."
            if not api_response.get("success", False) or api_response.get("error"):
                return api_response.get("error", "Unable to retrieve threat intelligence data.")
            return None
        except Exception:
            return "Unable to process service response."

    def _fetch_paginated_relationship_data(self, relationship_name: str, indicator_value: str, ioc_type: str) -> List[Dict]:
        """
        Fetches all paginated GTI relationship data for a given IOC.

        GTI returns relationship data in cursor-paginated format.  
        This method repeatedly follows the cursor until no more pages exist.

        Args:
            relationship_name: Name of GTI relationship (e.g., 'resolutions').
            indicator_value: IOC being queried.
            ioc_type: IOC type ('ip', 'domain', 'file', etc.)

        Returns:
            List of all gathered relationship entries.
        """
        try:
            if not self.gti_client or ioc_type not in IOC_ENDPOINT_MAP:
                return []
            if not indicator_value or not isinstance(indicator_value, str):
                return []

            endpoint = f"{IOC_ENDPOINT_MAP[ioc_type]}/{indicator_value}/{relationship_name}"
            attributes = RELATIONSHIP_ATTRIBUTES_MAP.get(relationship_name, ATTRIBUTES)
            params = {"attributes": attributes, "limit": DEFAULT_LIMIT}

            all_items = []

            for _ in range(MAX_PAGINATION_ITERATIONS):
                response = self.gti_client.make_api_request(endpoint=endpoint, method="GET", params=params)

                if self._handle_api_error(response):
                    break

                api_data = response.get("response", {})
                batch_items = api_data.get("data", [])

                processed = self._process_region_and_industry_data(batch_items, relationship_name)
                all_items.extend(processed)

                cursor = api_data.get("meta", {}).get("cursor")
                if not cursor:
                    break

                params["cursor"] = cursor

            return all_items

        except Exception:
            return []

    def _process_region_and_industry_data(self, relationship_items: List[Dict], relationship_name: str) -> List[Dict]:
        """
        Processes region and industry relationship structures.

        Some relationships (e.g., regions, industries) require flattening.
        This method routes those items to a dedicated processor.

        Returns:
            Modified or original list of relationship entries.
        """
        try:
            if relationship_name not in REGION_AND_INDUSTRY_RELATIONSHIPS:
                return relationship_items
            return [self._process_single_item(item) for item in relationship_items]
        except Exception:
            return relationship_items

    def _process_single_item(self, item: Dict) -> Dict:
        """
        Flattens hierarchy-based GTI region/industry structures into simpler strings.

        GTI returns nested region/industry hierarchies.  
        This method extracts readable values.

        Returns:
            Updated relationship item with flattened attributes.
        """
        try:
            if not isinstance(item, dict):
                return item

            attributes = item.get("attributes", {})
            if not isinstance(attributes, dict):
                return item

            processed_item = item.copy()
            processed_attributes = attributes.copy()

            processed_attributes.update(
                {
                    "source_regions_hierarchy": self._extract_countries_from_hierarchy(processed_attributes.get("source_regions_hierarchy", [])),
                    "targeted_regions_hierarchy": self._extract_countries_from_hierarchy(processed_attributes.get("targeted_regions_hierarchy", [])),
                    "targeted_industries_tree": self._extract_industries_from_tree(processed_attributes.get("targeted_industries_tree", [])),
                }
            )

            processed_item["attributes"] = processed_attributes
            return processed_item

        except Exception:
            return item

    def _extract_countries_from_hierarchy(self, regions_hierarchy: List[Dict]) -> str:
        """
        Convert region hierarchy list into comma-separated country names.

        Returns:
            A readable string such as "USA, Germany, India".
        """
        try:
            countries = {
                region.get("country", "").strip()
                for region in regions_hierarchy
                if isinstance(region, dict) and region.get("country")
            }
            countries.discard("")
            return ", ".join(sorted(countries))
        except Exception:
            return ""

    def _extract_industries_from_tree(self, industries_tree: List[Dict]) -> str:
        """
        Convert GTI industry tree structures into flattened industry names.

        Returns:
            A comma-separated list of industry names.
        """
        try:
            industries = {
                entry.get("industry", "").strip()
                for entry in industries_tree
                if isinstance(entry, dict) and entry.get("industry")
            }
            industries.discard("")
            return ", ".join(sorted(industries))
        except Exception:
            return ""

    def _process_relationships(self, report_data: Dict, indicator_value: str, ioc_type: str) -> Dict[str, List]:
        """
        Handles enrichment of IOC relationships, including fetching paginated data.

        Args:
            report_data: The base GTI report’s "response" block.
            indicator_value: IOC being enriched.
            ioc_type: IOC type.

        Returns:
            Dictionary of enriched relationship data for the report.
        """
        try:
            relationships = (
                report_data.get("data", {}).get("relationships", {})
                if isinstance(report_data, dict)
                else {}
            )

            if not isinstance(relationships, dict):
                return {}

            enriched = {}

            for rel_name, rel_data in relationships.items():
                if not isinstance(rel_data, dict):
                    enriched[rel_name] = []
                    continue

                items = rel_data.get("data", [])
                cursor = rel_data.get("meta", {}).get("cursor")

                if cursor:
                    enriched[rel_name] = self._fetch_paginated_relationship_data(rel_name, indicator_value, ioc_type)
                else:
                    enriched[rel_name] = self._process_region_and_industry_data(items, rel_name)

            return enriched

        except Exception:
            return {}

    def _extract_mitre_attack_data(self, mitre_response: Dict) -> List[Dict]:
        """
        Extracts MITRE ATT&CK data from GTI sandbox results.

        Converts deeply nested GTI MITRE structures into a uniform list.

        Returns:
            List of tactics with technique details.
        """
        try:
            mitre_data = []
            response_data = (
                mitre_response.get("response", {}).get("data", {})
                if isinstance(mitre_response, dict)
                else {}
            )

            for sandbox_name, sandbox_data in response_data.items():
                tactics = sandbox_data.get("tactics", [])
                for tactic in tactics:
                    techniques = tactic.get("techniques", [])
                    mitre_data.append(
                        {
                            "id": tactic.get("id", ""),
                            "name": tactic.get("name", ""),
                            "sandbox_name": sandbox_name,
                            "link": tactic.get("link", ""),
                            "description": tactic.get("description", ""),
                            "techniques": [
                                {
                                    "id": t.get("id", ""),
                                    "name": t.get("name", ""),
                                    "link": t.get("link", ""),
                                    "description": t.get("description", ""),
                                    "signatures": (
                                        t.get("signatures", [])
                                        if isinstance(t.get("signatures"), list)
                                        else []
                                    ),
                                }
                                for t in techniques
                                if isinstance(t, dict)
                            ],
                        }
                    )

            return mitre_data

        except Exception:
            return []

    def _extract_ioc_from_relationship_item(self, relationship_name: str, data: Dict, data_type: str) -> Optional[Tuple[str, Dict]]:
        """
        Extracts related IOCs embedded inside GTI relationship entries.

        Supports mapping:
            resolutions → IP
            communicating_files → hash
            contacted_domains → domain
            etc.

        Returns:
            Tuple(ioc_type, formatted_artifact_dict) or None.
        """
        try:
            if relationship_name not in IOC_EXTRACTION_MAP or not isinstance(data, dict):
                return None

            ioc_type, id_key, src = IOC_EXTRACTION_MAP[relationship_name]

            if src == "attributes":
                attr = data.get("attributes", {})
                value = attr.get(id_key) if isinstance(attr, dict) else None
            else:
                value = data.get(id_key)

            if not value or not isinstance(value, str):
                return None

            return ioc_type, {
                "data": value,
                "tags": [f"known-relationship:{data_type.replace('_', '-')}"],
            }

        except Exception:
            return None

    def extract_ioc_from_the_report_relationship(self, report: Dict, iocs: Dict[str, List], data_type: str) -> None:
        """
        Traverses GTI report relationships and extracts related IOCs.

        Populates the Cortex IOC dictionary used for artifact generation.
        """
        try:
            relationships = report.get("response", {}).get("data", {}).get("relationships", {}) if isinstance(report, dict) else {}

            for rel_name, rel_items in relationships.items():
                if rel_name not in IOC_RELATIONSHIP_KEYS or not isinstance(rel_items, list):
                    continue

                for item in rel_items:
                    extracted = self._extract_ioc_from_relationship_item(rel_name, item, data_type)
                    if extracted:
                        ioc_type, formatted = extracted
                        iocs.setdefault(ioc_type, []).append(formatted)

        except Exception:
            pass

    def _get_report_template(self, indicator: str, ioc_type: str, iocs: Dict[str, List], fetch_func, use_url_id: bool = False) -> Dict:
        """
        Generic template function for fetching and enriching GTI reports.

        Steps:
        1. Validate input
        2. Fetch base report using provided GTI function
        3. Validate response
        4. Enrich with relationship data (including pagination)
        5. Extract related IOCs
        6. Return final enriched GTI report

        Args:
            indicator: IOC string
            ioc_type: IOC type name
            iocs: IOC extraction container
            fetch_func: GTI client method
            use_url_id: Whether URL needs Base64-encoded ID for relationships
        """
        try:
            if not self.gti_client:
                self.error("The threat intelligence client is not initialized.")

            if not indicator or not isinstance(indicator, str):
                self.error("Please provide a valid indicator value.")

            report = fetch_func(indicator)
            err = self._handle_api_error(report)
            if err:
                self.error(err)

            response = report.get("response", {})
            if not isinstance(response, dict):
                self.error("Unexpected response format received from the service.")

            if use_url_id:
                data = response.get("data", {})
                derived_indicator = data.get("id", "") if isinstance(data, dict) else ""
                if not derived_indicator:
                    self.error("Unable to process URL identifier.")
            else:
                derived_indicator = indicator

            enriched = self._process_relationships(response, derived_indicator, ioc_type)
            if "data" in response and isinstance(response["data"], dict):
                response["data"]["relationships"] = enriched

            self.extract_ioc_from_the_report_relationship(report, iocs, ioc_type)

            return report

        except Exception as e:
            self.error(f"Unable to process {ioc_type} report: {str(e)}")

    def get_ip_address_report(self, ip_address: str, iocs: Dict[str, List]) -> Dict:
        """
        Fetches an enriched GTI report for an IP address.
        """
        if not self.gti_client:
            self.error("The threat intelligence client is not initialized.")
        return self._get_report_template(ip_address, "ip", iocs, self.gti_client.get_ip_report)

    def get_domain_report(self, domain: str, iocs: Dict[str, List]) -> Dict:
        """
        Fetches an enriched GTI report for a domain.
        """
        if not self.gti_client:
            self.error("The threat intelligence client is not initialized.")
        return self._get_report_template(domain, "domain", iocs, self.gti_client.get_domain_report)

    def get_url_report(self, url: str, iocs: Dict[str, List]) -> Dict:
        """
        Fetches an enriched GTI report for a URL.
        """
        if not self.gti_client:
            self.error("The threat intelligence client is not initialized.")
        return self._get_report_template(url, "url", iocs, self.gti_client.get_url_report, use_url_id=True)

    def get_file_report(self, file_hash: str, iocs: Dict[str, List]) -> Dict:
        """
        Fetches an enriched GTI report for a FILE hash.

        Additionally:
        - Fetches MITRE ATT&CK mapping
        - Attaches MITRE details to the final report
        """
        try:
            if not self.gti_client:
                self.error("The threat intelligence client is not initialized.")

            file_report = self._get_report_template(file_hash, "file", iocs, self.gti_client.get_file_report)

            mitre = self.gti_client.get_mitre_attack_data(file_hash)
            err = self._handle_api_error(mitre)
            if err:
                return file_report

            mitre_data = self._extract_mitre_attack_data(mitre)

            if isinstance(file_report.get("response"), dict) and isinstance(file_report["response"].get("data"), dict):
                file_report["response"]["data"]["mitre_attack_data"] = mitre_data

            return file_report

        except Exception as e:
            self.error(f"Unable to process file report: {str(e)}")
            