import time
import os
from typing import Any, Dict
from cortexutils.analyzer import Analyzer
from gti_api_helper import GoogleThreatIntelligenceClient
from constants import MAX_FILE_SIZE, POLLING_INTERVAL


class GTIPrivateScanAnalyzer(Analyzer):
    """
    Orchestrates private scanning of files and URLs using Google Threat Intelligence (GTI).

    This analyzer:
    - Validates all private-scan parameters (sandbox, retention, locale, etc.)
    - Submits a file or URL for private analysis
    - Polls GTI until scan finishes
    - Retrieves the final "private" report
    """

    def __init__(self, api_key: str) -> None:
        """
        Initialize the private scan analyzer and prepare GTI client + payload.

        Args:
            api_key: GTI API key.
        """
        super().__init__()
        try:
            self.gti_client = GoogleThreatIntelligenceClient(api_key)
            self.payload = self._initialize_payload()
        except Exception as e:
            self.error(f"Unable to initialize analyzer: {str(e)}")

    def _clean_parameter_value(self, value: Any) -> Any:
        """
        Clean a parameter value by:
        - Stripping whitespace
        - Converting true/false strings to boolean
        - Converting empty strings to None
        """
        try:
            if isinstance(value, str):
                stripped = value.strip()
                if stripped == "":
                    return None
                if stripped.lower() in ["true", "false"]:
                    return stripped.lower() == "true"
                return stripped
            return value
        except Exception:
            return value

    def _initialize_payload(self) -> Dict[str, Any]:
        """
        Determines whether parameters belong to file-scan or URL-scan
        and validates them accordingly.

        Returns the complete GTI private-scan payload.
        """
        try:
            if self.data_type == "file":
                payload = self._validate_file_parameters()
            elif self.data_type == "url":
                payload = self._validate_url_parameters()
            else:
                self.error(f"Unsupported data type: {self.data_type}")

            if isinstance(payload, dict) and "error" in payload:
                self.error(payload["error"])

            return payload
        except Exception as e:
            self.error(f"Unable to validate scan parameters: {str(e)}")

    def _validate_common_parameters(self) -> Dict[str, str]:
        """
        Validate common options shared between file and URL private scans:

        - retention_period_days
        - storage_region
        - interaction_timeout

        Returns a sanitized parameter dictionary.
        """
        try:
            payload: Dict[str, str] = {}

            # Retention period
            days = self._clean_parameter_value(self.get_param("config.retention_period_days", None, None))
            if days is not None:
                if not isinstance(days, (int, float)):
                    self.error("Retention period must be a numeric value.")
                if isinstance(days, float) and not days.is_integer():
                    self.error("Retention period must be a whole number.")
                payload["retention_period_days"] = str(days)

            # Storage region
            region = self._clean_parameter_value(self.get_param("config.storage_region", None, None))
            if region is not None:
                if not isinstance(region, str):
                    self.error("Storage region must be text.")
                region_up = region.upper()
                payload["storage_region"] = region_up

            # Interaction timeout
            timeout = self._clean_parameter_value(self.get_param("config.interaction_timeout", None, None))
            if timeout is not None:
                if not isinstance(timeout, (int, float)):
                    self.error("Interaction timeout must be a numeric value.")
                if isinstance(timeout, float) and not timeout.is_integer():
                    self.error("Interaction timeout must be a whole number.")
                payload["interaction_timeout"] = str(timeout)

            return payload

        except Exception as e:
            self.error(f"Unable to validate common parameters: {str(e)}")

    def _validate_url_parameters(self) -> Dict[str, str]:
        """
        Validate private-scan URL-only settings:

        - Sandbox selection list

        Returns a completed URL payload.
        """
        try:
            payload = self._validate_common_parameters()

            # Sandboxes
            sandboxes = self._clean_parameter_value(self.get_param("config.sandboxes", None, None))
            if sandboxes is not None:
                if not isinstance(sandboxes, str):
                    self.error("Sandboxes must be text.")
                payload["sandboxes"] = sandboxes

            return payload

        except Exception as e:
            self.error(f"Unable to validate URL parameters: {str(e)}")

    def _validate_file_parameters(self) -> Dict[str, str]:
        """
        Validate private-scan file-specific settings:

        - command_line
        - disable_sandbox
        - enable_internet
        - password
        - interaction_sandbox
        - locale

        Returns a sanitized file payload.
        """
        try:
            payload = self._validate_common_parameters()

            # Command line
            cmd = self._clean_parameter_value(self.get_param("config.command_line", None, None))
            if cmd is not None:
                if not isinstance(cmd, str):
                    self.error("Command line must be text.")
                payload["command_line"] = cmd

            # disable_sandbox
            disable = self._clean_parameter_value(self.get_param("config.disable_sandbox", None, None))
            if disable is not None:
                if not isinstance(disable, bool):
                    self.error("Disable sandbox must be yes or no.")
                payload["disable_sandbox"] = str(disable).lower()

            # enable_internet
            enable = self._clean_parameter_value(self.get_param("config.enable_internet", None, None))
            if enable is not None:
                if not isinstance(enable, bool):
                    self.error("Enable internet must be yes or no.")
                payload["enable_internet"] = str(enable).lower()

            # password
            pwd = self._clean_parameter_value(self.get_param("config.password", None, None))
            if pwd is not None:
                if not isinstance(pwd, str):
                    self.error("Password must be text.")
                payload["password"] = pwd

            # interaction sandbox
            isb = self._clean_parameter_value(self.get_param("config.interaction_sandbox", None, None))
            if isb is not None:
                if not isinstance(isb, str):
                    self.error("Interaction sandbox must be text.")
                payload["interaction_sandbox"] = isb

            # locale
            locale = self._clean_parameter_value(self.get_param("config.locale", None, None))
            if locale is not None:
                if not isinstance(locale, str):
                    self.error("Locale must be text.")
                locale_up = locale.upper()
                payload["locale"] = locale_up

            return payload

        except Exception as e:
            self.error(f"Unable to validate file parameters: {str(e)}")

    def _handle_api_error(self, api_response: dict):
        """
        Validate GTI API response format and check for "success" field.

        Any error → stops analyzer with self.error().
        """
        try:
            if not api_response:
                self.error("Unable to connect to the threat intelligence service.")

            if not isinstance(api_response, dict):
                self.error("Unexpected response received from the service.")

            if not api_response.get("success", False) or api_response.get("error"):
                self.error(api_response.get("error", "Unable to retrieve threat intelligence data."))
        except Exception:
            self.error("Unable to process service response.")

    def _extract_analysis_id(self, api_response: dict) -> str:
        """
        Read the analysis ID from a GTI submission response.

        Returns:
            str: analysis ID or empty string.
        """
        try:
            value = api_response.get("response", {}).get("data", {}).get("id", "")
            return value if isinstance(value, str) else ""
        except Exception:
            return ""

    def _wait_for_analysis_completion(self, analysis_id: str) -> Dict[str, Any]:
        """
        Poll GTI private analysis until:
        - status == "completed" → return final analysis
        - status == error states → fail
        """
        try:
            if not self.gti_client:
                self.error("The service client is not initialized.")

            if not analysis_id:
                self.error("A valid analysis ID is required to begin polling.")

            while True:
                result = self.gti_client.get_private_analysis_report(analysis_id=analysis_id)
                self._handle_api_error(result)

                status = (
                    result.get("response", {})
                    .get("data", {})
                    .get("attributes", {})
                    .get("status", "")
                )

                if not status:
                    self.error("Unable to determine scan progress.")

                if status == "completed":
                    return result

                if status in ["unsupported file type", "error"]:
                    self.error(f"Scan failed: {status.replace('_', ' ').title()}")

                time.sleep(POLLING_INTERVAL)

        except Exception as e:
            self.error(f"Unable to process scan completion: {str(e)}")

    def _submit_file_for_analysis(self, file_path: str) -> Dict[str, Any]:
        """
        Validate file → read bytes → submit to GTI private scan endpoint.

        Automatically selects small/large upload method.
        """
        try:
            if not self.gti_client:
                self.error("The service client is not initialized.")

            if not os.path.exists(file_path):
                self.error(f"File not found: {file_path}")

            if not os.path.isfile(file_path):
                self.error(f"Selected path does not refer to a valid file: {file_path}")

            size = os.path.getsize(file_path)
            if size == 0:
                self.error("The file is empty. Please provide a valid file.")

            name = os.path.basename(file_path)
            if not name:
                self.error("The file name is invalid.")

            with open(file_path, "rb") as f:
                data = f.read()

            if size <= MAX_FILE_SIZE:
                return self.gti_client.submit_private_file(filename=name, file_data=data, payload=self.payload)

            return self.gti_client.submit_large_private_file(filename=name, file_data=data, payload=self.payload)

        except IOError as e:
            self.error(f"Unable to read the file: {str(e)}")

        except Exception as e:
            self.error(f"Unable to submit the file for analysis: {str(e)}")

    def get_scan_private_file_report(self, file_path: str) -> Dict[str, Any]:
        """
        Main public entrypoint for private FILE scans.

        Steps:
        1. Submit file for private scan  
        2. Poll until analysis completes  
        3. Extract SHA256  
        4. Fetch final detailed private report  
        """
        try:
            if not self.gti_client:
                self.error("The service client is not initialized.")

            submission = self._submit_file_for_analysis(file_path)
            self._handle_api_error(submission)
            
            analysis_id = self._extract_analysis_id(submission)
            if not analysis_id:
                self.error("Provide valid file and try again. Unable to begin scan because no analysis ID was received.")

            final = self._wait_for_analysis_completion(analysis_id)

            sha256 = (
                final.get("response", {})
                .get("meta", {})
                .get("file_info", {})
                .get("sha256", "")
            )

            if not isinstance(sha256, str) or len(sha256) != 64:
                self.error("Unable to identify the file after scanning.")

            report = self.gti_client.get_private_file_report(file_hash=sha256)
            self._handle_api_error(report)

            return report

        except Exception as e:
            self.error(f"Unable to complete file scan: {str(e)}")

    def get_scan_private_url_report(self, url: str) -> Dict[str, Any]:
        """
        Main public entrypoint for private URL scans.

        Steps:
        1. Submit URL for private scan  
        2. Poll until analysis completes  
        3. Fetch final private URL report  
        """
        try:
            if not self.gti_client:
                self.error("The service client is not initialized.")

            if not url or not isinstance(url, str):
                self.error("Please provide a valid URL.")

            submission = self.gti_client.submit_private_url(payload={"url": url, **self.payload})
            self._handle_api_error(submission)

            analysis_id = self._extract_analysis_id(submission)
            if not analysis_id:
                self.error("Provide valid URL and try again. Unable to begin scan because no analysis ID was received.")

            final = self._wait_for_analysis_completion(analysis_id)

            report = self.gti_client.get_private_url_report(url=url)
            self._handle_api_error(report)

            return report

        except Exception as e:
            self.error(f"Unable to complete URL scan: {str(e)}")
