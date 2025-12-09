import time
import os
from typing import Optional, Dict, Any, List
from cortexutils.analyzer import Analyzer
from gti_api_helper import GoogleThreatIntelligenceClient
from gti_get_ioc_report import GTIGetReportAnalyzer
from constants import MAX_FILE_SIZE, POLLING_INTERVAL


class GTIScanAnalyzer(Analyzer):
    """
    Handles public scanning of files and URLs using Google Threat Intelligence.

    This analyzer:
    - Submits files/URLs to GTI for scanning
    - Polls until the scan is finished
    - Retrieves the final standard “get” report once analysis completes

    It is used when the Cortex analyzer configuration selects `service = scan`.
    """

    def __init__(self, api_key: str) -> None:
        """
        Initialize the public scan analyzer.

        Creates the GTI client and the report generator used to get the final report.

        Args:
            api_key: Google Threat Intelligence API key.
        """
        super().__init__()
        self.gti_client = GoogleThreatIntelligenceClient(api_key)
        self.report_generator = GTIGetReportAnalyzer(api_key)
        self.init_error_message: Optional[str] = None

        self.password = self.get_param("config.password", None, None)
        if self.password is not None and not isinstance(self.password, str):
            self.error("Password must be a text value")

    def _handle_api_error(self, api_response: Optional[Dict]):
        """
        Validates API responses.

        If the response:
        - is missing
        - is in unexpected format
        - contains an error flag  
        → stops the analyzer with `self.error(...)`.
        """
        if not api_response:
            self.error("Unable to connect to the threat intelligence service. Please try again.")

        if not isinstance(api_response, dict):
            self.error("The service returned an unexpected response format.")

        if not api_response.get("success", False) or api_response.get("error"):
            self.error(api_response.get("error", "Unable to retrieve threat intelligence information."))

    def _extract_analysis_id(self, api_response: Dict) -> str:
        """
        Extracts analysis ID from GTI submission response.

        Returns:
            str: analysis ID or empty string.
        """
        try:
            data = api_response.get("response", {}).get("data", {})
            analysis_id = data.get("id", "")
            return analysis_id if isinstance(analysis_id, str) else ""
        except Exception:
            return ""

    def _wait_for_analysis_completion(self, analysis_id: str) -> Dict[str, Any]:
        """
        Polls GTI analysis status until it becomes `completed`.

        Returns:
            The final API report dictionary.
        """
        while True:
            try:
                report = self.gti_client.get_analysis_report(analysis_id=analysis_id)
                self._handle_api_error(report)

                status = (
                    report.get("response", {})
                    .get("data", {})
                    .get("attributes", {})
                    .get("status", "")
                )

                if not status:
                    self.error("Unable to determine the status of the ongoing scan.")

                if status == "completed":
                    return report

                if status in ["unsupported file type", "error"]:
                    self.error(f"Scan failed: {status.replace('_', ' ').title()}.")

                time.sleep(POLLING_INTERVAL)

            except Exception as e:
                self.error(f"Unable to check scan status: {str(e)}")

    def _validate_file(self, file_path: str):
        """
        Validates the input file path.

        Checks existence, accessibility, filename and non-emptiness.
        """
        try:
            if not os.path.exists(file_path):
                self.error("File not found. Please verify the file path and try again.")

            if not os.path.isfile(file_path):
                self.error("The selected path does not point to a valid file.")

            if os.path.getsize(file_path) == 0:
                self.error("The file is empty. Please provide a valid file.")

            if not os.path.basename(file_path):
                self.error("The file name is invalid or unreadable.")

        except Exception as e:
            self.error(f"Unable to validate the file: {str(e)}")

    def _read_and_submit_file(self, file_path: str) -> Dict[str, Any]:
        """
        Reads a file and submits it to GTI.

        Automatically chooses small-file vs large-file submission method.
        """
        try:
            with open(file_path, "rb") as f:
                file_data = f.read()

            filename = os.path.basename(file_path)
            file_size = len(file_data)
            is_small_file = file_size <= MAX_FILE_SIZE

            if is_small_file:
                return self.gti_client.submit_file(
                    filename=filename,
                    file_data=file_data,
                    password=self.password,
                )

            return self.gti_client.submit_large_file(
                filename=filename,
                file_data=file_data,
                password=self.password,
            )

        except IOError as e:
            self.error(f"Unable to read the file: {str(e)}")

        except Exception as e:
            self.error(f"Unable to submit the file for scanning: {str(e)}")

    def _submit_file_for_analysis(self, file_path: str) -> Dict[str, Any]:
        """
        Wraps file validation + file submission logic.
        """
        try:
            self._validate_file(file_path)
            return self._read_and_submit_file(file_path)
        except Exception as e:
            self.error(f"File submission could not be completed: {str(e)}")

    def _extract_file_hash(self, final_report: Dict[str, Any]) -> str:
        """
        Extracts SHA256 hash from GTI’s completed analysis report.
        """
        try:
            meta = final_report.get("response", {}).get("meta", {})
            info = meta.get("file_info", {})
            sha256 = info.get("sha256", "")
            return sha256 if isinstance(sha256, str) and len(sha256) == 64 else ""
        except Exception:
            return ""

    def _process_scan_submission(self, submission_response: Dict[str, Any]) -> Dict[str, Any]:
        """
        Handles complete scan workflow:
        - Validate submission response
        - Extract analysis ID
        - Poll until analysis completes
        """
        try:
            self._handle_api_error(submission_response)

            analysis_id = self._extract_analysis_id(submission_response)
            if not analysis_id:
                self.error("Unable to start the scan. Please verify the input and try again.")

            return self._wait_for_analysis_completion(analysis_id)

        except Exception as e:
            self.error(f"Unable to complete scan processing: {str(e)}")

    def get_scan_file_report(self, file_path: str, iocs: Dict[str, List]) -> Dict[str, Any]:
        """
        Performs:
        1. Public file scan
        2. Waits for GTI completion
        3. Fetches the final standard GTI "get" report
        """
        try:
            if self.init_error_message:
                self.error(self.init_error_message)

            submission = self._submit_file_for_analysis(file_path)
            self._handle_api_error(submission)
            
            final_report = self._process_scan_submission(submission)

            sha256 = self._extract_file_hash(final_report)
            if not sha256:
                self.error("Unable to identify the scanned file.")

            return self.report_generator.get_file_report(file_hash=sha256, iocs=iocs)

        except Exception as e:
            self.error(f"File scanning failed: {str(e)}")

    def get_scan_url_report(self, url: str, iocs: Dict[str, List]) -> Dict[str, Any]:
        """
        Performs:
        1. Public URL scan
        2. Waits for GTI completion
        3. Fetches the final standard GTI "get" report
        """
        try:
            if not url or not isinstance(url, str):
                self.error("Please provide a valid URL.")

            submission = self.gti_client.submit_url(payload={"url": url})
            self._handle_api_error(submission)
            
            final_report = self._process_scan_submission(submission)

            return self.report_generator.get_url_report(url=url, iocs=iocs)

        except Exception as e:
            self.error(f"URL scanning failed: {str(e)}")
