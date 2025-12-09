import base64
import requests
from typing import Dict, Any, Optional
from urllib3 import disable_warnings
from urllib3.exceptions import InsecureRequestWarning
from constants import (
    X_TOOL,
    BASE_URL,
    IP_RELATIONSHIPS_PARAMS,
    DOMAIN_RELATIONSHIPS_PARAMS,
    URL_RELATIONSHIPS_PARAMS,
    FILE_RELATIONSHIPS_PARAMS,
    IP_ADDRESSES,
    FILES,
    DOMAINS,
    URLS,
    MITRE,
    TIMEOUT,
    USER_AGENT,
    STATUS_CODE_MESSAGES,
)

disable_warnings(InsecureRequestWarning)


class GoogleThreatIntelligenceClient:
    """
    A client for interacting with the Google Threat Intelligence (GTI) API.

    This class handles API key management, request signing, session handling,
    and response parsing for various GTI endpoints.
    """

    def __init__(self, api_key: str, timeout: int = TIMEOUT) -> None:
        """
        Initializes the GoogleThreatIntelligenceClient.

        Args:
            api_key: The Google Threat Intelligence API key.
            timeout: The default timeout in seconds for API requests.
        """
        try:
            if not api_key or not isinstance(api_key, str) or not api_key.strip():
                self.api_key = ""
            else:
                self.api_key = api_key.strip()
            self.timeout = timeout
            self.default_headers = {
                "x-apikey": self.api_key,
                "User-Agent": USER_AGENT,
                "x-tool": X_TOOL,
            }
            self.session = requests.Session()
            self.session.verify = False
        except Exception:
            self.api_key = ""
            self.timeout = TIMEOUT
            self.default_headers = {}
            self.session = requests.Session()

    def __del__(self) -> None:
        """Closes the underlying requests session upon object deletion."""
        try:
            if hasattr(self, "session"):
                self.session.close()
        except Exception:
            pass

    def _build_url(self, endpoint: Optional[str] = None, url: Optional[str] = None) -> str:
        """
        Constructs a full API URL from a base URL and an endpoint or a full URL.

        Args:
            endpoint: The API endpoint (e.g., "files/hash").
            url: A full, pre-constructed URL. If provided, this is used instead.

        Returns:
            The fully constructed URL as a string, or an empty string if invalid.
        """
        try:
            if url:
                if not isinstance(url, str) or not url.strip():
                    return ""
                return url.strip()
            if not endpoint or not isinstance(endpoint, str):
                return ""
            clean_endpoint = endpoint.strip().lstrip("/")
            return f"{BASE_URL.rstrip('/')}/{clean_endpoint}"
        except Exception:
            return ""

    def _parse_error_response(self, response: requests.Response, ioc_value: Optional[str] = None) -> str:
        """
        Generates a human-readable error message from an HTTP error response.

        Args:
            response: The requests.Response object.
            ioc_value: The specific IOC value that was being queried, for context.

        Returns:
            A formatted error message string.
        """
        try:
            if response.status_code in STATUS_CODE_MESSAGES:
                template = STATUS_CODE_MESSAGES[response.status_code]
                base = template.format(ioc_value=ioc_value or "the requested resource")
            else:
                base = f"The request failed with status code {response.status_code}"
            detail = self._extract_api_error_detail(response)
            return f"{base} Response from GTI - {detail}" if detail else base
        except Exception:
            return "Unable to process the response from the service."

    def _extract_api_error_detail(self, response: requests.Response) -> Optional[str]:
        """
        Attempts to extract a specific error message from the API's JSON response body.

        Args:
            response: The requests.Response object.

        Returns:
            The error message string if found, otherwise None.
        """
        try:
            error_data = response.json()
            if isinstance(error_data.get("error"), dict):
                msg = error_data["error"].get("message", "")
            elif isinstance(error_data.get("error"), str):
                msg = error_data["error"]
            elif isinstance(error_data.get("message"), str):
                msg = error_data["message"]
            else:
                msg = ""
            msg = msg.strip()
            return msg if msg else None
        except Exception:
            try:
                text = response.text.strip()
                if text and len(text) < 500:
                    return text
            except Exception:
                pass
            return None

    def _handle_response(self, response: requests.Response, ioc_value: Optional[str] = None) -> Dict[str, Any]:
        """
        Handles the HTTP response from an API request, parsing success or error.

        Args:
            response: The requests.Response object.
            ioc_value: The IOC value associated with the request, for error context.

        Returns:
            A dictionary containing:
                "success" (bool): True if the request was successful (200/201).
                "response" (dict | None): The JSON response data if successful.
                "error" (str | None): The error message if unsuccessful.
                "status_code" (int): The HTTP status code.
        """
        result = {"success": False, "response": None, "error": None, "status_code": response.status_code}
        try:
            if response.status_code in (200, 201):
                try:
                    json_data = response.json()
                    if isinstance(json_data, dict):
                        result["success"] = True
                        result["response"] = json_data
                    else:
                        result["error"] = "The service returned data in an unexpected format."
                except ValueError:
                    result["error"] = "Unable to read the response from the service."
            else:
                result["error"] = self._parse_error_response(response, ioc_value)
        except Exception as e:
            result["error"] = f"Unable to process the service response: {str(e)}"
        return result

    def make_api_request(
        self,
        endpoint: Optional[str] = None,
        url: Optional[str] = None,
        params: Optional[Dict] = None,
        method: str = "GET",
        data: Optional[Dict] = None,
        files: Optional[Dict] = None,
        custom_headers: Optional[Dict] = None,
        ioc_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        The core method for making any API request to Google Threat Intelligence.

        It handles URL building, authentication, request execution, and error handling.

        Args:
            endpoint: The API endpoint (e.g., "files/hash").
            url: A full URL. Overrides 'endpoint' if provided.
            params: URL query parameters.
            method: HTTP method ("GET" or "POST").
            data: The request payload for POST requests.
            files: Files to upload for POST requests.
            custom_headers: Additional headers to merge with default headers.
            ioc_value: The IOC value for error logging.

        Returns:
            A dictionary from _handle_response, indicating success or failure.
        """
        try:
            if not self.api_key:
                return {"success": False, "error": "An API key is required to complete this request."}
            if method.upper() not in ("GET", "POST"):
                return {"success": False, "error": "The request method is not supported."}
            if params and not isinstance(params, dict):
                return {"success": False, "error": "The parameters must be provided in a valid format."}
            if data and not isinstance(data, dict):
                return {"success": False, "error": "The request data must be provided in a valid format."}

            request_url = self._build_url(endpoint, url)
            if not request_url:
                return {"success": False, "error": "The URL or endpoint provided is not valid."}

            headers = {**self.default_headers, **(custom_headers or {})}
            send = self.session.get if method.upper() == "GET" else self.session.post
            response = send(request_url, headers=headers, params=params, data=data, files=files, timeout=self.timeout)

            return self._handle_response(response, ioc_value)

        except requests.exceptions.Timeout:
            return {"success": False, "error": f"The request timed out after {self.timeout} seconds."}
        except requests.exceptions.ConnectionError:
            return {"success": False, "error": "Unable to connect to the service. Please try again later."}
        except requests.exceptions.RequestException as e:
            return {"success": False, "error": f"The request could not be completed: {str(e)}"}
        except Exception as e:
            return {"success": False, "error": f"An unexpected error occurred: {str(e)}"}

    def _validate_hash(self, file_hash: str) -> bool:
        """
        Validates if a string is a potentially valid file hash.

        Args:
            file_hash: The string to validate.

        Returns:
            True if the string is non-empty and alphanumeric, False otherwise.
        """
        try:
            return isinstance(file_hash, str) and bool(file_hash.strip()) and file_hash.replace("-", "").isalnum()
        except Exception:
            return False

    def _validate_string_param(self, param: str) -> bool:
        """
        Validates if a parameter is a non-empty string.

        Args:
            param: The string parameter to validate.

        Returns:
            True if the parameter is a non-empty string, False otherwise.
        """
        try:
            return isinstance(param, str) and bool(param.strip())
        except Exception:
            return False

    def get_ip_report(self, ip_address: str) -> Dict[str, Any]:
        """
        Retrieves a report for a specific IP address.

        Args:
            ip_address: The IP address to query.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not self._validate_string_param(ip_address):
                return {"success": False, "error": "The IP address provided is not valid."}
            clean = ip_address.strip()
            return self.make_api_request(
                endpoint=f"{IP_ADDRESSES}/{clean}",
                method="GET",
                params=IP_RELATIONSHIPS_PARAMS,
                ioc_value=clean,
            )
        except Exception as e:
            return {"success": False, "error": f"Unable to retrieve IP report: {str(e)}"}

    def get_domain_report(self, domain: str) -> Dict[str, Any]:
        """
        Retrieves a report for a specific domain.

        Args:
            domain: The domain name to query.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not self._validate_string_param(domain):
                return {"success": False, "error": "The domain name provided is not valid."}
            clean = domain.strip()
            return self.make_api_request(
                endpoint=f"{DOMAINS}/{clean}",
                method="GET",
                params=DOMAIN_RELATIONSHIPS_PARAMS,
                ioc_value=clean,
            )
        except Exception as e:
            return {"success": False, "error": f"Unable to retrieve domain report: {str(e)}"}

    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Retrieves a report for a specific file hash (SHA256, MD5, or SHA1).

        Args:
            file_hash: The file hash to query.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not self._validate_hash(file_hash):
                return {"success": False, "error": "The file hash provided is not valid."}
            clean = file_hash.strip()
            return self.make_api_request(
                endpoint=f"{FILES}/{clean}",
                method="GET",
                params=FILE_RELATIONSHIPS_PARAMS,
                ioc_value=clean,
            )
        except Exception as e:
            return {"success": False, "error": f"Unable to retrieve file report: {str(e)}"}

    def get_url_report(self, url: str) -> Dict[str, Any]:
        """
        Retrieves a report for a specific URL.

        Args:
            url: The URL to query. The URL will be Base64-encoded for the API.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not self._validate_string_param(url):
                return {"success": False, "error": "The URL provided is not valid."}
            clean = url.strip()
            try:
                url_id = base64.urlsafe_b64encode(clean.encode()).decode().strip("=")
                return self.make_api_request(
                    endpoint=f"{URLS}/{url_id}",
                    method="GET",
                    params=URL_RELATIONSHIPS_PARAMS,
                    ioc_value=clean,
                )
            except Exception:
                return {"success": False, "error": "Unable to process the URL provided."}
        except Exception as e:
            return {"success": False, "error": f"Unable to retrieve URL report: {str(e)}"}

    def get_private_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Retrieves a private report for a specific file hash.

        Args:
            file_hash: The file hash to query.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not self._validate_hash(file_hash):
                return {"success": False, "error": "The file hash provided is not valid."}
            clean = file_hash.strip()
            return self.make_api_request(
                endpoint=f"private/{FILES}/{clean}",
                method="GET",
                ioc_value=clean,
            )
        except Exception as e:
            return {"success": False, "error": f"Unable to retrieve private file report: {str(e)}"}

    def get_private_url_report(self, url: str) -> Dict[str, Any]:
        """
        Retrieves a private report for a specific URL.

        Args:
            url: The URL to query. The URL will be Base64-encoded for the API.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not self._validate_string_param(url):
                return {"success": False, "error": "The URL provided is not valid."}
            clean = url.strip()
            try:
                url_id = base64.urlsafe_b64encode(clean.encode()).decode().strip("=")
                return self.make_api_request(
                    endpoint=f"private/{URLS}/{url_id}",
                    method="GET",
                    ioc_value=clean,
                )
            except Exception:
                return {"success": False, "error": "Unable to process the URL provided."}
        except Exception as e:
            return {"success": False, "error": f"Unable to retrieve private URL report: {str(e)}"}

    def _submit_file_common(self, file_data: bytes, filename: str, endpoint: str, password: Optional[str] = None, ioc_value: Optional[str] = None) -> Dict[str, Any]:
        """
        A common internal method for submitting a file (public or private).

        Args:
            file_data: The raw bytes of the file.
            filename: The name of the file.
            endpoint: The API endpoint to submit to (e.g., "files").
            password: Optional password for compressed files.
            ioc_value: The value to use for error logging.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not isinstance(file_data, bytes) or not file_data:
                return {"success": False, "error": "The file data could not be processed."}
            if not self._validate_string_param(filename):
                return {"success": False, "error": "The file name provided is not valid."}
            payload = {"password": password} if password else {}
            files = {"file": (filename.strip(), file_data, "application/octet-stream")}
            return self.make_api_request(
                endpoint=endpoint,
                method="POST",
                files=files,
                data=payload,
                ioc_value=ioc_value or filename,
            )
        except Exception as e:
            return {"success": False, "error": f"Unable to submit the file: {str(e)}"}

    def submit_file(self, file_data: bytes, filename: str, password: Optional[str] = None) -> Dict[str, Any]:
        """
        Submits a file for public analysis.

        Args:
            file_data: The raw bytes of the file.
            filename: The name of the file.
            password: Optional password for compressed files.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        return self._submit_file_common(file_data, filename, "files", password, ioc_value=filename)

    def submit_private_file(self, file_data: bytes, filename: str, payload: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Submits a file for private analysis.

        Args:
            file_data: The raw bytes of the file.
            filename: The name of the file.
            payload: Optional additional data for the request (e.g., password).

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not isinstance(file_data, bytes) or not file_data:
                return {"success": False, "error": "The file data could not be processed."}
            if not self._validate_string_param(filename):
                return {"success": False, "error": "The file name provided is not valid."}
            files = {"file": (filename.strip(), file_data, "application/octet-stream")}
            return self.make_api_request(
                endpoint=f"private/{FILES}",
                method="POST",
                files=files,
                data=payload,
                ioc_value=filename,
            )
        except Exception as e:
            return {"success": False, "error": f"Unable to submit the file privately: {str(e)}"}

    def _submit_large_file_common(
        self,
        file_data: bytes,
        filename: str,
        upload_endpoint: str,
        password: Optional[str] = None,
        payload: Optional[Dict] = None,
        ioc_value: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        A common internal method for submitting a large file via a generated upload URL.

        Args:
            file_data: The raw bytes of the file.
            filename: The name of the file.
            upload_endpoint: The API endpoint to get the upload URL from.
            password: Optional password for compressed files.
            payload: Optional additional data payload.
            ioc_value: The value to use for error logging.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not isinstance(file_data, bytes) or not file_data:
                return {"success": False, "error": "The file data could not be processed."}
            if not self._validate_string_param(filename):
                return {"success": False, "error": "The file name provided is not valid."}
            upload_url_req = self.make_api_request(endpoint=upload_endpoint, method="GET")
            if not upload_url_req["success"]:
                return upload_url_req
            upload_url = upload_url_req.get("response", {}).get("data", "")
            if not self._validate_string_param(upload_url):
                return {"success": False, "error": "Unable to retrieve a valid upload URL from the service."}
            files = {"file": (filename.strip(), file_data, "application/octet-stream")}
            data = {"password": password} if password else payload
            return self.make_api_request(
                url=upload_url,
                method="POST",
                files=files,
                data=data,
                ioc_value=ioc_value or filename,
            )
        except Exception as e:
            return {"success": False, "error": f"Unable to submit the large file: {str(e)}"}

    def submit_large_file(self, file_data: bytes, filename: str, password: Optional[str] = None) -> Dict[str, Any]:
        """
        Submits a large file for public analysis (uses a two-step upload URL process).

        Args:
            file_data: The raw bytes of the file.
            filename: The name of the file.
            password: Optional password for compressed files.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        return self._submit_large_file_common(file_data, filename, f"{FILES}/upload_url", password, ioc_value=filename)

    def submit_large_private_file(self, file_data: bytes, filename: str, payload: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Submits a large file for private analysis (uses a two-step upload URL process).

        Args:
            file_data: The raw bytes of the file.
            filename: The name of the file.
            payload: Optional additional data for the request (e.g., password).

        Returns:
            A dictionary indicating success or failure of the request.
        """
        return self._submit_large_file_common(
            file_data,
            filename,
            f"private/{FILES}/upload_url",
            payload=payload,
            ioc_value=filename,
        )

    def _submit_url_common(self, payload: Dict, endpoint: str) -> Dict[str, Any]:
        """
        A common internal method for submitting a URL (public or private).

        Args:
            payload: The request payload, must contain a "url" key.
            endpoint: The API endpoint to submit to (e.g., "urls").

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not isinstance(payload, dict) or not self._validate_string_param(payload.get("url", "")):
                return {"success": False, "error": "The URL provided is not valid."}
            url_value = payload.get("url", "").strip()
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            return self.make_api_request(
                endpoint=endpoint,
                method="POST",
                data=payload,
                custom_headers=headers,
                ioc_value=url_value,
            )
        except Exception as e:
            return {"success": False, "error": f"Unable to submit the URL: {str(e)}"}

    def submit_url(self, payload: Dict) -> Dict[str, Any]:
        """
        Submits a URL for public analysis.

        Args:
            payload: The request payload, must contain a "url" key.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        return self._submit_url_common(payload, "urls")

    def submit_private_url(self, payload: Dict) -> Dict[str, Any]:
        """
        Submits a URL for private analysis.

        Args:
            payload: The request payload, must contain a "url" key.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        return self._submit_url_common(payload, f"private/{URLS}")

    def get_analysis_report(self, analysis_id: str) -> Dict[str, Any]:
        """
        Retrieves a public analysis report by its analysis ID.

        Args:
            analysis_id: The ID of the analysis (from a file/URL submission).

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not self._validate_string_param(analysis_id):
                return {"success": False, "error": "The analysis ID provided is not valid."}
            return self.make_api_request(
                endpoint=f"analyses/{analysis_id.strip()}",
                method="GET",
                ioc_value=analysis_id,
            )
        except Exception as e:
            return {"success": False, "error": f"Unable to retrieve the analysis report: {str(e)}"}

    def get_private_analysis_report(self, analysis_id: str) -> Dict[str, Any]:
        """
        Retrieves a private analysis report by its analysis ID.

        Args:
            analysis_id: The ID of the private analysis.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not self._validate_string_param(analysis_id):
                return {"success": False, "error": "The analysis ID provided is not valid."}
            return self.make_api_request(
                endpoint=f"private/analyses/{analysis_id.strip()}",
                method="GET",
                ioc_value=analysis_id,
            )
        except Exception as e:
            return {"success": False, "error": f"Unable to retrieve the private analysis report: {str(e)}"}

    def get_mitre_attack_data(self, file_hash: str) -> Dict[str, Any]:
        """
        Retrieves MITRE ATT&CK data associated with a file hash.

        Args:
            file_hash: The file hash to query.

        Returns:
            A dictionary indicating success or failure of the request.
        """
        try:
            if not self._validate_hash(file_hash):
                return {"success": False, "error": "The file hash provided is not valid."}
            clean = file_hash.strip()
            return self.make_api_request(
                endpoint=f"{FILES}/{clean}/{MITRE}",
                method="GET",
                ioc_value=clean,
            )
        except Exception as e:
            return {"success": False, "error": f"Unable to retrieve MITRE ATT&CK data: {str(e)}"}
        