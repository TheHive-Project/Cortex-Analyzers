#!/usr/bin/env python3
# encoding: utf-8
"""
Zscaler ZIA Allowlist Responder

Adds or removes URLs (domain, fqdn, url) to/from Zscaler Internet Access
global URL allowlist (whitelist).
"""

import re
import time
from datetime import datetime
from urllib.parse import urlparse

from cortexutils.responder import Responder
from zscaler import ZscalerClient
from zscaler.oneapi_client import LegacyZIAClient


class ZscalerZIA_Allowlist(Responder):
    """
    Cortex Responder to manage URL allowlist in Zscaler Internet Access (ZIA)
    Supports: domain, fqdn, url
    """

    # Common TLDs to block from bare use
    BARE_TLDS = {
        'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
        'io', 'co', 'uk', 'de', 'fr', 'jp', 'cn', 'au'
    }

    def __init__(self):
        Responder.__init__(self)

        # Determine authentication type
        self.auth_type = self.get_param('config.auth_type', 'oneapi').lower()

        # Validate auth_type
        if self.auth_type not in ['oneapi', 'legacy']:
            self.error(f"Invalid auth_type: {self.auth_type}. Must be 'oneapi' or 'legacy'")

        # Authentication parameters - conditionally required based on auth_type
        if self.auth_type == 'oneapi':
            # OneAPI OAuth2 parameters
            self.zia_vanity_domain = self.get_param('config.zia_vanity_domain', None, 'ZIA Vanity Domain is required for OneAPI authentication')
            self.zia_client_id = self.get_param('config.zia_client_id', None, 'ZIA Client ID is required for OneAPI authentication')
            self.zia_client_secret = self.get_param('config.zia_client_secret', None, 'ZIA Client Secret is required for OneAPI authentication')
            # Legacy parameters not used for OneAPI
            self.zia_username = None
            self.zia_password = None
            self.zia_api_key = None
        else:  # legacy
            # Legacy API parameters
            self.zia_username = self.get_param('config.zia_username', None, 'ZIA Username is required for legacy authentication')
            self.zia_password = self.get_param('config.zia_password', None, 'ZIA Password is required for legacy authentication')
            self.zia_api_key = self.get_param('config.zia_api_key', None, 'ZIA API Key is required for legacy authentication')
            self.zia_cloud = self.get_param('config.zia_cloud', None, 'ZIA Cloud is required for legacy authentication')
            # OneAPI parameters not used for legacy
            self.zia_vanity_domain = None
            self.zia_client_id = None
            self.zia_client_secret = None

        # Optional config
        if self.auth_type == 'oneapi':
            self.zia_cloud = self.get_param('config.zia_cloud', None)  # Optional: for beta/alpha environments

        self.action_type = self.get_param('config.action_type', 'add').lower()  # 'add' or 'remove' - set by responder flavor JSON
        self.dry_run = self.get_param('config.dry_run', False)
        self.activate_changes = self.get_param('config.activate_changes', True)
        self.allow_risky_iocs = self.get_param('config.allow_risky_iocs', False)
        self.allow_wildcards = self.get_param('config.allow_wildcards', False)
        self.http_proxy_hostname = self.get_param('config.http_proxy_hostname', None)
        self.http_proxy_port = self.get_param('config.http_proxy_port', None)

        # Initialize ZIA client
        self.zia_client = None
        self.audit_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'dry_run': self.dry_run,
            'action_taken': None,
            'ioc': None,
            'ioc_type': None,
            'already_present': False,
            'errors': []
        }

    def _init_zia_client(self):
        """Initialize Zscaler ZIA client with OneAPI OAuth2 or Legacy authentication"""
        if self.zia_client is None:
            try:
                if self.auth_type == 'oneapi':
                    # Prepare OneAPI OAuth2 configuration
                    config = {
                        "clientId": self.zia_client_id,
                        "clientSecret": self.zia_client_secret,
                        "vanityDomain": self.zia_vanity_domain,
                        "logging": {"enabled": False, "verbose": False}
                    }

                    # Add cloud parameter if specified (for beta/alpha environments)
                    if self.zia_cloud:
                        config["cloud"] = self.zia_cloud

                    if self.http_proxy_hostname and self.http_proxy_port:
                        config["proxy"] = {"host": self.http_proxy_hostname, "port": self.http_proxy_port}

                    # Create ZscalerClient and access ZIA services via .zia
                    try:
                        zscaler_client = ZscalerClient(config)
                        self.zia_client = zscaler_client.zia
                    except Exception as oauth_error:
                        error_msg = f"OAuth authentication failed: {str(oauth_error)}"
                        self.audit_data['errors'].append(error_msg)
                        self.error(error_msg)

                else:  # legacy
                    # Prepare Legacy API configuration
                    config = {
                        "username": self.zia_username,
                        "password": self.zia_password,
                        "api_key": self.zia_api_key,
                        "cloud": self.zia_cloud,
                        "logging": {"enabled": False, "verbose": False}
                    }

                    if self.http_proxy_hostname and self.http_proxy_port:
                        config["proxy"] = {"host": self.http_proxy_hostname, "port": self.http_proxy_port}

                    # Create LegacyZIAClient
                    try:
                        legacy_client = LegacyZIAClient(config)
                        self.zia_client = legacy_client.zia
                    except Exception as legacy_error:
                        error_msg = f"Legacy API authentication failed: {str(legacy_error)}"
                        self.audit_data['errors'].append(error_msg)
                        self.error(error_msg)

            except Exception as e:
                # Catch any other unexpected errors
                error_msg = f'Unexpected error during ZIA client initialization: {str(e)}'
                self.audit_data['errors'].append(error_msg)
                self.error(error_msg)

    def _validate_domain(self, domain):
        """Validate and normalize domain/FQDN"""
        if not domain:
            return False, None, "Empty domain"

        # Remove protocol if present
        domain = domain.lower().strip()
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]  # Remove path

        # Check for wildcard
        if domain.startswith('*.'):
            if not self.allow_wildcards:
                return False, None, f"Wildcard domains not allowed: {domain}"
            domain = '.' + domain[2:]  # Zscaler wildcard format: .example.com
            domain_to_check = domain[1:]
        else:
            domain_to_check = domain

        # Check for bare TLD
        if not self.allow_risky_iocs and domain_to_check in self.BARE_TLDS:
            return False, None, f"Bare TLD blocked (too generic): {domain}"

        # Basic FQDN validation
        fqdn_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        if not re.match(fqdn_pattern, domain_to_check):
            return False, None, f"Invalid domain format: {domain}"

        # Check for overly generic patterns
        if not self.allow_risky_iocs:
            parts = domain_to_check.split('.')
            if len(parts) <= 1:
                return False, None, f"Domain too generic: {domain}"

        return True, domain, None

    def _validate_url(self, url):
        """Validate URL and return full URL without protocol"""
        if not url:
            return False, None, None, "Empty URL"

        try:
            # Ensure URL has a scheme for parsing
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            parsed = urlparse(url)
            hostname = parsed.hostname

            if not hostname:
                return False, None, None, "Could not extract hostname from URL"

            # Validate the hostname part
            is_valid, normalized_host, error = self._validate_domain(hostname)
            if not is_valid:
                return False, None, None, error

            # Build full URL without protocol: hostname + path + params + query
            full_url_no_protocol = hostname
            if parsed.path:
                full_url_no_protocol += parsed.path
            if parsed.params:
                full_url_no_protocol += ';' + parsed.params
            if parsed.query:
                full_url_no_protocol += '?' + parsed.query

            return True, url, full_url_no_protocol, None
        except Exception as e:
            return False, None, None, f"URL parsing error: {str(e)}"

    def _activate_changes(self):
        """Activate pending changes in Zscaler"""
        if self.dry_run or not self.activate_changes:
            return True, "Activation skipped"

        max_retries = 3
        for attempt in range(max_retries):
            try:
                _, _, err = self.zia_client.activate.activate()
                if err:
                    error_str = str(err)
                    if '409' in error_str or 'EDIT_LOCK_NOT_AVAILABLE' in error_str:
                        if attempt < max_retries - 1:
                            time.sleep(2)
                            continue
                    return False, f"Activation failed: {err}"
                return True, "Changes activated"
            except Exception as e:
                if attempt < max_retries - 1:
                    time.sleep(2)
                    continue
                return False, f"Activation error: {str(e)}"
        return False, "Activation failed after retries"

    def _manage_allowlist(self, urls):
        """
        Add or remove URLs from ZIA global allowlist using incremental updates
        Returns: (success, already_present, error_message)
        """
        self._init_zia_client()

        try:
            # Get current allowlist (security settings) - SDK returns (data, response, error)
            security_settings, _, err = self.zia_client.security_policy_settings.get_whitelist()

            if err:
                return False, False, f"Failed to get allowlist: {err}"

            # Extract current allowlisted URLs (normalize to lowercase for comparison)
            # Try different possible field names (SDK uses snake_case: whitelist_urls)
            if hasattr(security_settings, 'whitelist_urls'):
                allowlist_urls = security_settings.whitelist_urls or []
            elif hasattr(security_settings, 'whitelistUrls'):
                allowlist_urls = security_settings.whitelistUrls or []
            elif isinstance(security_settings, dict):
                allowlist_urls = security_settings.get('whitelistUrls', security_settings.get('whitelist_urls', []))
            else:
                allowlist_urls = []

            current_urls = set(url.lower() for url in allowlist_urls if url)

            # Debug: Log allowlist info (useful for troubleshooting)
            self.audit_data['allowlist_info'] = {
                'total_urls': len(current_urls),
                'response_type': type(security_settings).__name__
            }

            # Normalize URLs to add/remove
            urls_to_process = set()
            if isinstance(urls, str):
                urls = [urls]

            for url in urls:
                urls_to_process.add(url.lower())

            # Debug logging - useful for troubleshooting
            self.audit_data['debug'] = {
                'url_to_process': list(urls_to_process)[0] if urls_to_process else None,
                'found_in_allowlist': urls_to_process.issubset(current_urls),
                'similar_urls': [
                    al_url for al_url in current_urls
                    for proc_url in urls_to_process
                    if proc_url.split('/')[0] in al_url or al_url.split('/')[0] in proc_url
                ][:5]
            }

            # Check if action is needed
            urls_exist_in_allowlist = urls_to_process.issubset(current_urls)

            # For add: skip if already present
            # For remove: skip if NOT present
            if self.action_type == 'add':
                if urls_exist_in_allowlist:
                    # Already allowlisted
                    self.audit_data['already_present'] = True
                    return True, True, None
            else:  # remove
                if not urls_exist_in_allowlist:
                    # Already not in allowlist (not found)
                    self.audit_data['already_present'] = True
                    return True, True, None

            # Perform action using incremental update
            if not self.dry_run:
                urls_list = list(urls_to_process)

                # Use appropriate method based on action type
                if self.action_type == 'add':
                    _, _, err = self.zia_client.security_policy_settings.add_urls_to_whitelist(urls_list)
                else:  # remove
                    _, _, err = self.zia_client.security_policy_settings.delete_urls_from_whitelist(urls_list)

                if err:
                    return False, False, f"Failed to update allowlist: {err}"

                # Activate changes if enabled
                activation_success, activation_msg = self._activate_changes()
                self.audit_data['activation_status'] = activation_msg
                if not activation_success:
                    return False, False, activation_msg

                return True, False, None

            # Dry run mode
            return True, False, None

        except Exception as e:
            return False, False, f"ZIA API error: {str(e)}"

    def run(self):
        """Main execution method"""
        Responder.run(self)

        # Get observable data
        data_type = self.get_param('data.dataType')
        data_value = self.get_param('data.data', None, 'No observable data available')

        self.audit_data['ioc'] = data_value
        self.audit_data['ioc_type'] = data_type

        try:
            # Process based on data type
            if data_type in ['domain', 'fqdn']:
                is_valid, normalized, error = self._validate_domain(data_value)
                if not is_valid:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                self.audit_data['action_taken'] = 'manage_allowlist'
                success, already_present, error = self._manage_allowlist(normalized)

                if not success:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                # Build message
                action_verb = 'added to' if self.action_type == 'add' else 'removed from'
                if already_present:
                    if self.action_type == 'add':
                        status = 'already in'
                    else:
                        status = 'not found in'
                else:
                    status = action_verb

                message = f"Domain '{normalized}' {status} ZIA URL allowlist"

                if self.dry_run and not already_present:
                    message = f"[DRY RUN] Would have {action_verb} ZIA URL allowlist"

                self.report({'message': message, 'audit': self.audit_data})

            elif data_type == 'url':
                is_valid, _normalized_url, full_url, error = self._validate_url(data_value)
                if not is_valid:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                self.audit_data['action_taken'] = 'manage_allowlist'
                # For URL allowlisting, we add the full URL (without protocol)
                success, already_present, error = self._manage_allowlist(full_url)

                if not success:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                # Build message
                action_verb = 'added to' if self.action_type == 'add' else 'removed from'
                if already_present:
                    if self.action_type == 'add':
                        status = 'already in'
                    else:
                        status = 'not found in'
                else:
                    status = action_verb

                message = f"URL '{data_value}' (added as: '{full_url}') {status} ZIA URL allowlist"

                if self.dry_run and not already_present:
                    message = f"[DRY RUN] Would have {action_verb} ZIA URL allowlist"

                self.report({'message': message, 'audit': self.audit_data})

            else:
                error_msg = f'Unsupported dataType: {data_type}. Expected: domain, fqdn, or url'
                self.audit_data['errors'].append(error_msg)
                self.error(error_msg)

        except Exception as e:
            error_msg = f'Unexpected error: {str(e)}'
            self.audit_data['errors'].append(error_msg)
            self.error(error_msg)

    def operations(self, raw):
        """Define operations to perform on TheHive after responder execution"""
        # Get timestamp for tag (format: YYYY-MM-DD_HH:MM:SS)
        timestamp = datetime.utcnow().strftime('%Y-%m-%d_%H:%M:%S')

        if self.audit_data.get('already_present'):
            if self.action_type == 'add':
                tag = f'ZIA:allowlist:already-present:{timestamp}'
            else:
                tag = f'ZIA:allowlist:not-found:{timestamp}'
        elif self.dry_run:
            tag = f'ZIA:allowlist:dry-run:{timestamp}'
        else:
            if self.action_type == 'add':
                tag = f'ZIA:allowlist:added:{timestamp}'
            else:
                tag = f'ZIA:allowlist:removed:{timestamp}'

        return [
            self.build_operation('AddTagToCase', tag='ZIA:action-taken'),
            self.build_operation('AddTagToArtifact', tag=tag)
        ]


if __name__ == '__main__':
    ZscalerZIA_Allowlist().run()
