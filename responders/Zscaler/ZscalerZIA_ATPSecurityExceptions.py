#!/usr/bin/env python3
# encoding: utf-8
"""
Zscaler ZIA ATP Security Exceptions Responder

Adds or removes URLs (domain, fqdn, url) to/from Zscaler Internet Access
ATP Security Exceptions (Policy > Security > Advanced Threat Protection > Security Exceptions).
"""

import re
import time
from datetime import datetime
from urllib.parse import urlparse

from cortexutils.responder import Responder
from zscaler import ZscalerClient
from zscaler.oneapi_client import LegacyZIAClient


class ZscalerZIA_ATPSecurityExceptions(Responder):
    """
    Cortex Responder to manage ATP Security Exceptions in Zscaler Internet Access (ZIA)
    Supports: domain, fqdn, url
    """

    # Common TLDs to block from bare use
    BARE_TLDS = {
        'com', 'net', 'org', 'edu', 'gov', 'mil', 'int',
        'io', 'co', 'uk', 'de', 'fr', 'jp', 'cn', 'au'
    }

    def __init__(self):
        Responder.__init__(self)

        self.auth_type = self.get_param('config.auth_type', 'oneapi').lower()

        if self.auth_type not in ['oneapi', 'legacy']:
            self.error(f"Invalid auth_type: {self.auth_type}. Must be 'oneapi' or 'legacy'")

        if self.auth_type == 'oneapi':
            self.zia_vanity_domain = self.get_param('config.zia_vanity_domain', None, 'ZIA Vanity Domain is required for OneAPI authentication')
            self.zia_client_id = self.get_param('config.zia_client_id', None, 'ZIA Client ID is required for OneAPI authentication')
            self.zia_client_secret = self.get_param('config.zia_client_secret', None, 'ZIA Client Secret is required for OneAPI authentication')
            self.zia_cloud = self.get_param('config.zia_cloud', None)
            self.zia_username = None
            self.zia_password = None
            self.zia_api_key = None
        else:
            self.zia_username = self.get_param('config.zia_username', None, 'ZIA Username is required for legacy authentication')
            self.zia_password = self.get_param('config.zia_password', None, 'ZIA Password is required for legacy authentication')
            self.zia_api_key = self.get_param('config.zia_api_key', None, 'ZIA API Key is required for legacy authentication')
            self.zia_cloud = self.get_param('config.zia_cloud', None, 'ZIA Cloud is required for legacy authentication')
            self.zia_vanity_domain = None
            self.zia_client_id = None
            self.zia_client_secret = None

        self.action_type = self.get_param('config.action_type', 'add').lower()
        self.dry_run = self.get_param('config.dry_run', False)
        self.activate_changes = self.get_param('config.activate_changes', True)
        self.allow_risky_iocs = self.get_param('config.allow_risky_iocs', False)
        self.allow_wildcards = self.get_param('config.allow_wildcards', False)
        proxy_url = self.get_param('config.proxy_https', None) or self.get_param('config.proxy_http', None)
        self.proxy_config = self._parse_proxy(proxy_url)

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

    @staticmethod
    def _parse_proxy(proxy_url):
        if not proxy_url:
            return None
        parsed = urlparse(proxy_url)
        cfg = {"host": parsed.hostname}
        if parsed.port:
            cfg["port"] = parsed.port
        return cfg

    def _init_zia_client(self):
        if self.zia_client is None:
            try:
                if self.auth_type == 'oneapi':
                    config = {
                        "clientId": self.zia_client_id,
                        "clientSecret": self.zia_client_secret,
                        "vanityDomain": self.zia_vanity_domain,
                        "logging": {"enabled": False, "verbose": False}
                    }
                    if self.zia_cloud:
                        config["cloud"] = self.zia_cloud
                    if self.proxy_config:
                        config["proxy"] = self.proxy_config
                    try:
                        zscaler_client = ZscalerClient(config)
                        self.zia_client = zscaler_client.zia
                    except Exception as oauth_error:
                        error_msg = f"OAuth authentication failed: {str(oauth_error)}"
                        self.audit_data['errors'].append(error_msg)
                        self.error(error_msg)
                else:
                    config = {
                        "username": self.zia_username,
                        "password": self.zia_password,
                        "api_key": self.zia_api_key,
                        "cloud": self.zia_cloud,
                        "logging": {"enabled": False, "verbose": False}
                    }
                    if self.proxy_config:
                        config["proxy"] = self.proxy_config
                    try:
                        legacy_client = LegacyZIAClient(config)
                        self.zia_client = legacy_client.zia
                    except Exception as legacy_error:
                        error_msg = f"Legacy API authentication failed: {str(legacy_error)}"
                        self.audit_data['errors'].append(error_msg)
                        self.error(error_msg)
            except Exception as e:
                error_msg = f'Unexpected error during ZIA client initialization: {str(e)}'
                self.audit_data['errors'].append(error_msg)
                self.error(error_msg)

    def _validate_domain(self, domain):
        if not domain:
            return False, None, "Empty domain"

        domain = domain.lower().strip()
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]

        if domain.startswith('*.'):
            if not self.allow_wildcards:
                return False, None, f"Wildcard domains not allowed: {domain}"
            domain = '.' + domain[2:]  # Zscaler wildcard format: .example.com
            domain_to_check = domain[1:]
        else:
            domain_to_check = domain

        if not self.allow_risky_iocs and domain_to_check in self.BARE_TLDS:
            return False, None, f"Bare TLD blocked (too generic): {domain}"

        fqdn_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
        if not re.match(fqdn_pattern, domain_to_check):
            return False, None, f"Invalid domain format: {domain}"

        if not self.allow_risky_iocs:
            parts = domain_to_check.split('.')
            if len(parts) <= 1:
                return False, None, f"Domain too generic: {domain}"

        return True, domain, None

    def _validate_url(self, url):
        if not url:
            return False, None, None, "Empty URL"

        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url

            parsed = urlparse(url)
            hostname = parsed.hostname

            if not hostname:
                return False, None, None, "Could not extract hostname from URL"

            is_valid, normalized_host, error = self._validate_domain(hostname)
            if not is_valid:
                return False, None, None, error

            full_url_no_protocol = normalized_host
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
        self._init_zia_client()

        try:
            security_settings, _, err = self.zia_client.security_policy_settings.get_whitelist()

            if err:
                return False, False, f"Failed to get allowlist: {err}"

            if hasattr(security_settings, 'whitelist_urls'):
                allowlist_urls = security_settings.whitelist_urls or []
            elif hasattr(security_settings, 'whitelistUrls'):
                allowlist_urls = security_settings.whitelistUrls or []
            elif isinstance(security_settings, dict):
                allowlist_urls = security_settings.get('whitelistUrls', security_settings.get('whitelist_urls', []))
            else:
                allowlist_urls = []

            current_urls = set(url.lower() for url in allowlist_urls if url)

            urls_to_process = set()
            if isinstance(urls, str):
                urls = [urls]
            for url in urls:
                urls_to_process.add(url.lower())

            urls_exist_in_allowlist = urls_to_process.issubset(current_urls)

            if self.action_type == 'add':
                if urls_exist_in_allowlist:
                    self.audit_data['already_present'] = True
                    return True, True, None
            else:
                if not urls_exist_in_allowlist:
                    self.audit_data['already_present'] = True
                    return True, True, None

            if not self.dry_run:
                urls_list = list(urls_to_process)
                if self.action_type == 'add':
                    _, _, err = self.zia_client.security_policy_settings.add_urls_to_whitelist(urls_list)
                else:
                    _, _, err = self.zia_client.security_policy_settings.delete_urls_from_whitelist(urls_list)

                if err:
                    return False, False, f"Failed to update allowlist: {err}"

                activation_success, activation_msg = self._activate_changes()
                self.audit_data['activation_status'] = activation_msg
                if not activation_success:
                    return False, False, activation_msg

                return True, False, None

            return True, False, None

        except Exception as e:
            return False, False, f"ZIA API error: {str(e)}"

    def run(self):
        Responder.run(self)

        data_type = self.get_param('data.dataType')
        data_value = self.get_param('data.data', None, 'No observable data available')

        self.audit_data['ioc'] = data_value
        self.audit_data['ioc_type'] = data_type

        try:
            if data_type in ['domain', 'fqdn']:
                is_valid, normalized, error = self._validate_domain(data_value)
                if not is_valid:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                self.audit_data['action_taken'] = 'manage_atp_security_exceptions'
                success, already_present, error = self._manage_allowlist(normalized)

                if not success:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                action_verb = 'added to' if self.action_type == 'add' else 'removed from'
                status = ('already in' if self.action_type == 'add' else 'not found in') if already_present else action_verb
                message = f"Domain '{normalized}' {status} ZIA ATP Security Exceptions"
                if self.dry_run and not already_present:
                    message = f"[DRY RUN] Would have {action_verb} ZIA ATP Security Exceptions"

                self.report({'message': message, 'audit': self.audit_data})

            elif data_type == 'url':
                is_valid, _normalized_url, full_url, error = self._validate_url(data_value)
                if not is_valid:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                self.audit_data['action_taken'] = 'manage_atp_security_exceptions'
                success, already_present, error = self._manage_allowlist(full_url)

                if not success:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                action_verb = 'added to' if self.action_type == 'add' else 'removed from'
                status = ('already in' if self.action_type == 'add' else 'not found in') if already_present else action_verb
                message = f"URL '{data_value}' (added as: '{full_url}') {status} ZIA ATP Security Exceptions"
                if self.dry_run and not already_present:
                    message = f"[DRY RUN] Would have {action_verb} ZIA ATP Security Exceptions"

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
        if self.audit_data.get('already_present'):
            tag = 'ZIA:atp-security-exceptions:already-present' if self.action_type == 'add' else 'ZIA:atp-security-exceptions:not-found'
        elif self.dry_run:
            tag = 'ZIA:atp-security-exceptions:dry-run'
        else:
            tag = 'ZIA:atp-security-exceptions:added' if self.action_type == 'add' else 'ZIA:atp-security-exceptions:removed'

        return [
            self.build_operation('AddTagToCase', tag='ZIA:action-taken'),
            self.build_operation('AddTagToArtifact', tag=tag)
        ]


if __name__ == '__main__':
    ZscalerZIA_ATPSecurityExceptions().run()
