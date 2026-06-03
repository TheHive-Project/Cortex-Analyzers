#!/usr/bin/env python3
# encoding: utf-8
"""
Zscaler ZIA URL Category Management Responder

Adds or removes observables (domain, fqdn, url, ip, cidr) to/from a custom URL category
in Zscaler Internet Access.
"""

import ipaddress
import re
import time
from datetime import datetime
from urllib.parse import urlparse

import tldextract
from cortexutils.responder import Responder
from zscaler import ZscalerClient
from zscaler.oneapi_client import LegacyZIAClient


class ZscalerZIA_URLCategory(Responder):
    """
    Cortex Responder to manage URL categories in Zscaler Internet Access (ZIA)
    Supports: domain, fqdn, url, ip, cidr
    """

    # RFC1918 private IP ranges
    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
    ]

    # Localhost ranges
    LOCALHOST_RANGES = [
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('::1/128'),
    ]

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

        self.zia_url_category_id = self.get_param('config.zia_url_category_id', None)
        self.zia_url_category_name = self.get_param('config.zia_url_category_name', None)

        if not self.zia_url_category_id and not self.zia_url_category_name:
            self.error('Either zia_url_category_id or zia_url_category_name must be provided')

        self.action_type = self.get_param('config.action_type', 'add').lower()
        self.dry_run = self.get_param('config.dry_run', False)
        self.activate_changes = self.get_param('config.activate_changes', True)
        self.allow_private_ips = self.get_param('config.allow_private_ips', False)
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
            'zia_category_id': self.zia_url_category_id,
            'zia_category_name': None,
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

    def _resolve_category_id(self):
        if self.zia_url_category_id:
            return True, self.zia_url_category_id, None

        if not self.zia_url_category_name:
            return False, None, "No category ID or name provided"

        self._init_zia_client()

        try:
            categories, _, err = self.zia_client.url_categories.list_categories()

            if err:
                return False, None, f"Failed to list categories: {err}"

            if not categories:
                return False, None, "No categories found"

            search_name = self.zia_url_category_name.lower()
            matches = []

            for cat in categories:
                cat_id = cat.get('id', '')
                cat_name = (
                    cat.get('configuredName') or
                    cat.get('configured_name') or
                    cat.get('name') or
                    cat.get('val')
                )
                if cat_name and cat_name.lower() == search_name:
                    matches.append({'id': cat_id, 'name': cat_name, 'type': cat.get('type', 'unknown')})

            if not matches:
                custom_cats = []
                for c in categories:
                    if c.get('id', '').startswith('CUSTOM_'):
                        cat_name = (
                            c.get('configuredName') or
                            c.get('configured_name') or
                            c.get('name') or
                            c.get('val') or
                            '<no name field found>'
                        )
                        custom_cats.append(f"{c.get('id')}: {cat_name}")

                if custom_cats:
                    available = ', '.join(custom_cats[:5])
                    return False, None, (
                        f"Category '{self.zia_url_category_name}' not found. "
                        f"Available: {available}"
                    )
                return False, None, f"Category '{self.zia_url_category_name}' not found"

            if len(matches) > 1:
                match_list = ', '.join([f"{m['id']}" for m in matches])
                return False, None, (
                    f"Multiple categories match '{self.zia_url_category_name}': {match_list}. "
                    f"Use category ID instead."
                )

            category_id = matches[0]['id']
            self.audit_data['category_name_lookup'] = {
                'searched_name': self.zia_url_category_name,
                'resolved_id': category_id
            }
            return True, category_id, None

        except Exception as e:
            return False, None, f"Category name resolution failed: {str(e)}"

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
        elif self.allow_wildcards:
            # Use Mozilla Public Suffix List to find the registrable domain.
            # sub.evil.co.uk -> .evil.co.uk, xyz.app.evil.com -> .evil.com
            extracted = tldextract.extract(domain)
            parent = extracted.registered_domain or domain
            domain = '.' + parent
            domain_to_check = parent
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

    def _validate_ip(self, ip_str):
        if not ip_str:
            return False, None, "Empty IP address"

        try:
            ip_obj = ipaddress.ip_address(ip_str)

            for localhost_range in self.LOCALHOST_RANGES:
                if ip_obj in localhost_range:
                    return False, None, f"Localhost IP blocked: {ip_str}"

            if not self.allow_private_ips:
                if ip_obj.is_private:
                    for private_range in self.PRIVATE_RANGES:
                        if ip_obj in private_range:
                            return False, None, f"Private IP blocked (RFC1918): {ip_str}"

            return True, ip_obj, None
        except ValueError as e:
            return False, None, f"Invalid IP address: {str(e)}"

    def _validate_cidr(self, cidr_str):
        if not cidr_str:
            return False, None, "Empty CIDR"

        try:
            network_obj = ipaddress.ip_network(cidr_str, strict=False)

            if not self.allow_risky_iocs:
                if network_obj.num_addresses > 256:
                    return False, None, f"CIDR too broad (>{network_obj.num_addresses} IPs): {cidr_str}"

            for localhost_range in self.LOCALHOST_RANGES:
                if network_obj.overlaps(localhost_range):
                    return False, None, f"CIDR overlaps with localhost: {cidr_str}"

            if not self.allow_private_ips:
                for private_range in self.PRIVATE_RANGES:
                    if network_obj.overlaps(private_range):
                        return False, None, f"CIDR overlaps with private range (RFC1918): {cidr_str}"

            return True, network_obj, None
        except ValueError as e:
            return False, None, f"Invalid CIDR notation: {str(e)}"

    def _build_result_message(self, ioc_value, location_type, location_name,
                               already_present, ioc_label="IOC"):
        action_verb = 'added to' if self.action_type == 'add' else 'removed from'

        if already_present:
            if self.action_type == 'add':
                status = 'already in'
            else:
                status = 'not found in'
        else:
            status = action_verb

        loc_label = 'ZIA category'
        message = f"{ioc_label} '{ioc_value}' {status} {loc_label} '{location_name}'"

        if self.dry_run:
            if already_present:
                message = f"[DRY RUN] {message}"
            else:
                message = f"[DRY RUN] Would have {action_verb} {ioc_label.lower()} in {loc_label}"

        return message

    def _add_to_url_category(self, urls):
        self._init_zia_client()

        try:
            category, _, err = self.zia_client.url_categories.get_category(self.zia_url_category_id)

            if err or not category:
                error_msg = f"URL Category ID {self.zia_url_category_id} not found"
                if err:
                    error_str = str(err)
                    error_msg = f"{error_msg}: {error_str}"
                    if '401' in error_str or 'Unauthorized' in error_str:
                        error_msg += " - Check OAuth credentials and permissions"
                    elif '404' in error_str or 'not found' in error_str.lower():
                        error_msg += f" - Category '{self.zia_url_category_id}' doesn't exist in ZIA"
                return False, None, False, error_msg

            configured_name = (
                category.get('configuredName') or
                category.get('configured_name') or
                category.get('name') or
                category.get('customCategory')
            )

            category_name = configured_name or category.get('id', 'Unknown')
            self.audit_data['zia_category_name'] = category_name

            if not configured_name:
                return False, category_name, False, (
                    f"Category '{self.zia_url_category_id}' is missing a name field - "
                    f"might be a system category (only custom categories can be modified)"
                )

            current_urls = set(u.lower() for u in category.get('urls', []))

            urls_to_add = set()
            if isinstance(urls, str):
                urls = [urls]
            for url in urls:
                urls_to_add.add(url.lower())

            urls_exist_in_category = urls_to_add.issubset(current_urls)

            if self.action_type == 'add':
                if urls_exist_in_category:
                    self.audit_data['already_present'] = True
                    return True, category_name, True, None
            else:
                if not urls_exist_in_category:
                    self.audit_data['already_present'] = True
                    return True, category_name, True, None

            if not self.dry_run:
                urls_list = list(urls_to_add)
                action = 'ADD_TO_LIST' if self.action_type == 'add' else 'REMOVE_FROM_LIST'

                _, _, err = self.zia_client.url_categories.update_url_category(
                    self.zia_url_category_id,
                    action=action,
                    configured_name=configured_name,
                    urls=urls_list
                )

                if err:
                    return False, category_name, False, f"Failed to update URL category: {err}"

                activation_success, activation_msg = self._activate_changes()
                self.audit_data['activation_status'] = activation_msg
                if not activation_success:
                    return False, category_name, False, activation_msg

                return True, category_name, False, None

            return True, category_name, False, None

        except Exception as e:
            return False, None, False, f"ZIA API error: {str(e)}"

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

    def run(self):
        Responder.run(self)

        data_type = self.get_param('data.dataType')
        data_value = self.get_param('data.data', None, 'No observable data available')

        self.audit_data['ioc'] = data_value
        self.audit_data['ioc_type'] = data_type

        success, category_id, error = self._resolve_category_id()
        if not success:
            self.audit_data['errors'].append(error)
            self.error(error)

        self.zia_url_category_id = category_id

        try:
            if data_type in ['domain', 'fqdn']:
                is_valid, normalized, error = self._validate_domain(data_value)
                if not is_valid:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                self.audit_data['action_taken'] = 'update_url_category'
                success, category_name, already_present, error = self._add_to_url_category(normalized)

                if not success:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                message = self._build_result_message(
                    normalized, 'category', category_name, already_present, "Domain"
                )
                if normalized.startswith('.') and not data_value.strip().startswith('*.'):
                    message += f" (auto-converted from '{data_value}' to parent domain)"

                self.report({'message': message, 'audit': self.audit_data})

            elif data_type == 'url':
                if self.allow_wildcards:
                    # Wildcard mode: block the parent domain only, path is irrelevant
                    raw = data_value if data_value.startswith(('http://', 'https://')) else 'http://' + data_value
                    hostname = urlparse(raw).hostname or ''
                    if not hostname:
                        self.error('Could not extract hostname from URL')
                    is_valid, normalized, error = self._validate_domain(hostname)
                    if not is_valid:
                        self.audit_data['errors'].append(error)
                        self.error(error)
                    self.audit_data['action_taken'] = 'update_url_category'
                    success, category_name, already_present, error = self._add_to_url_category(normalized)
                    if not success:
                        self.audit_data['errors'].append(error)
                        self.error(error)
                    message = self._build_result_message(
                        normalized, 'category', category_name, already_present, "URL"
                    )
                    message += f" (parent domain of '{data_value}')"
                else:
                    is_valid, normalized_url, full_url, error = self._validate_url(data_value)
                    if not is_valid:
                        self.audit_data['errors'].append(error)
                        self.error(error)
                    self.audit_data['action_taken'] = 'update_url_category'
                    success, category_name, already_present, error = self._add_to_url_category(full_url)
                    if not success:
                        self.audit_data['errors'].append(error)
                        self.error(error)
                    url_label = f"{data_value} (added as: {full_url})"
                    message = self._build_result_message(
                        url_label, 'category', category_name, already_present, "URL"
                    )

                self.report({'message': message, 'audit': self.audit_data})

            elif data_type == 'ip':
                is_valid, ip_obj, error = self._validate_ip(data_value)
                if not is_valid:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                self.audit_data['action_taken'] = 'update_url_category'
                success, category_name, already_present, error = self._add_to_url_category(str(ip_obj))

                if not success:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                message = self._build_result_message(
                    str(ip_obj), 'category', category_name, already_present, "IP"
                )

                self.report({'message': message, 'audit': self.audit_data})

            elif data_type == 'cidr':
                is_valid, network_obj, error = self._validate_cidr(data_value)
                if not is_valid:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                self.audit_data['action_taken'] = 'update_url_category'
                success, category_name, already_present, error = self._add_to_url_category(str(network_obj))

                if not success:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                message = self._build_result_message(
                    str(network_obj), 'category', category_name, already_present, "CIDR"
                )

                self.report({'message': message, 'audit': self.audit_data})

            else:
                error_msg = f'Unsupported dataType: {data_type}. Expected: domain, fqdn, url, ip, or cidr'
                self.audit_data['errors'].append(error_msg)
                self.error(error_msg)

        except Exception as e:
            error_msg = f'Unexpected error: {str(e)}'
            self.audit_data['errors'].append(error_msg)
            self.error(error_msg)

    def operations(self, raw):
        if self.audit_data.get('already_present'):
            tag = 'ZIA:url-category:already-present' if self.action_type == 'add' else 'ZIA:url-category:not-found'
        elif self.dry_run:
            tag = 'ZIA:url-category:dry-run'
        else:
            tag = 'ZIA:url-category:added' if self.action_type == 'add' else 'ZIA:url-category:removed'

        return [
            self.build_operation('AddTagToCase', tag='ZIA:action-taken'),
            self.build_operation('AddTagToArtifact', tag=tag)
        ]


if __name__ == '__main__':
    ZscalerZIA_URLCategory().run()
