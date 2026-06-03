#!/usr/bin/env python3
# encoding: utf-8
"""
Zscaler ZIA Cloud Firewall Rule Responder

Adds or removes IP addresses and CIDR ranges from the dest_addresses list
of a ZIA Cloud Firewall Rule. The rule must pre-exist in ZIA; this responder
manages its destination address list, not the rule itself.

Network-layer blocking (all ports/protocols). Use for IP/CIDR observables.
For domain/fqdn/url observables use the URLCategory responder instead.
"""

import ipaddress
import time
from datetime import datetime
from urllib.parse import urlparse

from cortexutils.responder import Responder
from zscaler import ZscalerClient
from zscaler.oneapi_client import LegacyZIAClient


class ZscalerZIA_CloudFirewall(Responder):
    """
    Cortex Responder to manage IP/CIDR entries in a ZIA Cloud Firewall Rule.
    Supports: ip, cidr
    """

    PRIVATE_RANGES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
    ]

    LOCALHOST_RANGES = [
        ipaddress.ip_network('127.0.0.0/8'),
        ipaddress.ip_network('::1/128'),
    ]

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

        self.firewall_rule_id = self.get_param('config.firewall_rule_id', None)
        self.firewall_rule_name = self.get_param('config.firewall_rule_name', None)

        if not self.firewall_rule_id and not self.firewall_rule_name:
            self.error('Either firewall_rule_id or firewall_rule_name must be provided')

        self.action_type = self.get_param('config.action_type', 'add').lower()
        self.dry_run = self.get_param('config.dry_run', False)
        self.activate_changes = self.get_param('config.activate_changes', True)
        self.allow_private_ips = self.get_param('config.allow_private_ips', False)
        self.allow_risky_iocs = self.get_param('config.allow_risky_iocs', False)
        proxy_url = self.get_param('config.proxy_https', None) or self.get_param('config.proxy_http', None)
        self.proxy_config = self._parse_proxy(proxy_url)

        self.zia_client = None
        self.audit_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'dry_run': self.dry_run,
            'action_taken': None,
            'ioc': None,
            'ioc_type': None,
            'firewall_rule_id': self.firewall_rule_id,
            'firewall_rule_name': None,
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
                    except Exception as e:
                        error_msg = f"OAuth authentication failed: {str(e)}"
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
                    except Exception as e:
                        error_msg = f"Legacy API authentication failed: {str(e)}"
                        self.audit_data['errors'].append(error_msg)
                        self.error(error_msg)
            except Exception as e:
                error_msg = f'Unexpected error during ZIA client initialization: {str(e)}'
                self.audit_data['errors'].append(error_msg)
                self.error(error_msg)

    def _resolve_rule_id(self):
        """Resolve firewall rule name to ID, or validate the provided ID exists."""
        self._init_zia_client()

        try:
            rules, _, err = self.zia_client.cloud_firewall_rules.list_rules()
            if err:
                return False, None, f"Failed to list firewall rules: {err}"
            if not rules:
                return False, None, "No firewall rules found"

            # If ID provided: validate it exists and capture the name
            if self.firewall_rule_id:
                for rule in rules:
                    rid = rule.get('id') if isinstance(rule, dict) else getattr(rule, 'id', None)
                    if str(rid) == str(self.firewall_rule_id):
                        rname = rule.get('name') if isinstance(rule, dict) else getattr(rule, 'name', None)
                        self.audit_data['firewall_rule_name'] = rname
                        return True, self.firewall_rule_id, None

                available = self._rule_list_summary(rules)
                return False, None, (
                    f"Firewall rule ID '{self.firewall_rule_id}' not found. "
                    f"Available rules: {available}"
                )

            # Name lookup
            search_name = self.firewall_rule_name.lower()
            matches = []
            for rule in rules:
                rname = rule.get('name') if isinstance(rule, dict) else getattr(rule, 'name', None)
                rid = rule.get('id') if isinstance(rule, dict) else getattr(rule, 'id', None)
                if rname and rname.lower() == search_name:
                    matches.append({'id': rid, 'name': rname})

            if not matches:
                available = self._rule_list_summary(rules)
                return False, None, (
                    f"Firewall rule '{self.firewall_rule_name}' not found. "
                    f"Available rules: {available}"
                )

            if len(matches) > 1:
                return False, None, (
                    f"Multiple rules match '{self.firewall_rule_name}'. "
                    f"Use firewall_rule_id instead."
                )

            self.audit_data['firewall_rule_name'] = matches[0]['name']
            return True, matches[0]['id'], None

        except Exception as e:
            return False, None, f"Rule lookup failed: {str(e)}"

    def _rule_list_summary(self, rules):
        """Return a short summary of available rules for error messages."""
        names = []
        for rule in rules[:5]:
            rid = rule.get('id') if isinstance(rule, dict) else getattr(rule, 'id', '?')
            rname = rule.get('name') if isinstance(rule, dict) else getattr(rule, 'name', '?')
            names.append(f"{rid}: {rname}")
        return ', '.join(names)

    def _validate_ip(self, ip_str):
        if not ip_str:
            return False, None, "Empty IP address"
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            for r in self.LOCALHOST_RANGES:
                if ip_obj in r:
                    return False, None, f"Localhost IP blocked: {ip_str}"
            if not self.allow_private_ips:
                for r in self.PRIVATE_RANGES:
                    if ip_obj in r:
                        return False, None, f"Private IP blocked (RFC1918): {ip_str}"
            return True, str(ip_obj), None
        except ValueError as e:
            return False, None, f"Invalid IP address: {str(e)}"

    def _validate_cidr(self, cidr_str):
        if not cidr_str:
            return False, None, "Empty CIDR"
        try:
            network = ipaddress.ip_network(cidr_str, strict=False)
            if not self.allow_risky_iocs and network.num_addresses > 256:
                return False, None, f"CIDR too broad ({network.num_addresses} addresses): {cidr_str}"
            for r in self.LOCALHOST_RANGES:
                if network.overlaps(r):
                    return False, None, f"CIDR overlaps with localhost: {cidr_str}"
            if not self.allow_private_ips:
                for r in self.PRIVATE_RANGES:
                    if network.overlaps(r):
                        return False, None, f"CIDR overlaps with private range (RFC1918): {cidr_str}"
            return True, str(network), None
        except ValueError as e:
            return False, None, f"Invalid CIDR notation: {str(e)}"

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

    def _get_field(self, obj, *keys, default=None):
        """Get a field from a dict or object, trying multiple key names."""
        for key in keys:
            val = obj.get(key) if isinstance(obj, dict) else getattr(obj, key, None)
            if val is not None:
                return val
        return default

    def _build_rule_payload(self, rule, new_addresses):
        """
        Build update payload preserving all existing rule fields.
        Only dest_addresses is modified; everything else is carried over as-is.
        """
        g = self._get_field

        payload = {
            'name': g(rule, 'name'),
            'order': g(rule, 'order'),
            'action': g(rule, 'action'),
            'state': g(rule, 'state'),
            'dest_addresses': new_addresses,
        }

        # Carry over optional fields if present on the existing rule
        optional_fields = [
            ('description', 'description'),
            ('dest_ip_categories', 'destIpCategories'),
            ('dest_countries', 'destCountries'),
            ('nw_services', 'nwServices'),
            ('nw_service_groups', 'nwServiceGroups'),
            ('nw_applications', 'nwApplications'),
            ('nw_application_groups', 'nwApplicationGroups'),
            ('src_ip_groups', 'srcIpGroups'),
            ('src_ipv6_groups', 'srcIpv6Groups'),
            ('dest_ip_groups', 'destIpGroups'),
            ('departments', 'departments'),
            ('groups', 'groups'),
            ('users', 'users'),
            ('time_windows', 'timeWindows'),
            ('locations', 'locations'),
            ('location_groups', 'locationGroups'),
            ('labels', 'labels'),
            ('rank', 'rank'),
            ('enable_full_logging', 'enableFullLogging'),
        ]

        for snake, camel in optional_fields:
            val = g(rule, snake, camel)
            if val is not None:
                payload[snake] = val

        return payload

    def _manage_firewall_rule(self, address, rule_id):
        """
        Add or remove an IP/CIDR from a ZIA Cloud Firewall Rule's dest_addresses.
        Returns: (success, rule_name, already_present, error_message)
        """
        self._init_zia_client()

        try:
            rule, _, err = self.zia_client.cloud_firewall_rules.get_rule(rule_id)

            if err or not rule:
                error_msg = f"Firewall rule ID '{rule_id}' not found"
                if err:
                    error_str = str(err)
                    error_msg = f"{error_msg}: {error_str}"
                    if '401' in error_str or 'Unauthorized' in error_str:
                        error_msg += " - check OAuth credentials and permissions"
                    elif '403' in error_str or 'Forbidden' in error_str:
                        error_msg += " - account lacks Cloud Firewall edit permissions"
                return False, None, False, error_msg

            rule_name = self._get_field(rule, 'name') or str(rule_id)
            self.audit_data['firewall_rule_name'] = rule_name

            rule_action = (self._get_field(rule, 'action') or '').upper()
            if rule_action == 'ALLOW':
                return False, rule_name, False, (
                    f"Firewall rule '{rule_name}' has action ALLOW, not a blocking rule. "
                    f"Use a BLOCK_DROP/BLOCK_RESET/BLOCK_ICMP rule to block traffic."
                )

            current_addresses = self._get_field(rule, 'dest_addresses', 'destAddresses') or []
            current_set = {a.strip() for a in current_addresses if a}

            address_normalized = address.strip()
            already_present = address_normalized in current_set

            if self.action_type == 'add':
                if already_present:
                    self.audit_data['already_present'] = True
                    return True, rule_name, True, None
            else:  # remove
                if not already_present:
                    self.audit_data['already_present'] = True
                    return True, rule_name, True, None

            if not self.dry_run:
                if self.action_type == 'add':
                    new_addresses = sorted(current_set | {address_normalized})
                else:
                    new_addresses = sorted(a for a in current_set if a != address_normalized)

                payload = self._build_rule_payload(rule, new_addresses)
                _, _, err = self.zia_client.cloud_firewall_rules.update_rule(rule_id, **payload)

                if err:
                    return False, rule_name, False, f"Failed to update firewall rule: {err}"

                activation_success, activation_msg = self._activate_changes()
                self.audit_data['activation_status'] = activation_msg
                if not activation_success:
                    return False, rule_name, False, activation_msg

            return True, rule_name, False, None

        except Exception as e:
            return False, None, False, f"ZIA API error: {str(e)}"

    def _build_message(self, ioc_label, ioc_value, rule_name, already_present):
        action_verb = 'added to' if self.action_type == 'add' else 'removed from'
        if already_present:
            status = 'already in' if self.action_type == 'add' else 'not found in'
        else:
            status = action_verb
        message = f"{ioc_label} '{ioc_value}' {status} firewall rule '{rule_name}'"
        if self.dry_run and not already_present:
            message = f"[DRY RUN] Would have {action_verb} firewall rule '{rule_name}'"
        return message

    def run(self):
        Responder.run(self)

        data_type = self.get_param('data.dataType')
        data_value = self.get_param('data.data', None, 'No observable data available')

        self.audit_data['ioc'] = data_value
        self.audit_data['ioc_type'] = data_type

        success, rule_id, error = self._resolve_rule_id()
        if not success:
            self.audit_data['errors'].append(error)
            self.error(error)
        self.firewall_rule_id = rule_id

        try:
            if data_type == 'ip':
                is_valid, normalized, error = self._validate_ip(data_value)
                if not is_valid:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                self.audit_data['action_taken'] = 'manage_cloud_firewall'
                success, rule_name, already_present, error = self._manage_firewall_rule(normalized, rule_id)

                if not success:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                self.report({'message': self._build_message('IP', normalized, rule_name, already_present), 'audit': self.audit_data})

            elif data_type == 'cidr':
                is_valid, normalized, error = self._validate_cidr(data_value)
                if not is_valid:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                self.audit_data['action_taken'] = 'manage_cloud_firewall'
                success, rule_name, already_present, error = self._manage_firewall_rule(normalized, rule_id)

                if not success:
                    self.audit_data['errors'].append(error)
                    self.error(error)

                self.report({'message': self._build_message('CIDR', normalized, rule_name, already_present), 'audit': self.audit_data})

            else:
                error_msg = f'Unsupported dataType: {data_type}. Expected: ip or cidr'
                self.audit_data['errors'].append(error_msg)
                self.error(error_msg)

        except Exception as e:
            error_msg = f'Unexpected error: {str(e)}'
            self.audit_data['errors'].append(error_msg)
            self.error(error_msg)

    def operations(self, raw):
        if self.audit_data.get('already_present'):
            tag = 'ZIA:cloud-firewall:already-present' if self.action_type == 'add' else 'ZIA:cloud-firewall:not-found'
        elif self.dry_run:
            tag = 'ZIA:cloud-firewall:dry-run'
        else:
            tag = 'ZIA:cloud-firewall:added' if self.action_type == 'add' else 'ZIA:cloud-firewall:removed'

        return [
            self.build_operation('AddTagToCase', tag='ZIA:action-taken'),
            self.build_operation('AddTagToArtifact', tag=tag)
        ]


if __name__ == '__main__':
    ZscalerZIA_CloudFirewall().run()
