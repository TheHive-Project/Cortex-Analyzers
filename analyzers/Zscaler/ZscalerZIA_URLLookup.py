#!/usr/bin/env python3
# encoding: utf-8

from urllib.parse import urlparse

from cortexutils.analyzer import Analyzer
from zscaler import ZscalerClient
from zscaler.oneapi_client import LegacyZIAClient


class ZscalerZIA_URLLookup(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

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

        self.malicious_categories = self.get_param('config.malicious_categories', [])
        self.suspicious_categories = self.get_param('config.suspicious_categories', [])
        self.zia_client = None

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

                    try:
                        zscaler_client = ZscalerClient(config)
                        self.zia_client = zscaler_client.zia
                    except Exception as oauth_error:
                        self.error(f"OAuth authentication failed: {str(oauth_error)}")
                else:
                    config = {
                        "username": self.zia_username,
                        "password": self.zia_password,
                        "api_key": self.zia_api_key,
                        "cloud": self.zia_cloud,
                        "logging": {"enabled": False, "verbose": False}
                    }

                    try:
                        legacy_client = LegacyZIAClient(config)
                        self.zia_client = legacy_client.zia
                    except Exception as legacy_error:
                        self.error(f"Legacy API authentication failed: {str(legacy_error)}")

            except Exception as e:
                self.error(f'Unexpected error during ZIA client initialization: {str(e)}')

    def _normalize_url(self, data, data_type):
        if data_type == 'url':
            url_data = urlparse(data)
            normalized = url_data.netloc + url_data.path
            if url_data.params:
                normalized += ';' + url_data.params
            if url_data.query:
                normalized += '?' + url_data.query
            return normalized
        return data

    def _classify_url(self, url_data):
        url = url_data.get('url', 'Unknown')
        url_classifications = url_data.get('urlClassifications', [])
        security_classifications = url_data.get('urlClassificationsWithSecurityAlert', [])
        db_categorized_urls = url_data.get('dbCategorizedUrls', [])
        custom_categories = url_data.get('customCategories', [])

        level = 'safe'
        matched_categories = []

        # Security alerts have highest priority
        if security_classifications:
            level = 'suspicious'
            matched_categories = security_classifications

            if set(security_classifications).intersection(set(self.malicious_categories)):
                level = 'malicious'
                matched_categories = list(set(security_classifications).intersection(set(self.malicious_categories)))

        if url_classifications:
            if set(url_classifications).intersection(set(self.malicious_categories)):
                level = 'malicious'
                matched_categories = list(set(url_classifications).intersection(set(self.malicious_categories)))
            elif set(url_classifications).intersection(set(self.suspicious_categories)):
                if level != 'malicious':
                    level = 'suspicious'
                    matched_categories = list(set(url_classifications).intersection(set(self.suspicious_categories)))
            elif not security_classifications:
                level = 'safe'
                matched_categories = url_classifications

        return {
            'url': url,
            'level': level,
            'matched_categories': matched_categories,
            'all_classifications': url_classifications,
            'security_alerts': security_classifications,
            'custom_categories': custom_categories,
            'db_categorized_urls': db_categorized_urls,
            'metrics': {
                'total_categories': len(url_classifications),
                'security_alert_count': len(security_classifications),
                'has_custom_categories': len(custom_categories) > 0,
                'is_known_to_zscaler': len(db_categorized_urls) > 0 or len(url_classifications) > 0,
                'has_security_alerts': len(security_classifications) > 0
            }
        }

    def summary(self, raw):
        taxonomies = []

        classification = raw.get('classification', {})
        level = classification.get('level', 'info')
        matched_categories = classification.get('matched_categories', [])

        if matched_categories:
            value = ', '.join(matched_categories[:3])
            if len(matched_categories) > 3:
                value += f' (+{len(matched_categories) - 3} more)'
        else:
            value = 'No match'

        taxonomies.append(self.build_taxonomy(level, 'Zscaler', 'Category', value))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)

        if self.data_type not in ['domain', 'fqdn', 'url', 'ip']:
            self.error(f'Invalid data type: {self.data_type}. Expected: domain, fqdn, url, or ip')

        data = self.get_param('data', None, 'No observable data available')
        self._init_zia_client()

        try:
            normalized_url = self._normalize_url(data, self.data_type)
            result, error = self.zia_client.url_categories.lookup([normalized_url])

            if error:
                self.error(f'Zscaler URL lookup failed: {error}')

            if not result or len(result) == 0:
                self.error('No results returned from Zscaler')

            url_data = result[0]
            classification = self._classify_url(url_data)

            report = {
                'classification': classification,
                'categorization': {
                    'url_classifications': url_data.get('urlClassifications', []),
                    'security_alerts': url_data.get('urlClassificationsWithSecurityAlert', []),
                    'custom_categories': url_data.get('customCategories', []),
                    'db_categorized_urls': url_data.get('dbCategorizedUrls', [])
                },
                'assessment': {
                    'risk_level': classification['level'],
                    'is_malicious': classification['level'] == 'malicious',
                    'is_suspicious': classification['level'] in ['suspicious', 'malicious'],
                    'has_security_alerts': len(url_data.get('urlClassificationsWithSecurityAlert', [])) > 0,
                    'category_count': len(url_data.get('urlClassifications', [])),
                    'matched_threat_categories': classification['matched_categories']
                },
                'query': {
                    'original': data,
                    'normalized': normalized_url,
                    'type': self.data_type
                },
                'raw_response': url_data
            }

            self.report(report)

        except Exception as e:
            self.error(f'Unexpected error during URL lookup: {str(e)}')


if __name__ == '__main__':
    ZscalerZIA_URLLookup().run()
