#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from censys.search import CensysHosts, CensysCerts

from censys.common.exceptions import CensysNotFoundException, CensysRateLimitExceededException, CensysUnauthorizedException

import iocextract


class CensysAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        self.__uid = self.get_param(
            "config.uid",
            None,
            "No UID for Censys given. Please add it to the cortex configuration.",
        )
        self.__api_key = self.get_param(
            "config.key",
            None,
            "No API-Key for Censys given. Please add it to the cortex configuration.",
        )
        self.__max_records = self.get_param("config.max_records", None, 10)

    def search_hosts(self, ip):
        c = CensysHosts(api_id=self.__uid, api_secret=self.__api_key)
        query = c.search("ip: " + ip, per_page=1, pages=1)
        for result in query:
            return result
        return {}


    def search_certificate(self, hash):
        c = CensysCerts(api_id=self.__uid, api_secret=self.__api_key)

        try:
            result = c.view(hash)
            return result
        except Exception as e:
            self.error(f"Error fetching certificate: {str(e)}")
            return {}



    def search_website(self, dom):
        c = CensysHosts(api_id=self.__uid, api_secret=self.__api_key)
        query = c.search("dns.names: " + dom, per_page=self.__max_records, pages=1)
        for result in query:
            return result
        return {}


    def search_freetext(self, search):
        c = CensysHosts(api_id=self.__uid, api_secret=self.__api_key)
        results = c.search(search, fields=self.__fields, max_records=self.__max_records, flatten=self.__flatten)
        return [result for result in results]


    def run(self):
        try:
            if self.data_type == 'ip':
                self.report({
                    'ip': self.search_hosts(self.get_data())
                })
            elif self.data_type == 'hash':
                self.report({
                    'cert': self.search_certificate(self.get_data())
                })
            elif self.data_type == 'domain' or self.data_type == 'fqdn':
                self.report({
                    'website': self.search_website(self.get_data())
                })
            # elif self.data_type == 'other':
            #     self.report({
            #         'matches': self.search_freetext(self.get_data())
            #     })
            else:
                self.error(
                    "Data type not supported. Please use this analyzer with data types hash, ip or domain."
                )
        except CensysNotFoundException:
            self.report({"message": "{} could not be found.".format(self.get_data())})
        except CensysUnauthorizedException:
            self.error(
                "Censys raised NotAuthorizedException. Please check your credentials."
            )
        except CensysRateLimitExceededException:
            self.error("Rate limit exceeded.")

    def artifacts(self, raw):
        artifacts = []
        ipv4s = list(iocextract.extract_ipv4s(str(raw)))
        # ipv6s = list(iocextract.extract_ipv6s(str(raw)))
        domains = list(iocextract.extract_urls(str(raw)))
        hashes = list(iocextract.extract_hashes(str(raw)))

        if ipv4s:
            ipv4s = list(dict.fromkeys(ipv4s))
            for i in ipv4s:
                artifacts.append(self.build_artifact('ip', str(i)))
        
        # if ipv6s:
        #     ipv6s = list(dict.fromkeys(ipv6s))
        #     for i in ipv6s:
        #         artifacts.append(self.build_artifact('ip', str(i)))

        if hashes:
            hashes = list(dict.fromkeys(hashes))
            for j in hashes:
                artifacts.append(self.build_artifact('hash', str(j)))

        if domains:
            domains = list(dict.fromkeys(domains))
            for k in domains:
                artifacts.append(self.build_artifact('url', str(k)))
        return artifacts
    
    def summary(self, raw):
        taxonomies = []

        if 'ip' in raw:
            for ip_info in raw['ip']:
                ip_address = ip_info.get('ip', 'Unknown IP')
                asn = ip_info.get('autonomous_system', {}).get('asn', 'Unknown ASN')
                country = ip_info.get('location', {}).get('country', 'Unknown Country')
                city = ip_info.get('location', {}).get('city', 'Unknown City')
                os_product = ip_info.get('operating_system', {}).get('product', 'Unknown OS')
                service_count = len(ip_info.get('services', []))
                #taxonomies.append(self.build_taxonomy('info', 'Censys', 'IP', ip_address))
                #taxonomies.append(self.build_taxonomy('info', 'Censys', 'ASN', asn))
                #taxonomies.append(self.build_taxonomy('info', 'Censys', 'Country', country))
                #taxonomies.append(self.build_taxonomy('info', 'Censys', 'City', city))
                #taxonomies.append(self.build_taxonomy('info', 'Censys', 'OperatingSystem', os_product))
                taxonomies.append(self.build_taxonomy('info', 'Censys', 'OpenServices', service_count))

        elif 'website' in raw:
            taxonomies.append(self.build_taxonomy('info', 'Censys', 'recordsFound', len(raw["website"])))
            # for site in raw['website']:
            #     ip = site.get('ip', 'Unknown IP')
            #     asn = site.get('autonomous_system', {}).get('asn', 'Unknown ASN')
            #     country = site.get('location', {}).get('country', 'Unknown Country')
            #     service_count = len(site.get('services', []))
            #     #taxonomies.append(self.build_taxonomy('info', 'Censys', 'IP', ip))
            #     #taxonomies.append(self.build_taxonomy('info', 'Censys', 'ASN', asn))
            #     taxonomies.append(self.build_taxonomy('info', 'Censys', 'Country', country))
            #     taxonomies.append(self.build_taxonomy('info', 'Censys', 'Services', service_count))

        elif 'cert' in raw:
            raw = raw['cert']
            validator_keys = ["nss", "microsoft", "apple", "chrome"]
            validator_count = 0
            trusted_count = 0
            for key in validator_keys:
                validator = raw.get("validation", {}).get(key, {})
                if validator.get("is_valid", False) and validator.get("has_trusted_path", False):
                    trusted_count += 1
                validator_count += 1

            if trusted_count < validator_count:
                taxonomies.append(
                    self.build_taxonomy(
                        "suspicious",
                        "Censys",
                        "TrustedCount",
                        f"{trusted_count}/{validator_count}",
                    )
                )
            else:
                taxonomies.append(self.build_taxonomy('info', 'Censys', 'TrustedCount', f'{trusted_count}/{validator_count}'))

        # elif 'matches' in raw:
        #     result_count = len(raw.get('matches', []))
        #     taxonomies.append(self.build_taxonomy('info', 'Censys ipv4 search', 'results', result_count))

        return {
            'taxonomies': taxonomies
        }



if __name__ == "__main__":
    CensysAnalyzer().run()