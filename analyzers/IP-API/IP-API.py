#!/usr/bin/env python3
import requests
from cortexutils.analyzer import Analyzer


class IPAPI(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.key = self.get_param("config.key", None)

    def summary(self, raw):
        taxonomies = []
        level = 'info'
        namespace = 'IP-API'
        predicate = 'Country'
        value = "None"
        if "country" in raw:
            value = "{}".format(raw["country"])
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        Analyzer.run(self)
        if self.data_type in ('ip', 'domain'):
            data = self.get_data()
            base_url = "https://pro.ip-api.com/json" if self.key else "http://ip-api.com/json"
            fields = "status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query"
            params = {"key": self.key, "fields": fields} if self.key else {"fields": fields}

            try:
                with requests.Session() as session:
                    response = session.get(f"{base_url}/{data}", params=params, timeout=10)
                    response.raise_for_status()
                    result = response.json()
                    self.report(result or {})
            except requests.RequestException as e:
                self.error(f"HTTP request failed: {e}")
            except Exception as e:
                self.unexpectedError(e)
        else:
            self.notSupported()


if __name__ == '__main__':
    IPAPI().run()
