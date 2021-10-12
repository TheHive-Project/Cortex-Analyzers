#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from pycti import OpenCTIApiClient
import re

class OpenCTIAnalyzer(Analyzer):
    """Searches for given Observables in configured OpenCTI instances. All standard data types are supported."""

    def __init__(self):
        Analyzer.__init__(self)

        self.service = self.get_param(
            'config.service', "search_exact", None)

        ssl = self.get_param('config.cert_check', True)
        names = self.get_param('config.name', None, 'No OpenCTI instance name given.')
        urls = self.get_param('config.url', None, 'No OpenCTI url given.')
        keys = self.get_param('config.key', None, 'No OpenCTI api key given.')
        proxies = self.get_param('config.proxy', None)        

        if len(names) != len(urls) or len(urls) != len(keys):
            self.error("Config error: please add a name, an url and a key for each OpenCTI instance.")

        else:
            try:
                self.openctis = []
                for i in range(len(names)):
                    self.openctis.append({
                        "name": names[i],
                        "url": urls[i],
                        "api_client": OpenCTIApiClient(
                            url=urls[i],
                            token=keys[i],
                            log_level="error",
                            ssl_verify=ssl,
                            proxies={'http': self.http_proxy, 'https': self.https_proxy}
                        )
                    })
            except Exception as e:
                self.error(str(e))

    # determine which exact hash method is associated to a "hash" value
    def get_hash_type(self, ioc):
        print("###", ioc)
        match_d = {"sha256": "^([a-f0-9]{64})$",
                   "sha1": "^([a-f0-9]{40})$",
                   "md5": "^([a-f0-9]{32})$",
        }
        for k in match_d.keys():
            m = re.match(match_d[k], ioc, re.IGNORECASE)
            if m: return k
        return None

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "OpenCTI"
        predicate = "Search Observable"

        found = 0
        for r in raw['results']:
            if r['observables']:
                found += len(r['observables'])

        value = ("Found " + str(found) + " observables") if found > 0 else "Not found"
        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):

        data = self.get_param('data', None, 'Data is missing')
        data_type = self.get_param('dataType', None, 'Data type is missing')

        response = []

        cortex2opencti_types = {"ip": "value",
                                "url": "value",
                                "domain": "value",
                                "mail": "value",
                                "md5": "hashes_MD5",
                                "sha1": "hashes_SHA1",
                                "sha256": "hashes_SHA256",
                                "filename": "name"}
        for opencti in self.openctis:
            # Lookup observables

            # Prepare an OpenCTI type in case of an exact search
            if data_type == "hash": data_type = self.get_hash_type(data)
            opencti_type = cortex2opencti_types.get(data_type)
            if self.service == "search_exact" and opencti_type:
                observables = [opencti["api_client"].stix_cyber_observable.read(
                    filters=[{"key": opencti_type, "values": [data]}])]
            else:
                observables = opencti["api_client"].stix_cyber_observable.list(search=data)

            for observable in observables:
                # Strip observable data for lighter output
                for key in ["objectMarkingIds", "objectLabelIds", "externalReferencesIds",
                            "indicatorsIds", "parent_types"]:
                    observable.pop(key, None)

                # Get a list of reports containing this observable
                reports = opencti["api_client"].report.list(
                    filters=[
                        {
                            "key": "objectContains",
                            "values": [observable["id"]],
                        }
                    ]
                )

                # Strip reports data for lighter output.
                for report in reports:
                    for key in ["objects", "objectMarkingIds", "externalReferencesIds",
                                "objectLabelIds", "parent_types", "objectsIds", "x_opencti_graph_data"]:
                        report.pop(key, None)

                observable["reports"] = reports

            response.append({
                "name": opencti["name"],
                "url": opencti["url"],
                "observables": observables
            })

        self.report({'results': response})


if __name__ == '__main__':
    OpenCTIAnalyzer().run()
