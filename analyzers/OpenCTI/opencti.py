#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from pycti import OpenCTIApiClient

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

        response = []

        for opencti in self.openctis:
            # Lookup observables 
            observables = opencti["api_client"].stix_cyber_observable.list(search=data)

            if self.service == "search_exact":
                # Filter results to only keep exact matches
                observables = [observable for observable in observables if observable["observable_value"] == data]

            for observable in observables:
                # Strip observable data for lighter output
                del(observable["objectMarkingIds"])
                del(observable["objectLabelIds"])
                del(observable["externalReferencesIds"])
                del(observable["indicatorsIds"])
                del(observable["parent_types"])

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
                    del(report["objects"])
                    del(report["objectMarkingIds"])
                    del(report["externalReferencesIds"])
                    del(report["objectLabelIds"])
                    del(report["parent_types"])
                    del(report["objectsIds"])
                    del(report["x_opencti_graph_data"])

                observable["reports"] = reports

            response.append({
                "name": opencti["name"],
                "url": opencti["url"],
                "observables": observables
            })

        self.report({'results': response})


if __name__ == '__main__':
    OpenCTIAnalyzer().run()
