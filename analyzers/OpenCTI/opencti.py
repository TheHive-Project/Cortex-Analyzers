#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from pycti import OpenCTIApiClient

class OpenCTIAnalyzer(Analyzer):
    """Searches for given Observables in configured OpenCTI instances. All standard data types are supported."""

    def __init__(self):
        Analyzer.__init__(self)

        self.service = self.get_param(
            'config.service', "search_observable", None)

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
                            urls[i],
                            keys[i],
                            "error",
                            ssl,
                            proxies,
                        )
                    })
            except Exception as e:
                self.error(str(e))

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "OpenCTI"
        predicate = "Search Observable"

        data = []
        found = False
        for r in raw['results']:
            if r['observable']:
                found = True
            for res in r['reports']:
                if 'id' in res:
                    data.append(res['id'])

        # return number of reports
        value = "Found - " if found else "Not found - "
        if not data:
            value += "0 reports"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        else:
            value += "{} report(s)".format(len(list(set(data))))
            level = "suspicious"
            taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

        return {"taxonomies": taxonomies}

    def run(self):

        data = self.get_param('data', None, 'Data is missing')

        response = []

        for opencti in self.openctis:
            # Lookup observable 
            observable = opencti["api_client"].stix_observable.read(
                filters=[{"key": "observable_value", "values": [data]}]
            )
            reports = []
            if observable:
                # Strip observable data for lighter output.
                del(observable["markingDefinitionsIds"])
                del(observable["tagsIds"])
                del(observable["externalReferencesIds"])
                del(observable["indicatorsIds"])

                # Get a list of reports containing this observable
                reports = opencti["api_client"].report.list(
                    filters=[
                        {
                            "key": "observablesContains",
                            "values": [observable["id"]],
                        }
                    ]
                )

                # Strip reports data for lighter output.
                for r in reports:
                    del(r["graph_data"])
                    del(r["objectRefs"])
                    del(r["observableRefs"])
                    del(r["relationRefs"])
                    del(r["markingDefinitionsIds"])
                    del(r["tagsIds"])
                    del(r["externalReferencesIds"])
                    del(r["objectRefsIds"])
                    del(r["observableRefsIds"])
                    del(r["relationRefsIds"])

            response.append({
                "name": opencti["name"],
                "url": opencti["url"],
                "observable": observable,
                "reports": reports
            })

        self.report({'results': response})


if __name__ == '__main__':
    OpenCTIAnalyzer().run()
