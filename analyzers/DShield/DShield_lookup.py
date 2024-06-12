#!/usr/bin/env python3
# encoding: utf-8
import json
import requests
import datetime
import math
from cortexutils.analyzer import Analyzer

class DShieldAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

    def dshield_checkip(self, data):
        url = 'https://isc.sans.edu/api/ip/%s?json' % data
        r = requests.get(url)
        return json.loads(r.text)

    def artifacts(self, raw):
        artifacts = []
        if 'as' in raw:
            artifacts.append(
                self.build_artifact(
                    'autonomous-system',
                    str(raw['as']
                    )
                )
            )
        if 'asabusecontact' in raw:
            artifacts.append(
                self.build_artifact(
                    'mail',
                    str(raw['asabusecontact'])
                )
            )
        return artifacts

    def summary(self, raw):
        taxonomies = []
        value = "-"
        level = 'safe'

        categories = raw.get("Categories", None)
        blacklists = raw.get("Blacklists", None)
        num_categories = raw.get("Categories Identifier", None)

        if 'maxrisk' in raw:
            if 'threatfeedscount' in raw:
                r = int(raw['maxrisk']) + raw['threatfeedscount']
            else:
                r = int(raw['maxrisk'])
            if r <= 1:
                level = 'safe'
            elif r <= 6:
                level = 'suspicious'
            else:
                level = 'malicious'

        value = "{} count(s) / {} attack(s) / {} threatfeed(s)".format(raw['count'], raw['attacks'], raw['threatfeedscount'])

        taxonomies.append(self.build_taxonomy(level, "DShield", "Score", value))
        return {"taxonomies": taxonomies}

    def get_reputation(self, risk):
        if risk <= 1:
            return("Safe")
        elif risk <= 6:
            return("Suspicious")
        else:
            return("Malicious")

    def run(self):
        if self.data_type == 'ip':
            data = self.get_param('data', None, 'Data is missing')
            r = self.dshield_checkip(data)
            # Do we get valid results
            if self.data_type in r.keys():
                info = r[self.data_type]
                results = {}
                results['ip'] = info['number']
                results['count'] = info['count'] if isinstance(info['count'], int) else 0
                results['attacks'] = info['attacks'] if isinstance(info['attacks'], int) else 0
                results['lastseen'] = info['maxdate'] if isinstance(info['maxdate'], str) else 'None'
                results['firstseen'] = info['mindate'] if isinstance(info['mindate'], str) else 'None'
                results['updated'] = info['updated'] if isinstance(info['updated'], str) else 'None'
                results['comment'] = info['comment'] if isinstance(info['comment'], str) else 'None'
                results['asabusecontact'] = info['asabusecontact'] if isinstance(info['asabusecontact'], str) else 'Unknown'
                results['as'] = info['as']
                results['asname'] = info['asname']
                results['ascountry'] = info['ascountry']
                results['assize'] = info['assize']
                results['network'] = info['network']
                results['threatfeedscount'] = 0
                if 'threatfeeds' not in info:
                    results['threatfeeds'] = ''
                else:
                    results['threatfeedscount'] = len(json.loads(json.dumps(info['threatfeeds'])))
                    results['threatfeeds'] = info['threatfeeds'] 
                # Compute a risk level based on collected information
                results['maxrisk'] = 0
                maxrisk = 10
                if results['attacks'] > 0:
                    results['maxrisk'] = round(min(math.log10(results['attacks']) * 2, maxrisk))

                # We add the number of threat feeds to the maxrisk to increase the detection rate
                results['reputation'] = self.get_reputation(int(results['maxrisk']) + results['threatfeedscount'])
                self.report(results)
            else:
                self.error('No data found')
        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    DShieldAnalyzer().run()
