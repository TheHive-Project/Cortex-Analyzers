#!/usr/bin/env python3
# encoding: utf-8
import json
import requests
import datetime
from cortexutils.analyzer import Analyzer


class WOTAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.WOT_key = self.get_param('config.key', None,
                                      'Missing WOT API key')
        self.categories = {
            "101": "Malware or viruses",
            "102": "Poor customer experience",
            "103": "Phishing",
            "104": "Scam",
            "105": "Potentially illegal",
            "201": "Misleading claims or unethical",
            "202": "Privacy risks",
            "203": "Suspicious",
            "204": "Hate, discrimination",
            "205": "Spam",
            "206": "Potentially unwanted programs",
            "207": "Ads / pop-ups",
            "301": "Online tracking",
            "302": "Alternative or controversial medicine",
            "303": "Opinions, religion, politics",
            "304": "Other",
            "401": "Adult content",
            "402": "Incidental nudity",
            "403": "Gruesome or shocking",
            "404": "Site for kids",
            "501": "Good site"
        }

    def points_to_verbose(self, points):
        if points >= 80:
            return "Excellent"
        elif points >= 60:
            return "Good"
        elif points >= 40:
            return "Unsatisfactory"
        elif points >= 20:
            return "Poor"
        else:
            return "Very poor"

    def wot_checkurl(self, data):
        url = 'http://api.mywot.com/0.4/public_link_json2?hosts=' + data + '/&callback=process&key=' + self.WOT_key
        r = requests.get(url)
        return json.loads(r.text.replace("process(", "").replace(")", ""))

    def summary(self, raw):
        taxonomies = []
        value = "-"

        categories = raw.get("Categories", None)
        blacklists = raw.get("Blacklists", None)
        num_categories = raw.get("Categories Identifier", None)

        if categories:
            value = "|".join(categories)
        if blacklists:
            value = "|".join([x[0] for x in blacklists])
            level = "malicious"
        else:
            if num_categories:
                min_cat = min([int(x) for x in num_categories])
            else:
                min_cat = 501
            if min_cat > 300:
                level = "safe"
            elif min_cat > 200:
                level = "suspicious"
            else:
                level = "malicious"

        taxonomies.append(self.build_taxonomy(level, "WOT", "Category", "{}".format(value)))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type in ['domain', 'fqdn']:
            data = self.get_param('data', None, 'Data is missing')
            r = self.wot_checkurl(data)
            if data in r.keys():
                info = r[data]
                r_dict = {}
                if '0' in info.keys():
                    r_dict['Trustworthiness'] = {}
                    r_dict['Trustworthiness']['Reputation'] = self.points_to_verbose(info['0'][0])
                    r_dict['Trustworthiness']['Confidence'] = self.points_to_verbose(info['0'][1])
                if '4' in info.keys():
                    r_dict['Child_Safety'] = {}
                    r_dict['Child_Safety']['Reputation'] = self.points_to_verbose(info['4'][0])
                    r_dict['Child_Safety']['Confidence'] = self.points_to_verbose(info['4'][1])
                if 'blacklists' in info.keys():
                    r_dict['Blacklists'] = [(k, datetime.datetime.fromtimestamp(v).strftime('%Y-%m-%d %H:%M:%S'))
                                            for k, v in info['blacklists'].items()]
                if 'categories' in info.keys():
                    r_dict['Categories'] = [self.categories[x] for x in list(info['categories'].keys())]
                    r_dict['Categories Identifier'] = list(info['categories'].keys())
                self.report(r_dict)
        else:
            self.error('Invalid data type')


if __name__ == '__main__':
    WOTAnalyzer().run()
