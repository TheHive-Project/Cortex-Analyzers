#!/usr/bin/env python
# encoding: utf-8

from cortexutils.analyzer import Analyzer

import os, sys
import json
import yara
import zipfile
import requests
import datetime
from requests.auth import HTTPBasicAuth
from stat import S_ISREG, ST_CTIME, ST_MODE, ST_MTIME


class MalpediaAnalyzer(Analyzer):
    """Checking binaries through yara rules. This analyzer requires a list of yara rule paths in the cortex
    configuration. If a path is given, an index file is expected."""
    def __init__(self):
        Analyzer.__init__(self)

        self.baseurl = "https://malpedia.caad.fkie.fraunhofer.de/api/get"
        
        self.rulepaths = str(self.getParam('config.rules', None))
        self.user = self.getParam('config.user', None)
        self.pwd = self.getParam('config.pwd', None)
        self.update_hours = int(self.getParam('config.update_hours', 10))

        if not os.path.exists(self.rulepaths):
            os.makedirs(self.rulepaths)

        try:
            newest = max(datetime.datetime.fromtimestamp(os.stat(path)[ST_MTIME]) for path in (os.path.join(self.rulepaths, fn) for fn in os.listdir(self.rulepaths) if os.path.isfile(os.path.join(self.rulepaths, fn)) and os.path.join(self.rulepaths, fn).endswith('.yar') ))
            hours = (datetime.datetime.now() - newest).seconds / 3600
        except ValueError:
            hours = self.update_hours + 1
        

        if hours > self.update_hours:
            try:
                req = requests.get("%s/yara/after/2010-01-01?format=json" % self.baseurl, auth=HTTPBasicAuth(self.user, self.pwd))
                if req.status_code == requests.codes.ok:
                    rules_json = json.loads(req.text)
                    for color, color_data in rules_json.items():
                        for rule_name, rule_text in color_data.items():
                            with open('%s' % os.path.join(self.rulepaths, rule_name), 'w') as f:
                                f.write(rule_text.encode('utf-8').strip())
            except Exception:
                e = sys.exc_info()[1]
                with open('%s' % os.path.join(self.rulepaths, "error.txt"), 'w') as f:
                    f.write(e.args[0])

    def check(self, file):
        """
        Checks a given file against all available yara rules
        :param file: Path to file
        :type file:str
        :returns: Python list with matched rules info
        :rtype: list
        """
        result = []
        all_matches = []
        for filerules in os.listdir(self.rulepaths): 
            try:
                rule = yara.compile(os.path.join(self.rulepaths, filerules))
            except yara.SyntaxError:
                continue
            matches = rule.match(file)
            if len(matches) > 0:
                for rulem in matches:
                    rule_family = "_".join([x for x in rulem.rule.replace("_", ".", 1).split("_")[:-1]])
                    if rule_family not in all_matches:
                        all_matches.append(rule_family)
        for rule_family in all_matches:    
            rules_info_txt = requests.get("%s/family/%s" % (self.baseurl, rule_family), auth=HTTPBasicAuth(self.user, self.pwd))
            rules_info_json = json.loads(rules_info_txt.text)   
            result.append({
                'family':rule_family, 
                'common_name': rules_info_json['common_name'], 
                'description': rules_info_json['description'], 
                'attribution': rules_info_json['attribution'], 
                'alt_names': rules_info_json['alt_names'], 
                'urls': rules_info_json['urls']
            })
        
        return result

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Malpedia"
        predicate = "Match"

        value = "\"{} rule(s)\"".format(len(raw["results"]))
        if len(raw["results"]) == 0:
            level = "safe"
        else:
            level = "malicious"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == 'file':
            self.report({'results': self.check(self.getParam('file'))})
        else:
            self.error('Wrong data type.')

if __name__ == '__main__':
    MalpediaAnalyzer().run()

