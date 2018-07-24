#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer

import os
import pyclamd

cd = pyclamd.ClamdUnixSocket()

class ClamAnalyzer(Analyzer):
    """This is a minimal analyzer that just does nothing other than returning an empty result. It can be used as
    skeleton when creating new analyzers."""

    def __init__(self):
        """Initialization of the class. Here normally all parameters are read using `self.get_param`
        (or `self.getParam`)"""
        Analyzer.__init__(self)


    def check(self, file: str) -> list:
        """
        Checks a given file against all available yara rules

        :param file: Path to file
        :returns: Python dictionary containing the results
        """
        result = []
        match = cd.scan_file(file)
        result.append(str(match))
        
        return result


   # def summary(self, raw):
    #    return raw
    def summary(self, raw):
        taxonomies = []
        namespace = "Clamscan"
        predicate = "Match"

        value = "{} rule(s)".format(len(raw["results"]))        
        if len(str(raw["results"])) < 12:            
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
    """This is necessary, because it is called from the CLI."""
    ClamAnalyzer().run()
