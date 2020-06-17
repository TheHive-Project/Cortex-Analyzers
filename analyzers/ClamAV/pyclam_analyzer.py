#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer

import os
import pyclamd

cd = pyclamd.ClamdUnixSocket()


class ClamAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

    def check(self, file: str) -> list:
        """
        Checks a given file against all available yara rules

        :param file: Path to file
        :returns: Python dictionary containing the results
        """
        match = cd.scan_file(file)
        if match:
            return match[file][1]
        return None

    # def summary(self, raw):
    #    return raw
    def summary(self, raw):
        taxonomies = []
        namespace = "ClamAV"
        predicate = "Match"

        if raw["results"]:
            value = "{}".format(raw["results"])
            level = "malicious"
        else:
            value = "No matches"
            level = "safe"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):
        if self.data_type == "file":
            self.report({"results": self.check(self.getParam("file"))})
        else:
            self.error("Wrong data type.")


if __name__ == "__main__":
    """This is necessary, because it is called from the CLI."""
    ClamAnalyzer().run()
