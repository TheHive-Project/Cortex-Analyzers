#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
import io
import os
import hashlib


class VirusshareAnalyzer(Analyzer):
    """
    This analyzer allows searching through a previously downloaded hash list of virusshare. If the hash has not the
    length of 32 characters (md5), search is skipped and the ``isonvs`` report parameter is set to ``unknown``. In the
    report, a button is placed for redirecting to virusshare.com.
    As parameter this analyzer takes ``path`` which contains the path (obviously...) to the virusshare hash lists. To be
    able to downloads the lists in an easier way, ``download_hashes.py`` was provided. More info in the documentation.
    """
    def __init__(self):
        Analyzer.__init__(self)
        self.path = self.get_param('config.path', None, 'No path to virusshare hash directory given.')
        if not os.path.isdir(self.path):
            self.error('Given path is not a directory.')
        self.filelist = os.listdir(self.path)

    def summary(self, raw):
        taxonomies = []
        level = "safe"
        namespace = "Virusshare"
        predicate = "Search"

        if raw["isonvs"]:
            if raw["isonvs"] == "unknown":
                value = "Not MD5"
                level = "suspicious"
            else:
                value = "Found"
                level = "malicious"
        else:
            value = "Not Found"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {'taxonomies': taxonomies}

    def run(self):
        searchhash = ''
        if self.data_type == 'hash':
            searchhash = self.get_data()
            if len(searchhash) != 32:
                self.report({'isonvs': 'unknown',
                             'hash': searchhash})
        elif self.data_type == 'file':
            filepath = self.get_param('file')
            hasher = hashlib.md5()
            with io.open(filepath, mode='rb') as afile:
                for chunk in iter(lambda: afile.read(65536), b''):
                    hasher.update(chunk)
            searchhash = hasher.hexdigest()
        else:
            self.error('Unsupported data type.')

        # Read files
        for file in self.filelist:
            filepath = os.path.join(self.path, file)
            if not os.path.isfile(filepath):
                continue
            with io.open(filepath, 'r') as afile:
                for line in afile:
                    # Skipping comments
                    if line[0] == '#':
                        continue
                    if searchhash.lower() in line:
                        self.report({'isonvs': True,
                                     'md5': searchhash})
        self.report({'isonvs': False,
                     'md5': searchhash})


if __name__ == '__main__':
    VirusshareAnalyzer().run()
