#!/usr/bin/env python3
# encoding: utf-8

import time
import hashlib
from diario import Diario
from cortexutils.analyzer import Analyzer


class DiarioAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        self.service = self.get_param('config.service', None, 'Service parameter is missing')
        self.client_id = self.get_param('config.client_id', None, 'Missing Client ID')
        self.secret = self.get_param('config.secret', None, 'Missing Secret')
        self.polling_interval = self.get_param('config.polling_interval', 60)
        self.api = Diario(self.client_id, self.secret)

    _predictions = {
        "M": "Malware",
        "G": "Goodware",
        "NM": "No Macros present",  # Only applies to office documents
        "U": "Unknown"
    }

    _stages = {
        "A": "Analyzed",
        "Q": "Queued",
        "P": "Processing",
        "F": "Failed"
    }

    def check_response(self, document_hash):
        response = self.api.search(document_hash)
        if response.error:
            if response.error.code == 413:
                time.sleep(self.polling_interval)
                return self.check_response(document_hash)
            elif response.error.code in (406, 409):
                return dict(message=response.error.message)
            else:
                self.error(response.error)
        if response.data["status"] in ("P", "Q"):
            time.sleep(self.polling_interval)
            return self.check_response(document_hash)
        elif response.data["status"] == "F":
            self.error(response.data)

        data = response.data
        data["prediction"] = self._predictions.get(data["prediction"])
        data["status"] = self._stages.get(data["status"])
        return dict(data)

    def summary(self, raw):
        taxonomies = []
        level = "info"
        namespace = "Diario"
        predicate = "GetReport"
        value = "Not Found"

        if self.service == "scan":
            predicate = "Scan"

        verdicts = {
            "Goodware": "safe",
            "Malware": "malicious",
            "Unknown": "suspicious",
            "No Macros present": "info",
        }

        if "sha256" in raw:
            value = raw["prediction"]
            level = verdicts.get(value)

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def run(self):

        if self.service == "scan":
            if self.data_type == "file":
                filepath = self.get_param('file', None, 'File is missing')
                response = self.api.upload(filepath)
                if response.error:
                    self.error(response.error["message"])
                data = response.data.get("hash", None)
            else:
                self.error("Data type has to be a File")
                return

        elif self.service == "get":
            # If we want to only get the report of a file we get the
            # SHA256 hash and check if there is a report
            if self.data_type == "file":
                filepath = self.get_param('file', None, 'File is missing')
                sha256_hash = hashlib.sha256()
                with open(filepath, "rb") as f:
                    # Read and update hash string value in blocks of 4K
                    for byte_block in iter(lambda: f.read(4096), b""):
                        sha256_hash.update(byte_block)
                data = sha256_hash.hexdigest()
            elif self.data_type == "hash":
                data = self.get_param('data', None, 'Data is missing')
            else:
                self.error("Data type has to be a File or Hash")
                return

        else:
            self.error("Service doesn't exists")
            return

        self.report(self.check_response(data))


if __name__ == '__main__':
    DiarioAnalyzer().run()
