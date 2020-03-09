#!/usr/bin/env python3
# encoding: utf-8
import re
import os
import subprocess
from cortexutils.analyzer import Analyzer

try:
    import sqlalchemy as db

    USE_DB = True
except ImportError:
    USE_DB = False

FIELDS = [
    "sha1",
    "md5",
    "crc32",
    "filename",
    "filesize",
    "productcode",
    "opsystemcode",
    "specialcode",
]


class NsrlAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        conn = self.get_param("config.conn", None)
        self.engine = None
        self.grep_path = self.get_param("config.grep_path", None)
        self.file_path = self.get_param("config.file_path", None)

        if conn and USE_DB:
            self.engine = db.create_engine(conn)
        elif self.grep_path and self.file_path:
            pass
        else:
            self.error("No valid configuration found")

    def summary(self, raw):
        taxonomies = []
        if raw["found"]:
            taxonomies.append(self.build_taxonomy("safe", "NSRL", "lookup", "found"))
        else:
            taxonomies.append(self.build_taxonomy("info", "NSRL", "lookup", "not found"))
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        data = self.get_param("data", None, "Data is missing")
        data = data.upper()

        if self.data_type != "hash":
            self.error("Invalid data type")

        md5_re = re.compile(r"^[a-f0-9]{32}(:.+)?$", re.IGNORECASE)
        sha1_re = re.compile(r"^[a-f0-9]{40}(:.+)?$", re.IGNORECASE)

        if md5_re.match(data):
            variable = "md5"
        elif sha1_re.match(data):
            variable = "sha1"
        else:
            self.error("Invalid hash type")

        results = {}
        if not self.engine:
            if not os.path.exists(self.file_path):
                self.error("NSRL file not found")
            try:
                output = subprocess.check_output(
                    [self.grep_path, "-m1", data, self.file_path]
                )
                values = [x.replace('"', "") for x in output.decode().strip().split(",")]
                for key, value in zip(FIELDS, values):
                    results[key] = value
                results["found"] = True
            except subprocess.CalledProcessError as e:
                results["found"] = False
            results["mode"] = "file"

        else:
            sql = "SELECT %s FROM nsrl WHERE %s='%s'" % (
                ", ".join(FIELDS),
                variable,
                data,
            )
            values = self.engine.execute(sql).fetchone()
            self.engine.dispose()
            if values:
                for key, value in zip(FIELDS, values[1:]):
                    results[key] = value
                results["found"] = True
            else:
                results["found"] = False
            results["mode"] = "db"

        self.report(results)


if __name__ == "__main__":
    NsrlAnalyzer().run()
