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
        self.nsrl_folder = self.get_param("config.nsrl_folder", None)

        if conn and USE_DB:
            self.engine = db.create_engine(conn)
        elif self.grep_path and self.nsrl_folder:
            pass
        else:
            self.error("No valid configuration found")

    def summary(self, raw):
        taxonomies = []
        if raw["found"]:
            taxonomies.append(self.build_taxonomy("safe", "NSRL", "lookup", "found"))
        else:
            taxonomies.append(
                self.build_taxonomy("info", "NSRL", "lookup", "not found")
            )
        return {"taxonomies": taxonomies}

    def run(self):
        Analyzer.run(self)

        data = self.get_param("data", None, "Data is missing")
        data = data.upper()

        if self.data_type not in ['filename', "hash"]:
            self.error("Invalid data type")

        if self.data_type == 'hash':

            md5_re = re.compile(r"^[a-f0-9]{32}(:.+)?$", re.IGNORECASE)
            sha1_re = re.compile(r"^[a-f0-9]{40}(:.+)?$", re.IGNORECASE)

            if md5_re.match(data):
                variable = "md5"
            elif sha1_re.match(data):
                variable = "sha1"
            else:
                self.error("Invalid hash type")

        else:
            variable = "filename"

        results = {}
        results["records"] = []
        if not self.engine:
            if not os.path.exists(self.nsrl_folder) and not os.path.isdir(
                self.nsrl_folder
            ):
                self.error("NSRL folder not found or not valid")
            try:
                output = subprocess.Popen(
                    [self.grep_path, "-r", "-i", data, self.nsrl_folder],
                    stdout=subprocess.PIPE,
                    universal_newlines=True,
                )
                for line in output.stdout.readlines():
                    tmp = {}
                    file_path, values = line.strip().split(":")
                    values = [
                        x.replace('"', "") for x in values.split(",")
                    ]
                    for key, value in zip(FIELDS, values):
                        tmp[key] = value
                    tmp["dbname"], tmp["release"] = (
                        file_path.split("/")[-1].replace(".txt", "").split("_")
                    )
                    results["records"].append(tmp)
                results["found"] = True
            except subprocess.CalledProcessError as e:
                results["found"] = False
            results["mode"] = "file"

        else:
            if variable != 'filename':
                sql = "SELECT %s FROM nsrl WHERE %s='%s'" % (
                    ", ".join(FIELDS + ["dbname", "release"]),
                    variable,
                    data
                )
            else:
                sql = "SELECT %s FROM nsrl WHERE %s ilike '%s'" % (
                    ", ".join(FIELDS + ["dbname", "release"]),
                    variable,
                    "%%{}%%".format(data)
                )
            values = self.engine.execute(sql)
            self.engine.dispose()
            if values.rowcount > 0:
                for row in values:
                    results["records"].append(
                        {
                            key: value
                            for (key, value) in zip(FIELDS + ["dbname", "release"], row)
                        }
                    )
                results["found"] = True
            else:
                results["found"] = False
            results["mode"] = "db"

        self.report(results)


if __name__ == "__main__":
    NsrlAnalyzer().run()
