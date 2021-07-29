#!/usr/bin/env python3
# encoding: utf-8

from cortexutils.responder import Responder
import requests
import os
import magic
import tempfile
import mimetypes
import filetype
from thehive4py.api import TheHiveApi
from thehive4py.models import Case, CaseObservable


class VirustotalDownloader(Responder):
    def __init__(self):
        Responder.__init__(self)
        self.virustotal_apikey = self.get_param(
            "config.virustotal_apikey", None, "Virustotal API key missing!"
        )
        self.thehive_url = self.get_param(
            "config.thehive_url", None, "TheHive URL missing!"
        )
        self.thehive_apikey = self.get_param(
            "config.thehive_apikey", None, "TheHive API key missing!"
        )

    def run(self):
        Responder.run(self)

        data_type = self.get_param("data.dataType")
        case_id = self.get_param("data.case._id")
        ioc_types = ["hash"]

        if data_type in ioc_types:
            url = "https://www.virustotal.com/vtapi/v2/file/download"
            params = {
                "apikey": self.virustotal_apikey,
                "hash": self.get_param("data.data"),
            }

            response = requests.get(url, params=params)

            if response.status_code == 200:
                filename = ""
                downloaded_file = response.content

                tempdir = tempfile.gettempdir()
                f = open(tempdir + "/" + self.get_param("data.data"), "wb")
                f.write(downloaded_file)
                f.close()
                filename = f.name

                kind = filetype.guess(f.name)

                api = TheHiveApi(self.thehive_url, self.thehive_apikey)

                if kind and kind.extension != None:
                    os.rename(f.name, f.name + "." + kind.extension)
                    filename = f.name + "." + kind.extension

                    file_observable = CaseObservable(
                        dataType="file",
                        data=[filename],
                        tlp=self.get_param("data.tlp"),
                        ioc=True,
                        tags=[
                            "src:VirusTotal",
                            str(kind.mime),
                            str(kind.extension),
                            "parent:" + self.get_param("data.data"),
                        ],
                        message="",
                    )
                else:
                    file_observable = CaseObservable(
                        dataType="file",
                        data=[f.name],
                        tlp=self.get_param("data.tlp"),
                        ioc=True,
                        tags=[
                            "src:VirusTotal",
                            "parent:" + self.get_param("data.data"),
                        ],
                        message="",
                    )

                response = api.create_case_observable(case_id, file_observable)

                self.report(
                    {"message": str(response.status_code) + " " + response.text}
                )
            else:
                self.report(
                    {
                        "message": "Virustotal returned the following error code: "
                        + str(response.status_code)
                        + ". If you receive 403 this means that you are using a public API key but this responder needs a private Virustotal API key!"
                    }
                )
        else:
            self.error('Incorrect dataType. "Hash" expected.')

    def operations(self, raw):
        return [self.build_operation("AddTagToArtifact", tag="Virustotal:Downloaded")]


if __name__ == "__main__":
    VirustotalDownloader().run()
