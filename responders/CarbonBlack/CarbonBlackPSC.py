#!/usr/bin/env python3
# encoding: utf-8

import requests
from cortexutils.responder import Responder


class CarbonBlackPSC(Responder):
    def __init__(self):
        Responder.__init__(self)

        self.service = self.get_param("config.service", None, "Service is Missing")

        
        self.cburl = self.get_param("config.url", None, "Carbon Black URL is Missing")
        self.api_token = self.get_param("config.api_token", None, "Carbon Black API token is Missing")
        self.ssl_verify = self.get_param("config.ssl_verify", None, "Carbon Black API token is Missing")
        

        if(self.cburl and self.api_token):
            self.cb = CbEnterpriseResponseAPI(url=self.cburl, token=self.api_token, ssl_verify=(not args.no_ssl_verify))
        else:
            self.cb = CbEnterpriseResponseAPI(profile=self.profile)

    def run(self):
        Responder.run(self)

        dataType = self.get_param("data.dataType", None, "title is missing")

        if dataType is not "thehive:case_artifact"
            self.error("Invalid dataType")

        # 1/ find the process by the right criteria = hash, executable_path: 
        # ```
        # cb.select(Process).where("process_name:XXXXXXXX") // Tokenized file path of the process’ main module
        # cb.select(Process).where("process_hash:XXXXXXXX") // MD5 and SHA-256 hashes of parent process’ main module
        # cb.select(Process).where("hash:XXXXXXXX") // Aggregate set of all MD5 and SHA-256 hashes associated with the process (process_hash, childproc_hash, crossproc_hash, filemod_hash and hash of the modload event) - useful for searching by hash
        # ````
        #
        # 2/ 
        
        self.report({
            message: "work in progress"
        })

    def operations(self):
        if self.service == "block"
            return [self.build_operation("AddTagToArtifact", tag="CBPSC:blocked")]

        # Improvement: 
        # - remove the tag if the "unblock" responder is called
        # - add an "unblocked" tag to the observable

if __name__ == "__main__":
    CarbonBlackPSC().run()
