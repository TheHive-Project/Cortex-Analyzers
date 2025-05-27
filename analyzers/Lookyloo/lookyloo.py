#!/usr/bin/env python3

# Author: THA-CERT //PVA
# Lookyloo documentation: https://pylookyloo.readthedocs.io/en/latest/

from pylookyloo import Lookyloo as LK
from cortexutils.analyzer import Analyzer
from urllib.parse import urlparse
from io import BytesIO
from time import sleep
from base64 import b64encode
from datetime import datetime

class Lookyloo(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)
        self.lookyloo_instance = self.get_param("config.Lookyloo_instance", "https://lookyloo.circl.lu/") # By default, it will query the public instance of Lookyloo
        self.timeout = self.get_param("config.Capture_timeout", 120) # Default timeout set at 120s

        # The proxy will be automatically setup by Cortex
        self.lookyloo = LK(self.lookyloo_instance)

        if not self.lookyloo.is_up:  # to make sure it is up and reachable
            self.error("Lookyloo is not reachable or not up. Exit")

    def summary(self, raw):
        taxonomies = []
        level = "info" # Put the report in blue
        namespace = "Lookyloo"
        predicate = ""
        value = ""

        if (len(raw["redirections"]) > 0):
            if (len(raw["screenshot"]) > 0):
                level = "safe" # Put the report in green
                predicate = "Screenshot"
                value = "OK"
            else:
                predicate = "Domain"
                value = "resolved"
        else:
            predicate = "Domain"
            value = "not resolved"

        taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))
        return {"taxonomies": taxonomies}

    def artifacts(self, raw):
        artifacts = []

        for url in raw["redirections"]:
            artifacts.append(self.build_artifact("url", url))

            domain = urlparse(url).netloc
            artifacts.append(self.build_artifact("domain", domain))
        return artifacts

    def run(self):
        Analyzer.run(self)
        url = self.get_param("data", None, "Data is missing")

        date = datetime.now().strftime("%d/%m/%Y, %H:%M:%S UTC")

        uuid = self.submit(url)
        self.wait_result(uuid)

        screen = self.get_screenshot(uuid)

        redirects = self.get_redirects(uuid)
        redirects = redirects["response"]["redirects"]

        screen_b64 = b64encode(screen.getvalue())
        screen_b64 = screen_b64.decode("utf-8")

        lk_report_url = self.get_url(uuid)
        status_report = ""

        if (len(redirects) > 0):
            if (len(screen_b64) > 0):
                status_report = "Capture done"
            else:
                status_report = "Domain resolved"
        else:
            status_report = "Domain not resolved"

        report_dict = {"submitted_url": url, "redirections": redirects, "url": lk_report_url, "submission_date": date,"status": status_report, "screenshot": screen_b64}
        self.report(report_dict)

    def submit(self, site):
        print("Submitting the url " + site + " to Lookyloo")
        # parameter listing: If False, the capture will be not be on the publicly accessible index page of lookyloo
        # parameter quiet: Returns the UUID only, instead of the whole URL
        return self.lookyloo.submit(url=site, listing=False, quiet=True)

    # Query Lookyloo each seconds to get status. If status is 1 (capture OK), then return.
    # If timeout of 120s is exceeded, return the status code
    def wait_result(self, uuid):
        timer = 0
        status = 0
        print("Waiting results (timeout set at " + str(self.timeout) + "s)", end="", flush=True)
        while(timer < self.timeout and status != 1):
            print(".", end="", flush=True)
            status = self.lookyloo.get_status(uuid)
            status = status["status_code"]
            timer += 1
            sleep(1)
        if(status == 1): # if it get results
            print("\nCapture done in " + str(timer) + "s")
        else:
            print("\nTimeout exceeded after " + str(self.timeout) + "s, results are not ready")
        return status

    def get_screenshot(self, uuid):
        screen = self.lookyloo.get_screenshot(uuid)
        return screen

    def get_redirects(self, uuid):
        redirects = self.lookyloo.get_redirects(uuid)
        return redirects

    # return the URL of the lookyloo capture web interface.
    def get_url(self, uuid):
        url = ""
        if (self.lookyloo_instance[-1] == '/'):
            url = self.lookyloo_instance + "tree/" + uuid
        else:
            url = self.lookyloo_instance + "/tree/" + uuid
        return url

if __name__ == "__main__":
    Lookyloo().run()
