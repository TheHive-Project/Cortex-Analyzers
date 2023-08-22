#!/usr/bin/env python3
from cortexutils.analyzer import Analyzer
from vmrayclient import VMRayClient
from time import sleep


class VMRayAnalyzer(Analyzer):
    """
    VMRay analyzer that uses VMRayClient to connect to an VMRay instance. Allows uploading a sample and getting
    information bac via submission data. More info regarding configuration in the complete documentation.
    """

    _namespace = "VMRay"

    _severity_mapping = {
        "clean": "safe",
        "whitelisted": "safe",
        "suspicious": "suspicious",
        "malicious": "malicious",
        "blacklisted": "malicious",
    }

    _ioc_mapping = {
        "domains": ("domain", "domain"),
        "email_addresses": ("email", "mail"),
        "emails": ("sender", "mail"),
        "files": ("filename", "filename"),
        "ips": ("ip_address", "ip"),
        "mutexes": ("mutex_name", "other"),
        "registry": ("reg_key_name", "registry"),
        "urls": ("url", "url"),
    }

    def __init__(self):
        Analyzer.__init__(self)
        self.reanalyze = self.get_param("config.reanalyze", True)
        self.verdict_only = self.get_param("config.verdict_only", False)
        self.shareable = self.get_param("config.shareable", False)
        self.tags = self.get_param("config.tags", ["TheHive"])
        self.user_config = {
            "timeout": self.get_param("config.timeout", None),
            "net_scheme_name": self.get_param("config.net_scheme_name", None),
        }

        self.query_retry_wait = self.get_param("config.query_retry_wait", 10)
        self.recursive_sample_limit = self.get_param(
            "config.recursive_sample_limit", 10
        )

        verify = self.get_param("config.certverify", True)
        certpath = self.get_param("config.certpath", None)
        if verify and certpath:
            verify = certpath

        archive_compound_sample = self.get_param(
            "config.archive_compound_sample", False
        )
        if archive_compound_sample:
            archive_action = "compound_sample"
        else:
            archive_action = "separate_samples"

        self.vmrc = VMRayClient(
            url=self.get_param("config.url", None, "No VMRay URL given.").rstrip("/ "),
            key=self.get_param("config.key", None, "No VMRay API key given."),
            reanalyze=self.reanalyze,
            verify=verify,
            archive_password=self.get_param("config.archive_password", "malware"),
            archive_action=archive_action,
            max_jobs=self.get_param("config.max_jobs", None),
            enable_reputation=self.get_param("config.enable_reputation", None),
            enable_whois=self.get_param("config.enable_whois", None),
            analyzer_mode=self.get_param("config.analyzer_mode", None),
            known_malicious=self.get_param("config.known_malicious", None),
            known_benign=self.get_param("config.known_benign", None),
        )

    def _build_sample_node(self, sample, current_recursion_level):
        sample_id = sample["sample_id"]
        sample["sample_analyses"] = self.vmrc.get_sample_analyses(sample_id)
        sample["sample_threat_indicators"] = self.vmrc.get_sample_threat_indicators(
            sample_id
        )
        sample["sample_mitre_attack"] = self.vmrc.get_sample_mitre_attack(sample_id)
        sample["sample_iocs"] = self.vmrc.get_sample_iocs(sample_id)
        if self.recursive_sample_limit > current_recursion_level:
            sample["sample_child_samples"] = [
                self.vmrc.get_sample(child_sample_id)
                for child_sample_id in sample["sample_child_sample_ids"]
            ]
            for child_sample in sample["sample_child_samples"]:
                self._build_sample_node(child_sample, current_recursion_level + 1)

    def _build_report(self, submissions=None, samples=None):
        if not submissions and not samples:
            self.error(
                "Either submissions or samples must be provided in order to build a report"
            )
            return
        sample_ids = (
            [sample["sample_id"] for sample in samples]
            if samples
            else [submission["submission_sample_id"] for submission in submissions]
        )
        # note: the dictionary fetched in case the reanalysis is disabled is incomplete. we need to query the samples again in all cases
        samples = [self.vmrc.get_sample(sample_id) for sample_id in sample_ids]
        for sample in samples:
            self._build_sample_node(sample, 0)
        return {"samples": samples}

    def _wait_for_results(self, submission_result):
        # Ref: #332: check if job was submitted
        if not self.reanalyze:
            if len(submission_result["errors"]) > 0:
                # Sample has alredy been analyzed and reanalysis is turned off, get the reports
                self.report(self._build_report(samples=submission_result["samples"]))
                return  # stop waiting for report, because we already have it

        running_submissions = submission_result["submissions"]
        finished_submissions = []
        while len(running_submissions) != len(finished_submissions):
            finished_submissions.extend(
                [
                    updated_submission
                    for updated_submission in (
                        self.vmrc.update_submission(current_submission["submission_id"])
                        for current_submission in running_submissions
                    )
                    if "submission_finished" in updated_submission
                    and updated_submission["submission_finished"]
                ]
            )
            sleep(self.query_retry_wait)

        # Return the results
        self.report(self._build_report(submissions=finished_submissions))

    def run(self):
        if self.data_type == "hash":
            # don't run anything, try to build a report using existing results instead
            samples = self.vmrc.get_samples_by_hash(self.get_data())
            if samples:
                self.report(self._build_report(samples=samples))
            else:
                self.report({"samples": samples})
        elif self.data_type == "file":
            shareable = self.shareable and self.get_param("tlp") in (0, 1)
            self._wait_for_results(
                self.vmrc.submit_file_sample(
                    file_path=self.get_param("file"),
                    file_name=self.get_param("filename"),
                    tags=self.tags,
                    shareable=shareable,
                    user_config=self.user_config,
                )
            )
        elif self.data_type == "url":
            shareable = self.shareable and self.get_param("tlp") in (0, 1)
            self._wait_for_results(
                self.vmrc.submit_url_sample(
                    url_sample=self.get_data(),
                    tags=self.tags,
                    shareable=shareable,
                    user_config=self.user_config,
                )
            )
        else:
            self.error("Data type currently not supported")

    def _taxonomies_for_samples(self, samples):
        taxonomies = []
        for sample in samples:
            has_verdict = "sample_verdict" in sample
            level = (
                self._severity_mapping.get(sample["sample_verdict"], "info")
                if has_verdict
                else self._severity_mapping.get(sample["sample_severity"], "info")
            )
            value = "{}".format(
                sample["sample_verdict"] if has_verdict else sample["sample_score"]
            )
            if len(samples) > 1:
                value += " (from sample {})".format(sample["sample_id"])
            taxonomies.append(
                self.build_taxonomy(level, self._namespace, "Verdict", value)
                if has_verdict
                else self.build_taxonomy(level, self._namespace, "Score", value)
            )

            if not self.verdict_only:
                for threat_indicator in sample.get("sample_threat_indicators", {}).get(
                    "threat_indicators", []
                ):
                    predicate = threat_indicator.get("category", None)
                    value = threat_indicator.get("operation", "")
                    if predicate:
                        taxonomies.append(
                            self.build_taxonomy(
                                level, self._namespace, predicate, value
                            )
                        )

                for mitre_technique in sample.get("sample_mitre_attack", {}).get(
                    "mitre_attack_techniques", []
                ):
                    predicate = mitre_technique.get("technique_id", None)
                    value = mitre_technique.get("technique", "Unknown MITRE technique")
                    if "tactics" in mitre_technique:
                        value += " using tactics: {}".format(
                            ", ".join(mitre_technique["tactics"])
                        )
                    if predicate:
                        taxonomies.append(
                            self.build_taxonomy(
                                level, self._namespace, predicate, value
                            )
                        )

                # add child sample taxonomies if they have been added
                taxonomies.extend(
                    self._taxonomies_for_samples(sample.get("sample_child_samples", []))
                )
        return taxonomies

    def _sandbox_reports_for_samples(self, samples):
        sandbox = "vmray"
        sandbox_type = "on-premise"
        sandbox_reports = []
        for sample in samples:
            permalink = sample.get("sample_webif_url", None)
            score = sample.get("sample_vti_score", 0)
            sandbox_report = {
                "permalink": permalink,
                "score": score,
                "sandbox-type": sandbox_type,
                "{}-sandbox".format(sandbox_type): sandbox,
            }
            sandbox_reports.append(sandbox_report)

            # add child sample taxonomies if they have been added
            sandbox_reports.extend(
                self._sandbox_reports_for_samples(
                    sample.get("sample_child_samples", [])
                )
            )
        return sandbox_reports

    def summary(self, raw):
        taxonomies = []
        sandbox_reports = []
        samples = raw.get("samples", [])
        if len(samples) == 0:
            taxonomies.append(
                self.build_taxonomy("info", self._namespace, "None", "No Scan")
            )
        else:
            taxonomies.extend(self._taxonomies_for_samples(samples))
            sandbox_reports.extend(self._sandbox_reports_for_samples(samples))
        return {"taxonomies": taxonomies, "sandbox-reports": sandbox_reports}

    def _artifacts_for_samples(self, samples):
        artifacts = []
        for sample in samples:
            link = sample.get("sample_webif_url", None)
            iocs = sample.get("sample_iocs", {}).get("iocs", {})

            for (
                ioc_type,
                (ioc_payload_name, ioc_data_type),
            ) in self._ioc_mapping.items():
                if ioc_type in iocs:
                    for ioc_node in iocs[ioc_type]:
                        severity = ioc_node.get("severity", "unknown")
                        level = self._severity_mapping.get(severity, "info")
                        tags = list(set((severity, level, ioc_node["type"])))
                        payload = ioc_node[ioc_payload_name]

                        context_tags = []
                        if "hashes" in ioc_node:
                            for hash_node in ioc_node["hashes"]:
                                if "sha256_hash" in hash_node:
                                    hash_value = hash_node["sha256_hash"]
                                    context_tags.append("sha256:{}".format(hash_value))
                                    artifacts.append(
                                        self.build_artifact(
                                            "hash", hash_value, message=link, tags=tags
                                        )
                                    )
                        elif "operations" in ioc_node:
                            for operation in ioc_node["operations"]:
                                context_tags.append("operation:{}".format(operation))

                        tags.extend(set(context_tags))
                        artifacts.append(
                            self.build_artifact(
                                ioc_data_type, payload, message=link, tags=tags
                            )
                        )

            # add child samples if they have been added
            artifacts.extend(
                self._artifacts_for_samples(sample.get("sample_child_samples", []))
            )
        return artifacts

    def artifacts(self, raw):
        return self._artifacts_for_samples(raw.get("samples", []))


if __name__ == "__main__":
    VMRayAnalyzer().run()
