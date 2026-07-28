#!/usr/bin/env python3
# encoding: utf-8

import ipaddress
import time
from typing import Any, Dict, List, Optional

import requests
from cortexutils.analyzer import Analyzer


class ClusterHawkAnalyzer(Analyzer):
    def __init__(self):
        Analyzer.__init__(self)

        # Configuration
        self.api_key = self.get_param("config.api_key", None, "API key is required")
        self.base_url = self.get_param(
            "config.base_url", "https://clusterhawk.chawkr.com"
        )
        self.model_name = self.get_param(
            "config.model_name", None, "Model name is required"
        )
        self.check_quota = self.get_param("config.check_quota", True)
        self.timeout = self.get_param("config.timeout", 30)
        self.poll_interval = self.get_param("config.poll_interval", 10)
        self.job_name = self.get_param("config.job_name", "Cortex Analysis")

        # API headers
        self.headers = {"X-API-Key": self.api_key, "Content-Type": "application/json"}

        # Validate configuration
        if not self.api_key:
            self.error("API key is required")
        if not self.model_name:
            self.error("Model name is required")

    def check_concurrent_quota(self) -> bool:
        """Check if concurrent job quota allows new job submission"""
        if not self.check_quota:
            return True

        try:
            url = f"{self.base_url}/api/v1/public/quota/concurrent-jobs"
            response = requests.get(url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                quota_data = response.json()
                if quota_data.get("success"):
                    quota_info = quota_data["quota"]
                    can_submit = quota_info.get("can_submit", False)

                    self.info(
                        f"Quota check: {quota_info['current_usage']}/{quota_info['max_concurrent']} jobs used"
                    )
                    self.info(f"Available slots: {quota_info['available']}")

                    if not can_submit:
                        self.error(
                            f"Cannot submit job - concurrent quota limit reached. "
                            f"Current usage: {quota_info['current_usage']}/{quota_info['max_concurrent']}"
                        )
                        return False

                    return True
                else:
                    self.warning(
                        "Could not parse quota information, proceeding with submission"
                    )
                    return True
            else:
                self.warning(
                    f"Quota check failed with status {response.status_code}, proceeding with submission"
                )
                return True

        except Exception as e:
            self.warning(f"Quota check failed: {str(e)}, proceeding with submission")
            return True

    def submit_prediction_job(self, ip_addresses: List[str]) -> Optional[str]:
        """Submit a prediction job to ClusterHawk API"""
        try:
            url = f"{self.base_url}/api/v1/public/predict"

            payload = {
                "model_name": self.model_name,
                "ip_addresses": ip_addresses,
                "job_name": f"{self.job_name} - {int(time.time())}",
            }

            self.info(
                f"Submitting prediction job for {len(ip_addresses)} IP addresses using model '{self.model_name}'"
            )

            response = requests.post(
                url, headers=self.headers, json=payload, timeout=30
            )

            if response.status_code in (200, 202):
                result = response.json()
                if result.get("success"):
                    job_id = result.get("job_id") or result.get("data", {}).get(
                        "job_id"
                    )
                    self.info(f"Prediction job submitted successfully: {job_id}")
                    return job_id
                else:
                    self.error(
                        f"Prediction job submission failed: {result.get('message', 'Unknown error')}"
                    )
                    return None
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get("error", {}).get(
                        "message", f"HTTP {response.status_code}"
                    )
                except (ValueError, KeyError, AttributeError):
                    error_msg = f"HTTP {response.status_code}: {response.text}"

                self.error(f"Prediction job submission failed: {error_msg}")
                return None

        except Exception as e:
            self.error(f"Failed to submit prediction job: {str(e)}")
            return None

    def monitor_job_status(self, job_id: str) -> bool:
        """Monitor job status until completion"""
        start_time = time.time()
        max_wait = self.timeout * 60

        self.info(f"Monitoring job {job_id} (timeout: {self.timeout}m)")

        while time.time() - start_time < max_wait:
            try:
                url = f"{self.base_url}/api/v1/public/jobs/{job_id}/status"
                response = requests.get(url, headers=self.headers, timeout=30)

                if response.status_code == 200:
                    status_data = response.json()

                    if isinstance(status_data, dict) and isinstance(
                        status_data.get("data"), dict
                    ):
                        status_data = status_data["data"]

                    if isinstance(status_data, dict):
                        status = status_data.get("status", "unknown").lower()
                        progress = status_data.get("progress", 0) or 0
                    else:
                        status = str(status_data).lower()
                        progress = 0

                    self.info(f"Job status: {status} (progress: {progress:.1f}%)")

                    if status == "completed":
                        self.info("Job completed successfully")
                        return True
                    elif status == "failed":
                        error_msg = (
                            status_data.get("error_message", "Unknown error")
                            if isinstance(status_data, dict)
                            else "Job failed"
                        )
                        self.error(f"Job failed: {error_msg}")
                        return False
                    elif status in ["running", "pending", "processing"]:
                        # Job still processing, wait and check again
                        time.sleep(self.poll_interval)
                    else:
                        self.warning(f"Unknown job status: {status}")
                        time.sleep(self.poll_interval)
                else:
                    self.warning(
                        f"Status check failed with status {response.status_code}"
                    )
                    time.sleep(self.poll_interval)

            except Exception as e:
                self.warning(f"Status check failed: {str(e)}")
                time.sleep(self.poll_interval)

        self.error(f"Job monitoring timed out after {max_wait} seconds")
        return False

    def get_job_results(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Get results from completed job"""
        try:
            url = f"{self.base_url}/api/v1/public/jobs/{job_id}/results"
            response = requests.get(url, headers=self.headers, timeout=30)

            if response.status_code == 200:
                results = response.json()
                if results.get("success"):
                    self.info("Job results retrieved successfully")
                    return results
                else:
                    self.error("Failed to retrieve job results")
                    return None
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get("error", {}).get(
                        "message", f"HTTP {response.status_code}"
                    )
                except (ValueError, KeyError, AttributeError):
                    error_msg = f"HTTP {response.status_code}: {response.text}"

                self.error(f"Failed to get job results: {error_msg}")
                return None

        except Exception as e:
            self.error(f"Failed to retrieve job results: {str(e)}")
            return None

    def process_prediction_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Process and format prediction results for Cortex"""
        try:
            prediction_data = results.get("results", {}).get("prediction", {})
            predictions = prediction_data.get("predictions", [])

            if not predictions:
                return {
                    "summary": "No predictions available",
                    "predictions": [],
                    "total_analyzed": 0,
                }

            has_cluster_descriptions = any(
                "primary_characteristic" in pred and "key_indicators" in pred
                for pred in predictions
            )

            kind_distribution: Dict[str, int] = {
                "confident_match": 0,
                "ambiguous_diffuse": 0,
                "ambiguous_split": 0,
                "out_of_distribution": 0,
                "unknown": 0,
            }

            processed_predictions: List[Dict[str, Any]] = []
            cluster_summary: Dict[str, Dict[str, Any]] = {}

            for pred in predictions:
                ip = pred.get("ip", "unknown")
                cluster = pred.get("predicted_cluster")
                confidence = pred.get("confidence")
                kind = pred.get("kind") or "unknown"
                top1_minus_top2 = pred.get("top1_minus_top2")
                effective_n = pred.get("effective_n")
                candidates = pred.get("candidates") or []
                label = pred.get("label")
                is_ood = cluster is None or kind == "out_of_distribution"
                is_noise = not is_ood and cluster == -1
                cluster_key = "Out of distribution" if is_ood else f"Cluster {cluster}"

                if cluster_key not in cluster_summary:
                    cluster_info: Dict[str, Any] = {
                        "count": 0,
                        "_confidence_sum": 0.0,
                        "_confidence_count": 0,
                        "avg_confidence": 0.0,
                        "ips": [],
                        "is_ood": is_ood,
                        "is_noise": is_noise,
                    }

                    if "primary_characteristic" in pred:
                        cluster_info["description"] = pred.get(
                            "primary_characteristic", ""
                        )
                        cluster_info["indicators"] = pred.get("key_indicators", "")

                    cluster_summary[cluster_key] = cluster_info

                bucket = cluster_summary[cluster_key]
                bucket["count"] += 1
                bucket["ips"].append(ip)
                if isinstance(confidence, (int, float)):
                    bucket["_confidence_sum"] += float(confidence)
                    bucket["_confidence_count"] += 1

                if kind in kind_distribution:
                    kind_distribution[kind] += 1
                else:
                    kind_distribution["unknown"] += 1

                processed_pred: Dict[str, Any] = {
                    "ip": ip,
                    "cluster": cluster,
                    "confidence": (
                        round(float(confidence), 3)
                        if isinstance(confidence, (int, float))
                        else None
                    ),
                    "kind": kind,
                    "top1_minus_top2": (
                        round(float(top1_minus_top2), 3)
                        if isinstance(top1_minus_top2, (int, float))
                        else None
                    ),
                    "effective_n": (
                        round(float(effective_n), 2)
                        if isinstance(effective_n, (int, float))
                        else None
                    ),
                    "candidates": [
                        {
                            "cluster_id": c.get("cluster_id"),
                            "confidence": round(float(c.get("confidence", 0.0)), 3),
                        }
                        for c in candidates
                        if isinstance(c, dict)
                    ],
                }
                if label is not None:
                    processed_pred["label"] = label
                if "primary_characteristic" in pred:
                    processed_pred["cluster_description"] = pred.get(
                        "primary_characteristic", ""
                    )
                    processed_pred["cluster_indicators"] = pred.get(
                        "key_indicators", ""
                    )

                expl_status = pred.get("explanation_status")
                if expl_status:
                    processed_pred["explanation_status"] = str(expl_status)
                explanation = pred.get("explanation")
                if explanation:
                    processed_pred["explanation"] = explanation

                processed_predictions.append(processed_pred)

            for bucket in cluster_summary.values():
                conf_count = bucket.pop("_confidence_count", 0)
                conf_sum = bucket.pop("_confidence_sum", 0.0)
                bucket["avg_confidence"] = (
                    round(conf_sum / conf_count, 3) if conf_count else None
                )

            kind_distribution = {k: v for k, v in kind_distribution.items() if v > 0}

            result = {
                "summary": {
                    "total_analyzed": len(predictions),
                    "clusters_found": sum(
                        1
                        for v in cluster_summary.values()
                        if not v["is_ood"] and not v["is_noise"]
                    ),
                    "model_used": self.model_name,
                    "job_id": results.get("job_id", "unknown"),
                    "has_cluster_descriptions": has_cluster_descriptions,
                    "has_explanations": any(
                        "explanation" in p for p in processed_predictions
                    ),
                    "is_prebuilt_model": bool(
                        results.get("results", {})
                        .get("model_info", {})
                        .get("is_prebuilt")
                    ),
                    "kind_distribution": kind_distribution,
                },
                "cluster_summary": cluster_summary,
                "predictions": processed_predictions,
                "raw_results": prediction_data,
            }

            result["taxonomies"] = self._create_taxonomies(result)

            return result

        except Exception as e:
            self.error(f"Failed to process prediction results: {str(e)}")
            return {
                "summary": "Error processing results",
                "error": str(e),
                "predictions": [],
            }

    _KIND_TO_LEVEL = {
        "confident_match": "malicious",
        "ambiguous_split": "suspicious",
        "ambiguous_diffuse": "suspicious",
        "out_of_distribution": "info",
    }

    def _create_taxonomies(self, processed: Dict[str, Any]):
        tx = []
        preds = processed.get("predictions") or []
        if not preds:
            return tx

        for p in preds:
            kind = p.get("kind") or "unknown"
            level = self._KIND_TO_LEVEL.get(kind, "info")
            cluster = p.get("cluster")
            confidence = p.get("confidence")

            if cluster is not None:
                if kind == "confident_match":
                    predicate = "Cluster"
                else:
                    predicate = f"Cluster ({kind.replace('_', ' ')})"
                if isinstance(confidence, (int, float)):
                    value = f"{cluster} ({float(confidence):.2f})"
                else:
                    value = str(cluster)
            else:
                predicate = "Kind"
                value = kind.replace("_", " ")

            tx.append(
                {
                    "namespace": "Clusterhawk",
                    "predicate": predicate,
                    "value": value,
                    "level": level,
                }
            )
        return tx

    def summary(self, report):
        """
        Provide taxonomies for the Cortex tile.
        """
        taxonomies = report.get("taxonomies")
        if not taxonomies:
            taxonomies = self._create_taxonomies(report or {})
        return {"taxonomies": taxonomies}

    def run(self):
        """
        Main execution method
        """
        try:
            ip_address = self.get_data()

            if not ip_address:
                self.error("No IP address provided")
                return

            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                self.error(f"Invalid IP address format: {ip_address}")
                return

            # Check quota if enabled
            if not self.check_concurrent_quota():
                self.error("Concurrent job quota exceeded")
                return

            # Submit prediction job
            job_id = self.submit_prediction_job([ip_address])
            if not job_id:
                self.error("Failed to submit prediction job")
                return

            # Monitor job completion
            if not self.monitor_job_status(job_id):
                self.error("Job monitoring failed or timed out")
                return

            # Get results
            results = self.get_job_results(job_id)
            if not results:
                self.error("Failed to retrieve job results")
                return

            # Process and return results
            processed_results = self.process_prediction_results(results)
            self.report(processed_results)

        except Exception as e:
            self.error(f"Analysis failed: {str(e)}")


if __name__ == "__main__":
    ClusterHawkAnalyzer().run()
