#!/usr/bin/env python3
# encoding: utf-8

import ipaddress
import requests
import time
from typing import Dict, List, Optional, Any
from cortexutils.analyzer import Analyzer

class ClusterHawkAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)
        
        # Configuration
        self.api_key = self.get_param('config.api_key', None, 'API key is required')
        self.base_url = self.get_param('config.base_url', 'https://clusterhawk.chawkr.com')
        self.model_name = self.get_param('config.model_name', None, 'Model name is required')
        self.check_quota = self.get_param('config.check_quota', True)
        self.timeout = self.get_param('config.timeout', 30)
        self.poll_interval = self.get_param('config.poll_interval', 10)
        self.job_name = self.get_param('config.job_name', 'Cortex Analysis')
        
        # API headers
        self.headers = {
            'X-API-Key': self.api_key,
            'Content-Type': 'application/json'
        }
        
        # Validate configuration
        if not self.api_key:
            self.error('API key is required')
        if not self.model_name:
            self.error('Model name is required')

    def check_concurrent_quota(self) -> bool:
        """
        Check if concurrent job quota allows new job submission
        
        Returns:
            bool: True if quota allows submission, False otherwise
        """
        if not self.check_quota:
            return True
            
        try:
            url = f"{self.base_url}/api/v1/public/quota/concurrent-jobs"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                quota_data = response.json()
                if quota_data.get('success'):
                    quota_info = quota_data['quota']
                    can_submit = quota_info.get('can_submit', False)
                    
                    self.info(f"Quota check: {quota_info['current_usage']}/{quota_info['max_concurrent']} jobs used")
                    self.info(f"Available slots: {quota_info['available']}")
                    
                    if not can_submit:
                        self.error(f"Cannot submit job - concurrent quota limit reached. "
                                 f"Current usage: {quota_info['current_usage']}/{quota_info['max_concurrent']}")
                        return False
                    
                    return True
                else:
                    self.warning("Could not parse quota information, proceeding with submission")
                    return True
            else:
                self.warning(f"Quota check failed with status {response.status_code}, proceeding with submission")
                return True
                
        except Exception as e:
            self.warning(f"Quota check failed: {str(e)}, proceeding with submission")
            return True

    def submit_prediction_job(self, ip_addresses: List[str]) -> Optional[str]:
        """
        Submit a prediction job to ClusterHawk API
        
        Args:
            ip_addresses: List of IP addresses to analyze
            
        Returns:
            str: Job ID if successful, None otherwise
        """
        try:
            url = f"{self.base_url}/api/v1/public/predict"
            
            payload = {
                "model_name": self.model_name,
                "ip_addresses": ip_addresses,
                "job_name": f"{self.job_name} - {int(time.time())}"
            }
            
            self.info(f"Submitting prediction job for {len(ip_addresses)} IP addresses using model '{self.model_name}'")
            
            response = requests.post(url, headers=self.headers, json=payload, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                if result.get('success'):
                    job_id = result.get('job_id')
                    self.info(f"Prediction job submitted successfully: {job_id}")
                    return job_id
                else:
                    self.error(f"Prediction job submission failed: {result.get('message', 'Unknown error')}")
                    return None
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', {}).get('message', f'HTTP {response.status_code}')
                except:
                    error_msg = f'HTTP {response.status_code}: {response.text}'
                
                self.error(f"Prediction job submission failed: {error_msg}")
                return None
                
        except Exception as e:
            self.error(f"Failed to submit prediction job: {str(e)}")
            return None

    def monitor_job_status(self, job_id: str) -> bool:
        """
        Monitor job status until completion
        
        Args:
            job_id: Job ID to monitor
            
        Returns:
            bool: True if job completed successfully, False otherwise
        """
        start_time = time.time()
        max_wait = self.timeout*60
        
        self.info(f"Monitoring job {job_id} (timeout: {max_wait}m)")
        
        while time.time() - start_time < max_wait:
            try:
                url = f"{self.base_url}/api/v1/public/jobs/{job_id}/status"
                response = requests.get(url, headers=self.headers, timeout=30)
                
                if response.status_code == 200:
                    status_data = response.json()
                    
                    if isinstance(status_data, dict):
                        status = status_data.get('status', 'unknown').lower()
                        progress = status_data.get('progress', 0)
                    else:
                        status = str(status_data).lower()
                        progress = 0
                    
                    self.info(f"Job status: {status} (progress: {progress:.1f}%)")
                    
                    if status == 'completed':
                        self.info("Job completed successfully")
                        return True
                    elif status == 'failed':
                        error_msg = status_data.get('error_message', 'Unknown error') if isinstance(status_data, dict) else 'Job failed'
                        self.error(f"Job failed: {error_msg}")
                        return False
                    elif status in ['running', 'pending', 'processing']:
                        # Job still processing, wait and check again
                        time.sleep(self.poll_interval)
                    else:
                        self.warning(f"Unknown job status: {status}")
                        time.sleep(self.poll_interval)
                else:
                    self.warning(f"Status check failed with status {response.status_code}")
                    time.sleep(self.poll_interval)
                    
            except Exception as e:
                self.warning(f"Status check failed: {str(e)}")
                time.sleep(self.poll_interval)
        
        self.error(f"Job monitoring timed out after {max_wait} seconds")
        return False

    def get_job_results(self, job_id: str) -> Optional[Dict[str, Any]]:
        """
        Get results from completed job
        
        Args:
            job_id: Job ID to get results for
            
        Returns:
            Dict containing job results or None if failed
        """
        try:
            url = f"{self.base_url}/api/v1/public/jobs/{job_id}/results"
            response = requests.get(url, headers=self.headers, timeout=30)
            
            if response.status_code == 200:
                results = response.json()
                if results.get('success'):
                    self.info("Job results retrieved successfully")
                    return results
                else:
                    self.error("Failed to retrieve job results")
                    return None
            else:
                try:
                    error_data = response.json()
                    error_msg = error_data.get('error', {}).get('message', f'HTTP {response.status_code}')
                except:
                    error_msg = f'HTTP {response.status_code}: {response.text}'
                
                self.error(f"Failed to get job results: {error_msg}")
                return None
                
        except Exception as e:
            self.error(f"Failed to retrieve job results: {str(e)}")
            return None

    def process_prediction_results(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process and format prediction results for Cortex
        
        Args:
            results: Raw results from ClusterHawk API
            
        Returns:
            Dict containing formatted results
        """
        try:
            prediction_data = results.get('results', {}).get('prediction', {})
            predictions = prediction_data.get('predictions', [])
            
            if not predictions:
                self.warning("No predictions found in results")
                return {
                    'summary': 'No predictions available',
                    'predictions': [],
                    'total_analyzed': 0
                }
            
            has_cluster_descriptions = False
            
            for pred in predictions:
                if 'primary_characteristic' in pred and 'key_indicators' in pred:
                    has_cluster_descriptions = True
                    break
            
            if has_cluster_descriptions:
                self.info(f"Found cluster descriptions embedded in predictions")
            
            processed_predictions = []
            cluster_summary = {}
            
            for pred in predictions:
                ip = pred.get('ip', 'unknown')
                cluster = pred.get('predicted_cluster', 'unknown')
                confidence = pred.get('confidence', 0.0)
                uncertainty = pred.get('uncertainty', 0.0)
                model_variance = pred.get('model_variance', 0.0)
                
                cluster_key = f"Cluster {cluster}"
                if cluster_key not in cluster_summary:
                    cluster_info = {
                        'count': 0,
                        'avg_confidence': 0.0,
                        'ips': []
                    }
                    
                    if 'primary_characteristic' in pred:
                        cluster_info['description'] = pred.get('primary_characteristic', '')
                        cluster_info['indicators'] = pred.get('key_indicators', '')
                    
                    cluster_summary[cluster_key] = cluster_info
                
                cluster_summary[cluster_key]['count'] += 1
                cluster_summary[cluster_key]['avg_confidence'] += confidence
                cluster_summary[cluster_key]['ips'].append(ip)
                
                processed_pred = {
                    'ip': ip,
                    'cluster': cluster,
                    'confidence': round(confidence, 3),
                    'uncertainty': round(uncertainty, 3),
                    'model_variance': round(model_variance, 4)
                }
                
                if 'primary_characteristic' in pred:
                    processed_pred['cluster_description'] = pred.get('primary_characteristic', '')
                    processed_pred['cluster_indicators'] = pred.get('key_indicators', '')
                
                processed_predictions.append(processed_pred)
            
            for cluster_info in cluster_summary.values():
                if cluster_info['count'] > 0:
                    cluster_info['avg_confidence'] = round(
                        cluster_info['avg_confidence'] / cluster_info['count'], 3
                    )

            result = {
                'summary': {
                    'total_analyzed': len(predictions),
                    'clusters_found': len(cluster_summary),
                    'model_used': self.model_name,
                    'job_id': results.get('job_id', 'unknown'),
                    'has_cluster_descriptions': has_cluster_descriptions,
                    'is_prebuilt_model': self.model_name.upper().startswith('CHAWKR_')
                },
                'cluster_summary': cluster_summary,
                'predictions': processed_predictions,
                'raw_results': prediction_data
            }

            result['taxonomies'] = self._create_taxonomies(result)

            return result
            
        except Exception as e:
            self.error(f"Failed to process prediction results: {str(e)}")
            return {
                'summary': 'Error processing results',
                'error': str(e),
                'predictions': []
            }

    def _create_taxonomies(self, processed: Dict[str, Any]):
        """
        Build Cortex taxonomies where:
          - namespace: 'Clusterhawk'
          - predicate: cluster description (e.g., 'Noise')
          - value: confidence (string)
        If multiple predictions exist, create one row per prediction.
        """
        tx = []
        preds = processed.get("predictions") or []
        if not preds:
            return tx

        for p in preds:
            desc = p.get("cluster_description") or "Unknown"
            conf = float(p.get("confidence") or 0.0)
            tx.append({
                "namespace": "Clusterhawk",
                "predicate": str(desc),
                "value": f"{conf:.3f}",
                "level": "info"
            })
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
                self.error('No IP address provided')
                return
            
            try:
                ipaddress.ip_address(ip_address)
            except ValueError:
                self.error(f'Invalid IP address format: {ip_address}')
                return
            
            # Check quota if enabled
            if not self.check_concurrent_quota():
                self.error('Concurrent job quota exceeded')
                return
            
            # Submit prediction job
            job_id = self.submit_prediction_job([ip_address])
            if not job_id:
                self.error('Failed to submit prediction job')
                return
            
            # Monitor job completion
            if not self.monitor_job_status(job_id):
                self.error('Job monitoring failed or timed out')
                return
            
            # Get results
            results = self.get_job_results(job_id)
            if not results:
                self.error('Failed to retrieve job results')
                return
            
            # Process and return results
            processed_results = self.process_prediction_results(results)
            self.report(processed_results)
            
        except Exception as e:
            self.error(f'Analysis failed: {str(e)}')


if __name__ == '__main__':
    ClusterHawkAnalyzer().run()
