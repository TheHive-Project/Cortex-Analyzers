# ClusterHawk Cortex Analyzer

A Cortex analyzer for ClusterHawk threat intelligence platform that provides IP address prediction using pre-trained models.

## Overview

This Cortex analyzer integrates with ClusterHawk's prediction API to provide threat intelligence directly within TheHive/Cortex workflows. The analyzer uses pre-trained ClusterHawk models to predict threat clusters for IP addresses, providing confidence scores and infrastructure analysis based on existing threat intelligence models.

### What This Analyzer Does

- **Prediction Only**: Uses pre-trained ClusterHawk models to classify IP addresses
- **API Integration**: Submits prediction jobs and retrieves results from ClusterHawk
- **Infrastructure Analysis**: Provides confidence scores and uncertainty metrics for cluster assignments

## Features

- **IP Address Prediction**: Analyze individual IP addresses using pre-trained ClusterHawk models
- **Threat Pattern Recognition**: Identify infrastructure patterns that match known threat actor behaviors
- **Cluster Classification**: Identify which threat cluster an IP belongs to based on existing models
- **Confidence Scoring**: Get confidence levels and uncertainty metrics for predictions
- **Quota Management**: Automatic concurrent job quota checking before submission
- **Model Selection**: Use any pre-trained ClusterHawk model available in your account
- **API Integration**: Seamless integration with ClusterHawk's prediction API

## Prerequisites

- ClusterHawk account with **Hobby tier or higher subscription** (API access not available on Basic plans)
- At least one **pre-trained model** in your ClusterHawk account
- Valid API key generated from your ClusterHawk profile (shown for 30 seconds only)

## Workflow

### Step 1: Prepare Models on ClusterHawk Platform
Before using this analyzer, you must:

1. **Train Models**: Use the ClusterHawk platform to train models on your threat intelligence data
2. **Create Clusters**: Perform clustering analysis on the ClusterHawk platform to group IPs by infrastructure patterns
3. **Label Clusters**: Apply custom labeling rules to identify malicious clusters based on infrastructure characteristics
4. **Save Models**: Ensure your trained models are available for prediction

### Step 2: Configure Cortex Analyzer
1. **Get API Key**: Generate an API key from your ClusterHawk profile
2. **Configure Model**: Specify which pre-trained model to use for predictions
3. **Set Parameters**: Configure timeout, quota checking, and other options

### Step 3: Run Predictions
1. **Submit IPs**: The analyzer submits IP addresses to ClusterHawk for prediction
2. **Monitor Jobs**: Tracks job status and waits for completion
3. **Retrieve Results**: Gets prediction results with confidence scores and infrastructure analysis
4. **Return Intelligence**: Provides threat intelligence and cluster characteristics to TheHive/Cortex

## Configuration

### Required Parameters

- **api_key**: Your ClusterHawk API key (generate from Profile page)
- **model_name**: Name of the trained model to use for prediction

### Optional Parameters

- **base_url**: ClusterHawk API base URL (default: https://clusterhawk.chawkr.com)
- **job_name**: Custom name for prediction jobs (default: "Cortex Analysis")
- **check_quota**: Enable concurrent job quota checking (default: true)
- **timeout**: Maximum time to wait for job completion in minutes (default: 30)
- **poll_interval**: Interval between status checks in seconds (default: 10)

### Example Configuration

```json
{
  "api_key": "chawkr_your_api_key_here",
  "model_name": "network-classification-v1",
  "base_url": "https://clusterhawk.chawkr.com",
  "job_name": "Cortex Threat Analysis",
  "check_quota": true,
  "timeout": 30,
  "poll_interval": 10
}
```

## Usage

### In Cortex

1. [Enable the analyzer in Cortex](https://docs.strangebee.com/cortex/user-guides/first-start/#step-6-enable-and-configure-analyzers)
2. Configure the required parameters (API key and model name)
3. Run the analyzer on IP address observables
4. Review the threat intelligence results

### Supported Data Types

- **ip**: IPv4 addresses

## Output Format

The analyzer returns structured threat intelligence data including:

### Prediction Results
- **ip**: IP address analyzed
- **predicted_cluster**: Cluster number assigned by the model
- **confidence**: Confidence score (0.0 to 1.0)
- **uncertainty**: Uncertainty metric (0.0 to 1.0)
- **model_variance**: Model variance score
- **total_predictions**: Total number of predictions in the job

### Prebuilt Models (Enterprise Only)
For prebuilt models, additional fields are included:
- **primary_characteristic**: Description of the cluster characteristics
- **key_indicators**: Key indicators that led to the classification

### Example Output

```json
{
  "success": true,
  "job_id": "job_abc123def456",
  "pipeline_type": "REGULAR_MODEL_PREDICTION",
  "results": {
    "prediction": {
      "predictions": [
        {
          "ip": "192.168.1.100",
          "predicted_cluster": 2,
          "confidence": 0.94,
          "uncertainty": 0.06,
          "model_variance": 0.0037
        }
      ],
      "total_predictions": 1,
      "model_info": {
        "model_id": "job_abc123def456"
      }
    }
  },
  "created_at": "2024-01-15T10:25:00Z",
  "completed_at": "2024-01-15T10:28:45Z",
  "api_request": true,
  "model_name": "network-classification-v1"
}
```

### Prebuilt Model Response (Enterprise Only)

```json
{
  "success": true,
  "job_id": "job_xyz789abc123",
  "pipeline_type": "ADVANCED_MODEL_PREDICTION",
  "results": {
    "prediction": {
      "predictions": [
        {
          "ip": "203.0.113.42",
          "predicted_cluster": 11,
          "confidence": 0.89,
          "uncertainty": 0.11,
          "primary_characteristic": "Ultra-unstable C2 infrastructure",
          "key_indicators": "72% label change, 2.09 entropy, 10 cluster migrations"
        }
      ],
      "total_predictions": 1
    }
  },
  "created_at": "2024-01-15T10:25:00Z",
  "completed_at": "2024-01-15T10:28:45Z",
  "api_request": true,
  "model_name": "CHAWKR_STORM_0940_BRUTEFORCE"
}
```

## Support

For technical support or questions:
- ClusterHawk Support: support@chawkr.com
- Documentation: https://clusterhawk.chawkr.com/docs
- Platform: https://clusterhawk.chawkr.com/

## License

This analyzer is provided as part of the ClusterHawk platform. Please refer to your ClusterHawk subscription agreement for usage terms.
