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
- **Per-Prediction Explanations**: Each prediction can carry a decision breakdown — the specific signals that drove the assignment and which models weighed in — rendered as an expandable section in the long report
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

- **ip**: IPv4 and IPv6 addresses

## Output Format

The analyzer returns structured threat intelligence data including:

### How to read the result

Every prediction row carries a **`kind`** field — the contract's trust gate. Read it first:

- **`confident_match`** — strong fingerprint match. The model is confident in the cluster attribution. This is the **actionable subset** for SOAR/SIEM correlation rules.
- **`ambiguous_diffuse`** — top-1 leans toward this cluster but probability mass is spread thin across many candidates. Treat the attribution with softer trust and **review the candidate set** as a unit rather than relying on top-1 alone.
- **`ambiguous_split`** — close two-way / few-way tie between candidates. The true match is likely one of the listed candidates; investigate them as a set.
- **`out_of_distribution`** — no fingerprint match. The IP does not resemble any trained cluster. **`predicted_cluster` and `confidence` are intentionally `null`** on these rows to prevent silent false positives in SIEM joins. Investigate via behavioral evidence rather than the cluster attribution.

### Prediction Results — per-row fields

- **`ip`**: IP address analyzed
- **`predicted_cluster`**: Top-1 cluster id assigned by the model. **`null` when `kind == "out_of_distribution"`** — do not coerce to `-1` or `0`.
- **`confidence`**: Top-1 softmax probability, 0.0 to 1.0. **`null` on out-of-distribution rows** (by contract).
- **`kind`**: Trust gate — one of `confident_match`, `ambiguous_diffuse`, `ambiguous_split`, `out_of_distribution`.
- **`top1_minus_top2`**: Gap between top-1 and top-2 candidate confidence. Wide gap = clean win; small gap pairs with `ambiguous_split`. `null` on OOD rows.
- **`effective_n`**: `exp(entropy)` over the candidate distribution — interpretable as the "candidates worth of probability mass". Near 1.0 ⇒ confident; large values ⇒ diffuse hedging.
- **`candidates`**: Top-K candidate clusters above an entropy-aware confidence floor, each `{cluster_id, confidence}`. Empty array on OOD rows.
- **`label`** _(user-trained models only)_: Actor label from the training job.
- **`primary_characteristic`** / **`key_indicators`** _(prebuilt models only)_: Cluster fingerprint description from the prebuilt model's cluster
- **`explanation_status`** _(when available)_: `ok`, `partial`, `unavailable:<reason>`, or `disabled` — the state of the per-prediction "why did it land here" breakdown.
- **`explanation`** _(when available)_: a compact **"why did it land here"** object for THAT prediction — the specific signals that drove the assignment (not typical hosts in the cluster), which models weighed in.

### Per-Prediction Explanation

Each prediction may carry an `explanation` object answering **"why did THIS IP land in THIS cluster"** — the specific signals that drove the assignment, not a description of typical hosts in the cluster. Key fields:

- **`mode`**: drives the whole shape — a non-confident mode never reads like a confident story.
  - `single` — one cluster clearly fits.
  - `contrastive` — a close call; two-or-few candidates nearly tie.
  - `diffuse` — top-1 leans, but probability mass is spread thin across many clusters.
  - `none_fits` — out of distribution; no cluster fits (target/reference/margin are `null`).
- **`target`** / **`reference`**: the assigned cluster and what its decision margin is measured against.
- **`candidates[]`**: per candidate `{cluster_id, confidence, non_match, toward[], away[]}`. Each signal is `{label, weight, observed, value_state}`, where **`weight` is a signed share of total absolute pull** on the decision margin — a magnitude, **not** a match probability. `value_state` is `oov` (host presented a value the model doesn't recognise) or `absent` (not presented by this host).
- **`contrast`**: `{pair: [a, b], signals[]}` — what little separates the two closest clusters.
- **`model_votes[]`**: `{model, share, top_cluster}` — which models drove the decision.
- **`unmatched_observations[]`**: values the host presented that matched nothing the model knows.
- **`caveats[]`**: machine tokens (e.g. `near_tie_gap_0.05`, `mass_spread_across_9_clusters`) flagging why to read the explanation with care.
- **`explained_share`** / **`interpretable_share`**: 0–1 coverage — the fraction of deciding-model mass with feature attributions, and the fraction of signal mass that is human-interpretable.

`explanation_status` reports the state independently: `ok`, `partial` (some of the decision could not be attributed), `unavailable:<reason>`, or `disabled`. An explanation never alters or fails a prediction — a row always returns even when its explanation is unavailable.

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
          "kind": "confident_match",
          "top1_minus_top2": 0.83,
          "effective_n": 1.21,
          "candidates": [{ "cluster_id": 2, "confidence": 0.94 }],
          "label": "['Web Crawler']",
          "explanation_status": "ok",
          "explanation": {
            "mode": "single",
            "target": 2,
            "reference": "weighted_alternatives",
            "candidates": [
              {
                "cluster_id": 2,
                "confidence": 0.94,
                "toward": [
                  {
                    "label": "Product",
                    "weight": 0.42,
                    "observed": "nginx/1.18.0"
                  },
                  {
                    "label": "TLS JA3 fingerprint",
                    "weight": 0.31,
                    "observed": "a0e9f5b2...",
                    "value_state": "oov"
                  }
                ],
                "away": []
              }
            ],
            "model_votes": [
              {
                "model": "model_1",
                "share": 0.55,
                "top_cluster": 2
              }
            ],
            "explained_share": 0.92,
            "interpretable_share": 0.74
          }
        },
        {
          "ip": "2001:db8:3c4d:15::1a2f",
          "predicted_cluster": 5,
          "confidence": 0.91,
          "kind": "confident_match",
          "top1_minus_top2": 0.77,
          "effective_n": 1.28,
          "candidates": [{ "cluster_id": 5, "confidence": 0.91 }],
          "label": "['Botnet C2']"
        },
        {
          "ip": "10.0.0.50",
          "predicted_cluster": 1,
          "confidence": 0.42,
          "kind": "ambiguous_split",
          "top1_minus_top2": 0.05,
          "effective_n": 2.41,
          "candidates": [
            { "cluster_id": 1, "confidence": 0.42 },
            { "cluster_id": 7, "confidence": 0.37 },
            { "cluster_id": 3, "confidence": 0.11 }
          ],
          "label": "['Scanner']"
        },
        {
          "ip": "203.0.113.42",
          "predicted_cluster": null,
          "confidence": null,
          "kind": "out_of_distribution",
          "top1_minus_top2": null,
          "effective_n": 8.74,
          "candidates": [],
          "label": null
        }
      ],
      "total_predictions": 4,
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

### Prebuilt Model Response

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
          "kind": "confident_match",
          "top1_minus_top2": 0.71,
          "effective_n": 1.34,
          "candidates": [
            { "cluster_id": 11, "confidence": 0.89 },
            { "cluster_id": 4, "confidence": 0.07 }
          ],
          "primary_characteristic": "APAC residential telecom — CHINANET / Bharti Airtel SOHO routers",
          "key_indicators": "Dropbear SSH 2020.81, Mosquitto MQTT 1.6, JA3 e7d705a3286e19ea42f587b344ee6865"
        },
        {
          "ip": "198.51.100.7",
          "predicted_cluster": null,
          "confidence": null,
          "kind": "out_of_distribution",
          "top1_minus_top2": null,
          "effective_n": 12.4,
          "candidates": []
        }
      ],
      "total_predictions": 2
    }
  },
  "created_at": "2024-01-15T10:25:00Z",
  "completed_at": "2024-01-15T10:28:45Z",
  "api_request": true,
  "model_name": "CHAWKR_STORM_0940_BRUTEFORCE"
}
```

### Cortex Taxonomy Mapping

The analyzer surfaces each prediction as one Cortex taxonomy row under the `Clusterhawk` namespace. The `level` is mapped from `kind`, and the `predicate` / `value` carry the cluster id and confidence when available:

| kind                  | predicate                     | value                 | level        | Cortex tile colour                               |
| --------------------- | ----------------------------- | --------------------- | ------------ | ------------------------------------------------ |
| `confident_match`     | `Cluster`                     | `<id> (<confidence>)` | `malicious`  | red — actionable                                 |
| `ambiguous_split`     | `Cluster (ambiguous split)`   | `<id> (<confidence>)` | `suspicious` | orange — review candidate set                    |
| `ambiguous_diffuse`   | `Cluster (ambiguous diffuse)` | `<id> (<confidence>)` | `suspicious` | orange — soft-trust attribution                  |
| `out_of_distribution` | `Kind`                        | `out of distribution` | `info`       | grey — no cluster match, behavioural triage only |

Out-of-distribution rows omit the cluster id from the tile (since `predicted_cluster` and `confidence` are `null` by contract) and instead surface the trust-gate label as the value, so the tile is never misleading about a cluster that wasn't actually assigned.

## Support

For technical support or questions:

- ClusterHawk Support: support@chawkr.com
- Documentation: https://clusterhawk.chawkr.com/docs
- Platform: https://clusterhawk.chawkr.com/

## License

This analyzer is provided as part of the ClusterHawk platform. Please refer to your ClusterHawk subscription agreement for usage terms.
