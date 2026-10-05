# Suspicious_Verdict

## Overview

**Suspicious_Verdict** synchronizes triage decisions made on a **TheHive** Case or Alert with [**Suspicious**](https://github.com/thalesgroup-cert/suspicious), the case management platform developed and operated by **Thales CERT (THA-CERT)**.

When an analyst adds a verdict tag (`SAFE`, `SUSPICIOUS`, or `DANGEROUS`) to a Case or Alert in TheHive, running this responder automatically updates the corresponding investigation in Suspicious. This eliminates the need to manually copy the verdict from one platform to the other.

|                     |                                                                               |
| ------------------- | ----------------------------------------------------------------------------- |
| **Author**          | THA-CERT // EBA                                                               |
| **License**         | AGPL-V3                                                                       |
| **Data types**      | `thehive:case`, `thehive:alert`                                               |
| **Related project** | [thalesgroup-cert/suspicious](https://github.com/thalesgroup-cert/suspicious) |

## How it works

The responder follows these steps:

1. **Identify the Suspicious investigation.**
   The responder extracts the Suspicious case ID from the TheHive Case or Alert **title**. The title is expected to contain a pattern such as `... #1234 - <description>`.

2. **Read the verdict tag.**
   The responder checks the Case or Alert tags for exactly one tag matching `suspicious:verdict="<VALUE>"`, where `<VALUE>` must be `SAFE`, `SUSPICIOUS`, or `DANGEROUS` (see [Taxonomy](#taxonomy)).

3. **Update the Suspicious investigation.**
   The responder sends a `PATCH` request to:

   ```text
   {suspicious_url}/api/investigations/{suspicious_case_id}/edit-global/
   ```

   with the following payload:

   ```json
   {
     "score": 10,
     "confidence": 100,
     "classification": "<VALUE>"
   }
   ```

4. **Mark the item as processed.**
   Once Suspicious returns a successful `200` response, the responder adds the `suspicious:status="challenge_reviewed."` tag to the Case or Alert and reports a confirmation message in TheHive.

### Error handling

The responder fails explicitly, with the error visible in the TheHive task log, in any of the following cases:

* the Case or Alert ID is missing from the payload;
* no Suspicious case ID can be extracted from the title;
* the Case or Alert has no tags;
* multiple `suspicious:verdict=` tags are present;
* no valid `suspicious:verdict=` tag is found;
* the Suspicious API request fails, either because of a non-`200` response or a network error.

## Taxonomy

This responder uses the `suspicious` taxonomy provided with the project (`taxonomy/machinetag.json`). Import this taxonomy into TheHive to make the three verdict values available through tag auto-completion, each with its own colour.

| Tag                               | Meaning                                                   | Colour       |
| --------------------------------- | --------------------------------------------------------- | ------------ |
| `suspicious:verdict="SAFE"`       | The Case or Alert is classified as **Safe** in Suspicious | 🟢 `#00ad1c` |
| `suspicious:verdict="SUSPICIOUS"` | The Case or Alert is classified as **Suspicious**         | 🟠 `#ffa800` |
| `suspicious:verdict="DANGEROUS"`  | The Case or Alert is classified as **Dangerous**          | 🔴 `#ff0000` |

An analyst only needs to add the appropriate verdict tag to the Case or Alert and run the responder, either manually or automatically (see below).

## Configuration

| Name               | Type   | Required | Description                                                       |
| ------------------ | ------ | -------- | ----------------------------------------------------------------- |
| `suspicious_url`   | string | Yes      | Base URL of the Suspicious instance, e.g. `http://localhost:9020` |
| `suspicious_token` | string | Yes      | Suspicious API token used for authentication                      |

Configure these values under **Organization → Responders → Suspicious_Verdict** in Cortex, then enable the responder for your TheHive organization.

## Usage

### Manual trigger

To run the responder manually:

1. Add the appropriate verdict tag to the Case or Alert, for example `suspicious:verdict="DANGEROUS"`.
2. From the Case or Alert view in TheHive, run the **Suspicious_Verdict** responder.
3. The corresponding Suspicious investigation is updated, and the Case or Alert is tagged `suspicious:status="challenge_reviewed."`.

### Automatic trigger (optional)

Running the responder manually after every verdict update can easily be overlooked. TheHive supports **notifications** that can automatically run a responder when a matching event occurs — in this case, when a `suspicious:verdict=` tag is added to a Case or Alert.

The corresponding notification definition, **Run Suspicious_Verdict Responder**, is provided separately in the [`StrangeBee/integrations`](https://github.com/StrangeBeeCorp/integrations) repository, under `integrations/vendors/Suspicious/thehive/functions`, along with a dedicated README explaining how to import and configure it in TheHive.

➡️ See **StrangeBee/integrations — Run Suspicious_Verdict Responder** for the fully automated workflow:

**tag added → responder runs → Suspicious investigation updated**

No manual action is required once the notification is configured.

## Requirements

```text
requests
cortexutils
```

## Files in this responder

```text
Suspicious_Verdict/
├── suspicious_verdict.py
├── Suspicious_Verdict.json
├── requirements.txt
├── README.md
└── taxonomy/
    └── machinetag.json