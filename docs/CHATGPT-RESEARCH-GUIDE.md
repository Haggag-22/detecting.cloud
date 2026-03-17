# ChatGPT Research Guide: Detection Rule Sections

Use this document to research each section of a detection rule page. Copy the relevant block and paste it into ChatGPT with the detection context (e.g., API name, AWS service, attack type). ChatGPT will return researched content you can use to populate the detection.

---

## How to Use

1. **Identify the detection** – e.g., "DeleteFlowLogs", "CloudTrail StopLogging", "S3 PutBucketPolicy"
2. **Copy the research prompt** for the section you need
3. **Replace placeholders** – `[API_NAME]`, `[SERVICE]`, `[ATTACK_TYPE]` with your values
4. **Paste into ChatGPT** and ask it to research
5. **Use the output** to fill the corresponding section in `detections.ts`

---

## Section 1: Threat Context (Phase 1)

**Output format:** 4 fields: `attackerBehavior`, `realWorldUsage`, `whyItMatters`, `riskAndImpact`

### Research Prompt

```
I need threat context for a cloud security detection rule. Research and provide:

**Detection:** [API_NAME] on AWS [SERVICE] – [brief description of what the API/action does]

For each field, write 2–4 sentences in a professional detection-engineering style:

1. **attackerBehavior** – What does an attacker do with this API? What permissions are needed? How does it help them (evasion, exfiltration, persistence, etc.)?

2. **realWorldUsage** – Where has this behavior been seen in real campaigns, threat reports, or common abuse patterns? Cite if possible (e.g., CrowdStrike, Mandiant, AWS security bulletins).

3. **whyItMatters** – Why is detecting this action important? Why is it a high-signal event vs. normal operations?

4. **riskAndImpact** – What is the business/security impact if this goes undetected?

Be specific and technical. Avoid generic marketing language.
```

---

## Section 2: Telemetry Validation (Phase 2)

**Output format:** `requiredLogSources`, `requiredFields`, `loggingRequirements`, `limitations`

### Research Prompt

```
I need telemetry validation for a cloud security detection rule.

**Detection:** [API_NAME] on AWS [SERVICE]
**Log source:** [e.g., CloudTrail management events, CloudTrail data events, VPC Flow Logs]

Research and provide:

1. **requiredLogSources** – Exact log sources needed (e.g., "AWS CloudTrail (management events)", "CloudTrail data events for S3"). List as array.

2. **requiredFields** – Which event fields must be present? Use dot notation (e.g., eventSource, eventName, userIdentity.arn, requestParameters.X). List as array.

3. **loggingRequirements** – What must be enabled for this to work? (e.g., "CloudTrail must be enabled", "Data Events for S3 must be configured", "No Data Events required"). List as array.

4. **limitations** – Blind spots, delays, cross-account issues, regions, or anything that could cause missed detections. List as array.

Use AWS documentation and CloudTrail event reference. Be precise.
```

---

## Section 3: Data Modeling (Phase 3)

**Output format:** `rawToNormalized` array, `exampleNormalizedEvent` JSON

### Research Prompt

```
I need data modeling for a cloud security detection rule.

**Detection:** [API_NAME] on AWS [SERVICE]
**CloudTrail event structure:** [paste or describe the raw CloudTrail event]

Research and provide:

1. **rawToNormalized** – Field mappings from raw CloudTrail to a normalized schema. Use ECS-style naming where applicable:
   - eventSource → event.source or event.provider
   - eventName → event.action
   - userIdentity.arn → user.arn
   - requestParameters.X → aws.[service].X
   - sourceIPAddress → source.ip
   
   Format: array of { rawPath, normalizedPath, notes }

2. **exampleNormalizedEvent** – A sample normalized event as JSON. Include: @timestamp, event (category, type, action, outcome, provider), user (name, type), cloud (provider, account.id), aws.[service] (relevant request params), source (ip).
```

---

## Section 4: Enrichment and Context (Phase 4)

**Output format:** Array of `{ dimension, description, examples, falsePositiveReduction }`

### Research Prompt

```
I need enrichment dimensions for a cloud security detection rule.

**Detection:** [API_NAME] on AWS [SERVICE]
**What it detects:** [brief description]

Research and suggest 3–4 enrichment dimensions that would improve signal quality and reduce false positives. For each dimension, provide:

1. **dimension** – Short name (e.g., "Identity Context", "IP Reputation", "Asset Metadata", "Behavioral Baselines")

2. **description** – What data this dimension adds and why it helps.

3. **examples** – Concrete examples (e.g., "user.email from Okta", "GeoIP for impossible travel", "VPC tags: prod, egress").

4. **falsePositiveReduction** – How this dimension reduces false positives in one sentence.

Focus on dimensions commonly used in cloud detection engineering: identity, IP reputation, asset criticality, behavioral baselines, threat intel.
```

---

## Section 5: Detection Logic (Phase 5 – Detection Logic Tab)

**Output format:** `humanReadable`, `conditions`, `tuningGuidance`, `whenToFire`

### Research Prompt

```
I need a detection logic explanation for a cloud security rule.

**Detection:** [API_NAME] on AWS [SERVICE]
**Rule logic:** [e.g., "eventSource=ec2.amazonaws.com AND eventName=DeleteFlowLogs"]

Write in professional detection-engineering style:

1. **humanReadable** – 3–5 sentences explaining: what the detection identifies, why the rule is structured this way (broad vs. filtered), and how to use it in production (e.g., layer enrichment, correlate with other rules).

2. **conditions** – Bullet list of exact conditions that trigger the detection. Be precise (e.g., "eventSource equals ec2.amazonaws.com", "eventName equals DeleteFlowLogs").

3. **tuningGuidance** – How to reduce false positives: allowlists, enrichment, correlation with other detections. Number the suggestions.

4. **whenToFire** – When should this detection fire? Expected volume? When to apply tuning vs. suppress?
```

---

## Section 6: Testing (Phase 6)

**Output format:** `simulationCommand`, `testingSteps`

### Research Prompt

```
I need testing steps for a cloud security detection rule.

**Detection:** [API_NAME] on AWS [SERVICE]
**What triggers it:** [e.g., DeleteFlowLogs API call]

Provide:

1. **simulationCommand** – Exact AWS CLI command to simulate the attack in a lab. Use real syntax (e.g., aws ec2 delete-flow-logs --flow-log-ids fl-xxx). Include any required parameters.

2. **testingSteps** – Ordered list of steps to validate the detection:
   - Set up lab (isolated account, CloudTrail enabled)
   - Run simulation command
   - Verify event appears in CloudTrail
   - Run detection query (Athena/Splunk/etc.)
   - Confirm alert fires
   - Document results

Be specific and actionable. Reference AWS CLI docs if needed.
```

---

## Section 7: Deployment (Phase 7)

**Output format:** `whereItRuns`, `scheduling`, `considerations`

### Research Prompt

```
I need deployment context for a cloud security detection rule.

**Detection:** [API_NAME] on AWS [SERVICE]
**Log source:** [e.g., CloudTrail management events]

Provide:

1. **whereItRuns** – List of platforms where this detection can run: Athena, CloudWatch Logs Insights, Splunk, Datadog, Panther, Chronicle, EventBridge + Lambda, etc.

2. **scheduling** – Batch vs. real-time: typical schedule for Athena (e.g., every 5–15 min), real-time options (EventBridge + Lambda, SIEM streaming).

3. **considerations** – Practical notes: retention, correlation with other rules, Data Events required or not, cross-account, region, etc. List as array.
```

---

## Section 8: Detection Quality

**Output format:** `signalQuality`, `falsePositiveRate`, `expectedVolume`, `productionReadiness`

### Research Prompt

```
I need quality metrics for a cloud security detection rule.

**Detection:** [API_NAME] on AWS [SERVICE]
**What it detects:** [brief description]

Estimate and provide:

1. **signalQuality** – Score 1–10. Consider: how specific is the signal, how rare is the action in normal ops, how actionable is the alert.

2. **falsePositiveRate** – One phrase (e.g., "Low (legitimate cleanup is rare)", "Medium (automation can trigger)", "High (needs tuning)").

3. **expectedVolume** – Typical alert volume (e.g., "1–10 events/month", "Org-dependent", "High in large accounts").

4. **productionReadiness** – One of: "experimental", "validated", "production". Consider whether the rule has been tested and tuned in real environments.
```

---

## Rule Formats Research (Sigma, Athena, Splunk, Lambda)

**Output format:** Rule strings for each format

### Research Prompt

```
I need detection rules in multiple formats for a cloud security detection.

**Detection:** [API_NAME] on AWS [SERVICE]
**Trigger conditions:** [e.g., eventSource=ec2.amazonaws.com, eventName=DeleteFlowLogs]
**Optional filters:** [e.g., exclude certain roles, filter by region]

Generate:

1. **Sigma** – YAML Sigma rule. Use logsource.service: cloudtrail. Include title, status, detection selection, condition, level.

2. **CloudTrail Athena** – SQL query for cloudtrail_logs table. SELECT relevant fields, WHERE with eventSource and eventName, ORDER BY eventTime DESC.

3. **Splunk** – SPL query. index=aws sourcetype=aws:cloudtrail, filter by eventSource and eventName, | table relevant fields.

4. **Lambda** – Python lambda_handler for EventBridge CloudTrail events. Check detail.eventSource and detail.eventName, return matched alert payload. Include docstring with trigger and use case.

Use correct syntax for each format. Match the trigger conditions exactly.
```

---

## Quick Reference: Section → Fields

| Section | Key Fields |
|---------|------------|
| 1. Threat Context | attackerBehavior, realWorldUsage, whyItMatters, riskAndImpact |
| 2. Telemetry | requiredLogSources, requiredFields, loggingRequirements, limitations |
| 3. Data Modeling | rawToNormalized, exampleNormalizedEvent |
| 4. Enrichment | dimension, description, examples, falsePositiveReduction |
| 5. Detection Logic | humanReadable, conditions, tuningGuidance, whenToFire |
| 6. Testing | simulationCommand, testingSteps |
| 7. Deployment | whereItRuns, scheduling, considerations |
| 8. Quality | signalQuality, falsePositiveRate, expectedVolume, productionReadiness |

---

## Suggested Research Order

1. **Threat Context** – Understand the attack first
2. **Telemetry** – Confirm what logs and fields exist
3. **Rule Formats** – Write the actual rules
4. **Detection Logic** – Document the logic
5. **Data Modeling** – If you need normalized schema
6. **Enrichment** – Add context for tuning
7. **Testing** – Validate in lab
8. **Deployment** – Where and how to run
9. **Quality** – Estimate metrics
