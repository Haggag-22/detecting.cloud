# Detection Rule Page Format Reference

This document describes the structure and format of detection rule pages in Detecting.Cloud. Use it when writing new detection rules or updating existing ones.

---

## Overview

Each detection page follows a **detection engineering lifecycle** model. When a detection has a `lifecycle` object, it renders the full 8-section layout. Detections without `lifecycle` use the legacy rule-catalog layout.

---

## Base Detection Fields (Required for All Detections)

```typescript
{
  id: string;                    // e.g. "det-110"
  title: string;                // Display name
  description: string;          // Short technical description
  awsService: string;           // Primary AWS service (EC2, IAM, S3, etc.)
  relatedServices: string[];    // Other services in attack chain
  severity: "Critical" | "High" | "Medium" | "Low";
  tags: string[];               // e.g. ["EC2", "VPC", "Flow Logs"]
  logSources: string[];         // e.g. ["AWS CloudTrail"]
  falsePositives: string[];     // Known FP sources
  rules: RuleFormats;           // See Rule Formats section below
  relatedAttackSlugs: string[];
}
```

---

## Rule Formats (detection.rules)

| Key         | UI Label           | Purpose                                      |
|-------------|--------------------|----------------------------------------------|
| sigma       | Sigma              | Canonical rule format                         |
| cloudtrail  | CloudTrail Athena  | SQL for Athena / batch analytics             |
| splunk      | Splunk             | SIEM query                                   |
| lambda      | Lambda             | Python handler for EventBridge / real-time   |
| cloudwatch  | CloudWatch Insights| In "+ More" dropdown                         |
| eventbridge | EventBridge        | In "+ More" dropdown                         |

**Tab order in Phase 5:** Detection Logic → Sigma → CloudTrail Athena → Splunk → Lambda → More (CloudWatch, EventBridge)

---

## Lifecycle Object (Full Page Layout)

When present, `lifecycle` enables the 8-section detection engineering layout.

### Top-Level Lifecycle Fields

```typescript
lifecycle: {
  whyItMatters?: string;           // Short statement for overview (1–2 sentences)
  threatContext?: ThreatContext;
  telemetryValidation?: TelemetryValidation;
  dataModeling?: DataModeling;
  enrichment?: EnrichmentContext[];
  logicExplanation?: DetectionLogicExplanation;
  simulationCommand?: string;     // CLI command to simulate attack
  deployment?: DeploymentInfo;
  detectionFlow?: DetectionFlowStep[];  // Optional, rarely used
  quality?: DetectionQuality;
  communityConfidence?: CommunityConfidence;
}
```

---

## Phase 1: Threat Research and Prioritization

**Section title:** "Threat Research and Prioritization" (Phase 1)

```typescript
threatContext: {
  attackerBehavior: string;   // What the attacker does
  realWorldUsage?: string;    // Where seen in campaigns
  whyItMatters: string;       // Why this detection matters
  riskAndImpact: string;      // Business/security impact
}
```

**Sub-headers (amber):** Attacker Behavior, Real-World Usage, Why It Matters, Risk and Impact

---

## Phase 2: Telemetry and Data Analysis

**Section title:** "Telemetry and Data Analysis" (Phase 2)

```typescript
telemetryValidation: {
  requiredLogSources: string[];   // e.g. ["AWS CloudTrail (management events)"]
  requiredFields: string[];      // e.g. ["eventSource", "eventName", "userIdentity.arn"]
  loggingRequirements: string[]; // Setup notes
  limitations?: string[];        // Blind spots, delays, etc.
}
```

**Sub-headers:** Required Log Sources, Required Fields, Logging Requirements, Known Limitations

---

## Phase 3: Data Modeling and Log Normalization

**Section title:** "Data Modeling and Log Normalization" (Phase 3)

```typescript
dataModeling: {
  rawToNormalized: [
    { rawPath: string; normalizedPath: string; notes?: string; }
  ];
  exampleNormalizedEvent: string;  // JSON string
}
```

**Sub-headers:** Field Mappings (Raw → Normalized), Example Normalized Event

---

## Phase 4: Enrichment and Context

**Section title:** "Enrichment and Context" (Phase 4)

```typescript
enrichment: [
  {
    dimension: string;              // e.g. "Identity Context"
    description: string;
    examples: string[];
    falsePositiveReduction?: string;
  }
]
```

**Sub-headers:** Per-dimension (dimension name in amber), FP reduction note

---

## Phase 5: Writing the Detection Rule

**Section title:** "Writing the Detection Rule" (Phase 5)

### Detection Logic Tab (First Tab)

```typescript
logicExplanation: {
  humanReadable: string;      // Full prose explanation
  conditions?: string[];      // Exact trigger conditions
  tuningGuidance?: string;    // How to reduce FPs
  whenToFire?: string;        // When the detection should fire
}
```

**Content:** Human-readable explanation, Exact Conditions (bullets), Tuning Guidance, When to Fire, "Copy full explanation" button

### Rule Format Tabs

- **Sigma** – Canonical format
- **CloudTrail Athena** – SQL for Athena
- **Splunk** – SIEM query
- **Lambda** – Python handler for EventBridge
- **More** – CloudWatch Insights, EventBridge pattern

Each tab has copy functionality and syntax highlighting.

---

## Phase 6: Testing the Detection

**Section title:** "Testing the Detection" (Phase 6)

Uses:
- `lifecycle.simulationCommand` – CLI command
- `detection.telemetry?.exampleEvent` – Expected log output
- `detection.testingSteps` – Validation steps

**Sub-headers:** Simulation, Expected Log Output, Validation Steps

---

## Phase 7: Deployment and CI/CD

**Section title:** "Deployment and CI/CD" (Phase 7)

```typescript
deployment: {
  whereItRuns: string[];      // Athena, Splunk, EventBridge, etc.
  scheduling?: string;        // Batch vs real-time
  considerations?: string[];  // Practical notes
}
```

**Sub-headers:** Where It Runs, Scheduling, Practical Considerations

---

## Detection Quality & Community

**Section title:** "Detection Quality & Community"

```typescript
quality: {
  signalQuality: number;        // 1–10
  falsePositiveRate: string;     // e.g. "Low (legitimate cleanup is rare)"
  expectedVolume: string;        // e.g. "1–10 events/month"
  productionReadiness: "experimental" | "validated" | "production";
}
communityConfidence: { accurate: number; needsTuning: number; noisy: number; }
```

Community voting: Accurate / Needs tuning / Noisy (stored in localStorage)

---

## Detection Coverage

**Section title:** "Detection Coverage"

Shown when the detection has linked techniques or attack paths (from `getTechniquesForDetection`, `getAttackPathsForDetection`).

- **Techniques Detected:** Card layout with category badge, name, truncated description
- **Related Attack Paths:** Table with Path, Severity, link

---

## Optional Base Fields

```typescript
telemetry?: TelemetrySource;       // For legacy layout
investigationSteps?: string[];     // SOC runbook
testingSteps?: string[];           // Lab validation steps
```

---

## Example: Minimal Lifecycle for New Detection

```typescript
{
  id: "det-XXX",
  title: "Your Detection Title",
  description: "Short technical description.",
  awsService: "EC2",
  relatedServices: [],
  severity: "High",
  tags: ["EC2", "VPC"],
  logSources: ["AWS CloudTrail"],
  falsePositives: ["Known automation"],
  rules: {
    sigma: `...`,
    cloudtrail: `SELECT ... FROM cloudtrail_logs WHERE ...`,
    splunk: `index=aws ...`,
    // lambda, cloudwatch, eventbridge optional
  },
  relatedAttackSlugs: [],
  telemetry: { primaryLogSource: "...", generatingService: "...", importantFields: [...], exampleEvent: "..." },
  investigationSteps: ["..."],
  testingSteps: ["..."],
  lifecycle: {
    whyItMatters: "One sentence on why this matters.",
    threatContext: { attackerBehavior: "...", whyItMatters: "...", riskAndImpact: "..." },
    telemetryValidation: { requiredLogSources: [...], requiredFields: [...], loggingRequirements: [...] },
    dataModeling: { rawToNormalized: [...], exampleNormalizedEvent: "..." },
    enrichment: [{ dimension: "...", description: "...", examples: [...], falsePositiveReduction: "..." }],
    logicExplanation: {
      humanReadable: "Full prose explanation.",
      conditions: ["eventSource equals X", "eventName equals Y"],
      tuningGuidance: "How to reduce FPs.",
      whenToFire: "When to fire.",
    },
    simulationCommand: "aws ec2 some-command ...",
    deployment: { whereItRuns: [...], scheduling: "...", considerations: [...] },
    quality: { signalQuality: 8, falsePositiveRate: "Low", expectedVolume: "1–10/month", productionReadiness: "validated" },
    communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
  },
}
```

---

## Reference Detection

**det-110 (VPC Flow Logs Deleted)** is the canonical example with full lifecycle content. Use it as a template when adding or updating detections.

---

## File Locations

- **Data:** `src/data/detections.ts`
- **UI:** `src/components/DetectionLifecycleSections.tsx`
- **Page:** `src/pages/DetectionEngineering.tsx`
