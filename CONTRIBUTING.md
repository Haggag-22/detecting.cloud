# Contributing to Detecting.Cloud

Thanks for your interest in contributing detection rules! This guide explains how to submit community detection rules via Pull Request.

## How to Contribute a Detection Rule

### 1. Fork & Clone
```bash
git clone https://github.com/YOUR-USERNAME/detecting.cloud.git
cd detecting.cloud
npm install
```

### 2. Add Your Detection Rule

Edit `src/data/detections.ts` and add a new entry to the `detections` array.

Each detection rule follows this structure:

```typescript
{
  id: "det-XXX",              // Unique ID (use next available number)
  title: "Your Rule Title",
  description: "What this rule detects and why it matters.",
  awsService: "IAM",          // Primary AWS service (e.g., IAM, S3, EC2, Lambda, STS, etc.)
  relatedServices: ["Lambda"], // Other AWS services involved
  severity: "High",           // Critical | High | Medium | Low
  tags: ["IAM", "Persistence"],
  logSources: ["AWS CloudTrail"],
  falsePositives: ["Describe legitimate scenarios that could trigger this rule"],
  rules: {
    sigma: `your sigma rule here`,
    splunk: `your splunk query here`,
    cloudtrail: `your CloudTrail Lake SQL query here`,
    cloudwatch: `your CloudWatch Insights query here`,
  },
  relatedAttackSlugs: [],     // Related attack path slugs (if any)
}
```

### Rule Format Guidelines

- **At least one** rule format is required (sigma, splunk, cloudtrail, or cloudwatch)
- All four formats are preferred but not mandatory
- Use realistic, tested queries when possible
- Follow existing rules as examples

### Severity Levels

| Severity | Use When |
|----------|----------|
| **Critical** | Direct privilege escalation, credential theft, or data exfiltration |
| **High** | Significant security risk, persistence mechanisms |
| **Medium** | Suspicious activity that needs investigation |
| **Low** | Informational, minor policy violations |

### 3. Test Locally
```bash
npm run dev
```
Navigate to the Detection Engineering page and verify your rule appears correctly.

### 4. Submit a Pull Request
- Push your changes to your fork
- Open a PR against `main` branch of `Haggag-22/detecting.cloud`
- Include a brief description of what the rule detects
- Reference any MITRE ATT&CK technique IDs if applicable

## Code of Conduct

- Submit only original or properly attributed detection rules
- Ensure rules are relevant to AWS cloud security
- No malicious or offensive content
- Be respectful in PR discussions

## Questions?

Open an issue on the repo or reach out via the platform.
