# Contributing to Detecting.Cloud

Thanks for your interest in contributing detection rules! This guide explains how to submit community detection rules via Pull Request.

## How to Contribute a Detection Rule

### 1. Fork & Clone

```bash
git clone https://github.com/YOUR-USERNAME/detecting.cloud.git
cd detecting.cloud
npm install
```

### 2. Add Your Community Rule

> **Important**: Community rules go in `src/data/communityRules.ts` — NOT in `src/data/detections.ts` (which contains the core platform rules maintained by the project owner).

Add a new entry to the `communityRules` array in `src/data/communityRules.ts`:

```typescript
{
  id: "cr-XXX",                // Use next available number (e.g., cr-007)
  title: "Your Rule Title",
  description: "What this rule detects and why it matters.",
  author: "YourGitHubUsername",
  awsService: "IAM",           // Primary AWS service (IAM, S3, EC2, Lambda, KMS, etc.)
  severity: "High",            // Critical | High | Medium | Low
  format: "sigma",             // sigma | splunk | cloudtrail | cloudwatch
  rule: `your detection rule query here`,
  votes: 0,
  createdAt: "YYYY-MM-DD",     // Today's date
  tags: ["IAM", "Persistence"],
}
```

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

Navigate to the **Community Rules** page and verify your rule appears correctly.

### 4. Submit a Pull Request

- Push your changes to your fork
- Open a PR against the `main` branch of `Haggag-22/detecting.cloud`
- **Only modify `src/data/communityRules.ts`** — PRs touching other files will be rejected
- Include a brief description of what the rule detects
- Reference any MITRE ATT&CK technique IDs if applicable

## Project Structure (for reference)

```
src/data/
├── communityRules.ts   ← ADD YOUR RULES HERE
├── detections.ts       ← Core rules (do NOT modify)
├── techniques.ts       ← Technique library (do NOT modify)
├── attackPaths.ts      ← Attack paths (do NOT modify)
└── services.ts         ← AWS services (do NOT modify)
```

## Code of Conduct

- Submit only original or properly attributed detection rules
- Ensure rules are relevant to AWS cloud security
- No malicious or offensive content
- Be respectful in PR discussions

## Questions?

Open an [issue](https://github.com/Haggag-22/detecting.cloud/issues) on the repo.
