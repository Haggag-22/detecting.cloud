# Memory: index.md
Updated: now

# Detecting.Cloud Design System

- Theme: AWS-inspired colors — amber/yellow (HSL 43 96% 56%) as primary, blue (HSL 210 79% 46%) as accent
- Dark background: deep navy/charcoal (HSL 215 40% 6%)
- Fonts: Inter (display/body), JetBrains Mono (code)
- Global collapsible sidebar on content pages (Research, Attack Paths, Detection Engineering, Attack Graph) with nested accordion navigation
- Sidebar persists expand state via sessionStorage
- Homepage and About page have no sidebar
- Labs section REMOVED — platform focuses on Research, Attack Paths, Detection Engineering, Attack Graph
- Attack paths have categories: iam-abuse, privilege-escalation, persistence, lateral-movement, data-exfiltration
- Bidirectional mapping: attackPath.relatedDetectionIds ↔ detection.relatedAttackSlugs
- Detection rules organized by AWS service (IAM, Lambda, EC2, S3, EBS, DynamoDB, CloudTrail, KMS, EKS)
- Detection rules support multiple formats: Sigma, Splunk, CloudTrail Athena, CloudWatch Insights (tabs)
- Custom AWS service SVG icons in src/components/AwsIcons.tsx
- Logo: uploaded cloud icon at src/assets/logo.jpeg and public/logo.jpeg
