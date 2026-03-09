# Memory: index.md
Updated: now

# Detecting.Cloud Design System

- Theme: AWS-inspired colors — amber/yellow (HSL 43 96% 56%) as primary, blue (HSL 210 79% 46%) as accent
- Dark background: professional deep navy (HSL 215 40% 6%)
- Fonts: Inter (display/body), JetBrains Mono (code)
- Global collapsible + resizable sidebar on content pages (Research, Attack Paths, Detection Engineering, Attack Graph)
- Sidebar persists expand state via sessionStorage
- Homepage and About page have no sidebar
- Labs section removed — platform focuses on Research, Attack Paths, Detection Engineering, Attack Graph

# Data Model (src/data/)

- **services.ts**: AwsService entity (id, name, shortName, description, category) + LogSource entity (id, name, description, awsServiceId)
- **detections.ts**: Detection entity with `awsService` (primary) + `relatedServices[]` (cross-service). `getDetectionsByService()` groups by primary + related.
- **attackPaths.ts**: AttackPath entity with `relatedDetectionIds[]` for bidirectional mapping
- Attack paths have categories: iam-abuse, privilege-escalation, persistence, lateral-movement, data-exfiltration
- Detection rules support 4 formats: sigma, splunk, cloudtrail (Athena), cloudwatch (Insights)
- Attack graph is search-driven: select a technique or detection rule to visualize focused relationships
- GitHub repo: https://github.com/Haggag-22/detecting.cloud
