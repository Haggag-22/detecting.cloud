# Memory: index.md
Updated: now

# Detecting.Cloud Design System

- Theme: Blue primary (HSL 210 79% 46%), blue accent same value. Homepage keeps its gradient (amber→blue) unchanged.
- Dark background: professional deep navy (HSL 215 40% 6%)
- Fonts: Inter (display/body), JetBrains Mono (code)
- Global collapsible + resizable sidebar on content pages (Attack Paths, Detection Engineering, Attack Graph)
- Sidebar persists expand state via sessionStorage
- Homepage and About page have no sidebar
- Research section removed from sidebar
- GitHub repo: https://github.com/Haggag-22/detecting.cloud

# Data Model (src/data/) — Knowledge Graph Architecture

- **techniques.ts**: Technique entity — reusable atomic attacker actions (id, name, services[], permissions[], detectionIds[], mitigations[], category)
- **attackPaths.ts**: AttackPath entity — chains of technique references via `steps: { techniqueId, context }[]`
- **detections.ts**: Detection entity with `awsService` (primary) + `relatedServices[]`. `getDetectionsByService()` groups by primary only.
- **services.ts**: AwsService + LogSource entities
- Techniques are reusable nodes that appear in multiple attack paths (no duplication)
- Attack paths are sequences of technique IDs — displayed as visual flow chains with arrows
- Technique pages show "Used in Attack Paths" section listing all chains containing that technique
- Detection rules support 4 formats: sigma, splunk, cloudtrail (Athena), cloudwatch (Insights)
- Attack graph visualizes technique nodes, attack path chains, detection rules, and AWS services
- Sidebar has separate "Attack Paths" (chains) and "Techniques" (by category) sections
