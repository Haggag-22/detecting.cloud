# Memory: index.md
Updated: now

# Detecting.Cloud Design System

- Theme: AWS-inspired colors — amber/yellow (HSL 43 96% 56%) as primary, blue (HSL 210 79% 46%) as accent
- Dark background: deep navy/charcoal (HSL 213 35% 7%)
- Fonts: Inter (display/body), JetBrains Mono (code)
- **No top navbar** — all navigation via persistent left sidebar on every page
- Sidebar includes: logo/brand, search, all nav links, theme toggle, social links in footer
- Sidebar persists expand state via sessionStorage
- Attack paths have categories: iam-abuse, privilege-escalation, persistence, lateral-movement, data-exfiltration
- Bidirectional mapping: attackPath.relatedDetectionIds ↔ detection.relatedAttackSlugs
- GitHub repo: Haggag-22/detecting.cloud
- Domain: detecting.cloud
