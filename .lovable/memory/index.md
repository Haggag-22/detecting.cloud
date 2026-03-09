# Memory: index.md
Updated: now

# Detecting.Cloud Design System

- Theme: Blue accent for all interactive elements (buttons, links, nav). No amber/yellow for UI controls.
- Dark background: deep navy/charcoal (HSL 213 35% 7%)
- Fonts: Inter (display/body), JetBrains Mono (code)
- Gradient: blue→cyan (--gradient-start: 210 79% 46%, --gradient-end: 199 89% 48%)
- Global collapsible sidebar on content pages with nested accordion navigation
- Sidebar persists expand state via sessionStorage
- Homepage and About page have no sidebar

## Color Semantic System
- **Interactive (buttons/links)**: blue primary (HSL 210 79% 46%)
- **AWS services**: official AWS icons/colors only, neutral muted tags for service names
- **Severity**: Critical=red (--severity-critical), High=orange (--severity-high), Medium=yellow (--severity-medium)
- **Attack categories**: credential-access=purple, privilege-escalation=red, persistence=orange, lateral-movement=blue, exfiltration=green
- Category colors appear only on icons/badges, not row backgrounds

## Data
- Attack paths have objectives: credential-access, privilege-escalation, persistence, lateral-movement, exfiltration
- Bidirectional mapping: attackPath.relatedDetectionIds ↔ detection.relatedAttackSlugs
