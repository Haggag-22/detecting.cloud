

# Implementation Plan

## Items to Build (2, 4, 5, 7)

### 1. Homepage Stats Bar (Item 5)
Add a stats section below the hero CTA buttons on `src/pages/Index.tsx` showing live counts from the data:
- Import `techniques`, `attackPaths`, `detections` and count unique AWS services
- Render 4 stat items in a horizontal row: "12 Techniques · 5 Attack Paths · 18 Detection Rules · 6 AWS Services"
- Styled as subtle muted text with a divider, using `motion` fade-in animation

### 2. Detection Coverage Dashboard (Item 2)
Create a new page at `/coverage` — `src/pages/Coverage.tsx`:
- Matrix grid: rows = techniques, columns = detection coverage status
- Each technique row shows: name, category badge (colored), services, and coverage indicators (green = has detections, red = no detections, yellow = partial)
- Coverage is computed by checking each technique's `detectionIds` array against actual detection data
- Filter bar: by AWS service and by attack category
- Clicking a technique links to `/attack-paths?technique=<id>`
- Add route in `App.tsx` and nav link in sidebar/navbar

### 3. Code Block Improvements (Item 4)
Update `src/pages/DetectionEngineering.tsx` detection rule code blocks (lines 164-176):
- Add a "Copy to clipboard" button in the code block header bar
- Use `navigator.clipboard.writeText()` with a toast notification on success
- Add basic syntax highlighting via CSS classes for YAML keywords (sigma) and SQL/SPL keywords — lightweight approach using a small helper function that wraps keywords in `<span>` tags, no heavy library needed

### 4. Export & Share (Item 7)
Add export buttons to the detection rule detail view in `src/pages/DetectionEngineering.tsx`:
- "Download as .yml" button for Sigma rules — creates a Blob and triggers download
- "Download as .spl" button for Splunk queries
- "Copy link" button that copies the current URL to clipboard
- Buttons placed in the rule header area, styled as outlined blue buttons

---

## Item 3: Technique Detail Pages — Design Preview

This is what dedicated technique pages at `/attack-paths/technique/:id` would look like:

```text
┌─────────────────────────────────────────────────┐
│ Attack Paths > Techniques > EC2 IMDS Theft      │  ← breadcrumb
├─────────────────────────────────────────────────┤
│ [KeyRound icon]  EC2 IMDS Credential Theft      │
│ Category: CREDENTIAL ACCESS (purple badge)      │
│                                                 │
│ Description paragraph...                        │
├────────────┬────────────┬───────────┬───────────┤
│ Services   │ Permissions│ Detections│ Category  │
│ EC2, IAM   │ (none)     │ 2 rules   │ Cred.Acc. │
├────────────┴────────────┴───────────┴───────────┤
│                                                 │
│ ▸ Required Permissions                          │
│   (list of IAM permissions)                     │
│                                                 │
│ ▸ Mitigations                                   │
│   • Enforce IMDSv2...                           │
│   • Apply least-privilege...                    │
│                                                 │
│ ▸ Detection Rules (linked)                      │
│   ┌─ det-014: IMDS v1 Access ──── High ──────┐ │
│   └─ det-015: EC2 Role Credential... ─────────┘ │
│                                                 │
│ ▸ Used in Attack Paths                          │
│   ┌─ EC2 IMDS to S3 Exfiltration ── Critical ┐ │
│   └─ ...                                      ┘ │
│                                                 │
│ ▸ Related Techniques (shared services)          │
│   PassRole Abuse, AssumeRole Abuse              │
└─────────────────────────────────────────────────┘
```

Each technique gets its own route `/attack-paths/technique/:id` with full cross-referencing to attack paths, detection rules, and related techniques. This would replace the current inline technique view on the attack paths page.

---

## Files to Create/Modify

| File | Action |
|------|--------|
| `src/pages/Coverage.tsx` | Create — coverage dashboard |
| `src/pages/Index.tsx` | Edit — add stats bar |
| `src/pages/DetectionEngineering.tsx` | Edit — copy button, export buttons |
| `src/App.tsx` | Edit — add `/coverage` route |
| `src/components/Navbar.tsx` | Edit — add Coverage nav link |
| `src/components/AppSidebar.tsx` | Edit — add Coverage sidebar link |

