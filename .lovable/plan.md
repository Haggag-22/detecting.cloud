

# Plan: 8 Feature Additions for Detecting.Cloud

This is a large scope. I recommend implementing in 3 phases across multiple prompts. Here is the full plan:

---

## Phase 1 — Quick Wins (features 8, 14, 3)

### Feature 8: Dark/Light Theme Toggle
- Add a theme toggle button (Sun/Moon icon) to the `Navbar` next to the search/GitHub icons
- Use `next-themes` (already installed) with `ThemeProvider` wrapping the app
- Add a `:root` light theme to `index.css` alongside the existing dark theme (current dark becomes default)
- Light theme: white backgrounds, dark text, adjusted card/border/muted colors

### Feature 14: Search & Filter Improvements
- Add a global search shortcut (Cmd/Ctrl+K) that opens the existing `SearchDialog`
- Enhance `SearchDialog` to search across techniques, detections, and attack paths (currently limited)
- Add severity and service filter dropdowns to the Attack Paths list page
- Add a search bar to the Coverage page

### Feature 3: CloudTrail Log Samples
- Add a `cloudtrailSample` field to the `Technique` interface in `src/data/techniques.ts`
- Each technique gets a realistic raw CloudTrail JSON snippet showing what the event looks like
- Render on `TechniqueDetail.tsx` as a collapsible "CloudTrail Event Sample" section with syntax highlighting and a copy button
- Reuse the same code block pattern from `DetectionEngineering.tsx`

---

## Phase 2 — Analytical Features (features 7, 1)

### Feature 7: Detection Gap Analysis Tool
- New page at `/gap-analysis` with route in `App.tsx`
- Cross-references all techniques against detections to identify:
  - Techniques with zero detection rules
  - Categories with lowest coverage percentages
  - Services with no detection coverage
- Visual summary: bar chart (recharts) showing coverage % per category
- Actionable table listing uncovered techniques with "priority score" based on severity of attack paths they appear in
- Add to navbar and sidebar navigation

### Feature 1: Expand AWS Service Coverage
- Add new techniques to `src/data/techniques.ts` for ECS, EKS, Secrets Manager, SSM, and Organizations:
  - `tech-ecs-task-hijack` — ECS task definition modification
  - `tech-eks-rbac-abuse` — EKS RBAC privilege escalation
  - `tech-secrets-manager-theft` — Secrets Manager secret extraction
  - `tech-ssm-command-execution` — SSM Run Command lateral movement
  - `tech-org-scp-bypass` — Organizations SCP modification
- Add corresponding detection rules to `src/data/detections.ts`
- Add new AWS service icons to `AwsIcons.tsx`
- These automatically appear in sidebar, coverage matrix, and search

---

## Phase 3 — Interactive & Community (features 5, 12, 13)

### Feature 5: Attack Path Simulator
- New page at `/simulator` with route in `App.tsx`
- Interactive step-by-step walkthrough:
  - User picks a starting technique (e.g., IMDS theft)
  - Shows available "next moves" based on what permissions are gained
  - Each step shows: permissions acquired, services accessible, detection rules that would fire
  - Visual chain builds as user progresses (reuse `AttackFlowChain` component)
- Uses existing technique data — no backend needed
- "Score" at end showing how many detections would have caught the attack

### Feature 12: Community Rule Submissions
- New page at `/community` showing community-contributed detection rules
- Since there's no backend, implement as:
  - A curated `src/data/communityRules.ts` data file
  - "Submit a Rule" button links to a GitHub issue template URL
  - Display community rules in same format as detection rules with author attribution
  - Badge system: "Community" vs "Official" on detection cards

### Feature 13: Tool Comparison Matrices
- New page at `/tools` comparing security tools and their detection capabilities
- Data in `src/data/tools.ts` with entries for: GuardDuty, Security Hub, Prowler, ScoutSuite, Steampipe, CloudQuery
- Matrix table: rows = techniques, columns = tools, cells = supported/partial/none
- Filter by category and service
- Each tool gets a card with description, pricing model, and link

---

## Files to Create
- `src/pages/GapAnalysis.tsx`
- `src/pages/Simulator.tsx`
- `src/pages/Community.tsx`
- `src/pages/Tools.tsx`
- `src/data/communityRules.ts`
- `src/data/tools.ts`
- `src/components/ThemeToggle.tsx`

## Files to Modify
- `src/App.tsx` — add 4 new routes
- `src/main.tsx` — wrap with ThemeProvider
- `src/index.css` — add light theme variables
- `src/components/Navbar.tsx` — add theme toggle, new nav links
- `src/components/AppSidebar.tsx` — add new sections
- `src/data/techniques.ts` — add CloudTrail samples + new techniques
- `src/data/detections.ts` — add new detection rules
- `src/components/AwsIcons.tsx` — add ECS/EKS/SSM/SecretsManager icons
- `src/components/SearchDialog.tsx` — enhanced search
- `src/pages/TechniqueDetail.tsx` — CloudTrail sample section
- `src/pages/AttackPaths.tsx` — add filters
- `src/pages/Coverage.tsx` — add search bar

---

## Recommended Approach
Given the size, I suggest building **Phase 1 first** (theme toggle, search improvements, CloudTrail samples), then Phase 2, then Phase 3. Each phase is one prompt. Shall I start with Phase 1?

