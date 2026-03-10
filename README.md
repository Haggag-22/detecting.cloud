# Detecting.Cloud

**Cloud Attack Research & Detection Engineering Platform**

[detecting.cloud](https://detecting.cloud) is an open-source platform focused on researching real-world cloud attack paths and building practical detection rules for defenders.

## What's Inside

- **Attack Paths** — Step-by-step breakdowns of real-world AWS attack chains
- **Detection Rules** — Ready-to-use rules in Sigma, Splunk, CloudTrail Lake, and CloudWatch Insights formats
- **Technique Library** — Categorized cloud attack techniques (credential access, privilege escalation, persistence, lateral movement, exfiltration)
- **Attack Simulator** — Visualize attack flows and understand kill chains
- **Attack Graph** — Interactive graph showing relationships between techniques, detections, and services
- **Detection Coverage** — See which techniques have detections and identify gaps
- **Gap Analysis** — Find blind spots in your detection coverage
- **Community Rules** — Community-contributed detection rules (see [CONTRIBUTING.md](CONTRIBUTING.md))
- **Tool Comparison** — Compare AWS security tools and services

## Tech Stack

- React + TypeScript + Vite
- Tailwind CSS + shadcn/ui
- Framer Motion
- React Flow (attack graphs)

## Contributing

We welcome community detection rules! See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on submitting rules via Pull Request.

## Local Development

```bash
git clone https://github.com/Haggag-22/detecting.cloud.git
cd detecting.cloud
npm install
npm run dev
```

## License

This project is open source. Detection rules are free to use in your security operations.
