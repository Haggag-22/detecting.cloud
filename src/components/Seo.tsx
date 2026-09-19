import { Helmet } from "react-helmet-async";
import { useLocation } from "react-router-dom";

const SITE = "https://detecting.cloud";
const SITE_NAME = "Detecting.Cloud";

type Meta = { title: string; description: string };

const ROUTE_META: Record<string, Meta> = {
  "/": {
    title: "Detecting.Cloud — Cloud Attack Research and Detection Rules",
    description:
      "Cloud attack paths, techniques, and production-ready detection rules for AWS, Azure, GCP, and Kubernetes defenders.",
  },
  "/attack-paths": {
    title: "AWS Attack Chains — Detecting.Cloud",
    description:
      "Step-by-step cloud attack chains showing how attackers move from initial access to impact, with the detections that catch each step.",
  },
  "/techniques": {
    title: "Cloud Attack Techniques Library — Detecting.Cloud",
    description:
      "Browse cloud attack techniques by category, service, and required IAM permissions, each mapped to detection coverage.",
  },
  "/detection-engineering": {
    title: "Detection Engineering Rules — Detecting.Cloud",
    description:
      "Sigma, Splunk, and Athena detection rules for cloud attacks, with log sources, tuning notes, and false-positive guidance.",
  },
  "/attack-graph": {
    title: "Cloud Attack Graph — Detecting.Cloud",
    description:
      "Interactive graph linking attack paths, techniques, cloud services, log sources, and detection rules.",
  },
  "/coverage": {
    title: "Detection Coverage Matrix — Detecting.Cloud",
    description:
      "See which cloud attack techniques have detection coverage and where the gaps are across services and categories.",
  },
  "/threat-matrix": {
    title: "Cloud Threat Matrix — Detecting.Cloud",
    description:
      "A tactic-by-tactic threat matrix of cloud attacker behaviour mapped to detection rules.",
  },
  "/simulator": {
    title: "Attack Path Simulator — Detecting.Cloud",
    description:
      "Walk through a cloud attack chain step by step and see exactly which detections would fire at each stage.",
  },
  "/cloudtrail-analyzer": {
    title: "CloudTrail Analyzer — Detecting.Cloud",
    description:
      "Upload AWS CloudTrail events and match them against attack techniques and detection rules in the browser.",
  },
  "/community-rules": {
    title: "Community Detection Rules — Detecting.Cloud",
    description:
      "Community-contributed cloud detection rules, reviewed and published through pull requests.",
  },
  "/about": {
    title: "About — Detecting.Cloud",
    description:
      "Why Detecting.Cloud exists: open cloud attack research and practical detection engineering for defenders.",
  },
};

const FALLBACK: Meta = ROUTE_META["/"];

export function Seo({ title, description }: Partial<Meta> = {}) {
  const { pathname } = useLocation();
  const base = ROUTE_META[pathname] ?? FALLBACK;
  const finalTitle = title ?? base.title;
  const finalDescription = description ?? base.description;
  const url = `${SITE}${pathname === "/" ? "/" : pathname}`;

  return (
    <Helmet>
      <title>{finalTitle}</title>
      <meta name="description" content={finalDescription} />
      <link rel="canonical" href={url} />
      <meta property="og:site_name" content={SITE_NAME} />
      <meta property="og:type" content="website" />
      <meta property="og:title" content={finalTitle} />
      <meta property="og:description" content={finalDescription} />
      <meta property="og:url" content={url} />
      <meta name="twitter:title" content={finalTitle} />
      <meta name="twitter:description" content={finalDescription} />
    </Helmet>
  );
}
