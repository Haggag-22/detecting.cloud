import { Layout } from "@/components/Layout";
import { useParams, Link } from "react-router-dom";
import { getTechniqueById, techniqueCategories } from "@/data/techniques";
import { getAttackPathsForTechnique } from "@/data/attackPaths";
import { detections } from "@/data/detections";
import { Badge } from "@/components/ui/badge";
import {
  ChevronRight, Shield, Link as LinkIcon, Network, Crosshair,
  KeyRound, TrendingUp, Server, Wifi, Database, ShieldOff, Lock,
  FileJson, Copy, Check,
} from "lucide-react";
import { useState } from "react";
import { LucideIcon } from "lucide-react";
import { LucideIcon } from "lucide-react";

const categoryIcon: Record<string, LucideIcon> = {
  "initial-access": Crosshair,
  "credential-access": KeyRound,
  "privilege-escalation": TrendingUp,
  "persistence": Server,
  "lateral-movement": Wifi,
  "exfiltration": Database,
  "defense-evasion": ShieldOff,
};

const categoryIconColor: Record<string, string> = {
  "initial-access": "text-muted-foreground",
  "credential-access": "text-purple-400",
  "privilege-escalation": "text-red-400",
  "persistence": "text-orange-400",
  "lateral-movement": "text-blue-400",
  "exfiltration": "text-emerald-400",
  "defense-evasion": "text-muted-foreground",
};

const categoryColor: Record<string, string> = {
  "initial-access": "bg-muted text-muted-foreground",
  "credential-access": "bg-purple-500/15 text-purple-400",
  "privilege-escalation": "bg-red-500/15 text-red-400",
  "persistence": "bg-orange-500/15 text-orange-400",
  "lateral-movement": "bg-blue-500/15 text-blue-400",
  "exfiltration": "bg-emerald-500/15 text-emerald-400",
  "defense-evasion": "bg-muted text-muted-foreground",
};

const severityColor: Record<string, string> = {
  Critical: "bg-severity-critical/15 text-severity-critical",
  High: "bg-severity-high/15 text-severity-high",
  Medium: "bg-severity-medium/15 text-severity-medium",
};

const TechniqueDetailPage = () => {
  const { id } = useParams<{ id: string }>();
  const technique = id ? getTechniqueById(id) : null;

  if (!technique) {
    return (
      <Layout>
        <div className="container py-12 text-center">
          <h1 className="font-display text-2xl font-bold mb-4">Technique Not Found</h1>
          <Link to="/attack-paths" className="text-primary hover:underline">← Back to Attack Paths</Link>
        </div>
      </Layout>
    );
  }

  const usedInPaths = getAttackPathsForTechnique(technique.id);
  const relatedDetections = detections.filter((d) => technique.detectionIds.includes(d.id));
  const CatIcon = categoryIcon[technique.category];

  return (
    <Layout>
      <div className="container py-12 max-w-4xl">
        {/* Breadcrumb */}
        <div className="flex items-center gap-2 text-sm text-muted-foreground mb-6">
          <Link to="/attack-paths" className="hover:text-foreground transition-colors">Attack Paths</Link>
          <ChevronRight className="h-3.5 w-3.5" />
          <span className="text-muted-foreground">Techniques</span>
          <ChevronRight className="h-3.5 w-3.5" />
          <span className="text-foreground">{technique.name}</span>
        </div>

        {/* Header */}
        <div className="mb-8">
          <div className="flex flex-wrap gap-2 mb-3">
            <Badge className={`text-xs border-0 uppercase tracking-wide flex items-center gap-1 ${categoryColor[technique.category]}`}>
              {CatIcon && <CatIcon className={`h-3 w-3 ${categoryIconColor[technique.category]}`} />}
              {techniqueCategories[technique.category].label}
            </Badge>
            {technique.services.map((svc) => (
              <Badge key={svc} variant="outline" className="text-xs border-border text-muted-foreground">{svc}</Badge>
            ))}
          </div>
          <h1 className="font-display text-3xl font-bold mb-3">{technique.name}</h1>
          <p className="text-muted-foreground leading-relaxed mb-4">{technique.description}</p>
          <Link
            to={`/attack-graph?technique=${technique.id}`}
            className="inline-flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-2 text-sm font-medium text-destructive hover:bg-destructive/20 transition-colors"
          >
            <Network className="h-4 w-4" />
            View in Attack Graph
          </Link>
        </div>

        {/* Summary Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
          <div className="rounded-lg border border-border/50 bg-card p-4">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Category</p>
            <div className="flex items-center gap-1.5">
              {CatIcon && <CatIcon className={`h-4 w-4 ${categoryIconColor[technique.category]}`} />}
              <span className="font-medium text-sm">{techniqueCategories[technique.category].label}</span>
            </div>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Services</p>
            <p className="text-sm font-medium">{technique.services.join(", ")}</p>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Detections</p>
            <p className="text-sm font-medium">{relatedDetections.length} rules</p>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Attack Paths</p>
            <p className="text-sm font-medium">{usedInPaths.length} chains</p>
          </div>
        </div>

        {/* Required Permissions */}
        {technique.permissions.length > 0 && (
          <div className="mb-8">
            <h2 className="flex items-center gap-2 font-display text-lg font-semibold mb-3">
              <Lock className="h-4 w-4 text-primary" /> Required Permissions
            </h2>
            <div className="flex flex-wrap gap-2">
              {technique.permissions.map((p) => (
                <code key={p} className="px-2.5 py-1.5 rounded-md bg-muted text-xs font-mono text-primary border border-border/50">
                  {p}
                </code>
              ))}
            </div>
          </div>
        )}

        {/* Mitigations */}
        <div className="mb-8">
          <h2 className="flex items-center gap-2 font-display text-lg font-semibold mb-3">
            <Shield className="h-4 w-4 text-emerald-400" /> Mitigations
          </h2>
          <ul className="space-y-2">
            {technique.mitigations.map((m, i) => (
              <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                <span className="text-emerald-400 mt-0.5">•</span> {m}
              </li>
            ))}
          </ul>
        </div>

        {/* Detection Rules */}
        {relatedDetections.length > 0 && (
          <div className="border-t border-border pt-6 mb-8">
            <h2 className="flex items-center gap-2 font-display text-lg font-semibold mb-4">
              <LinkIcon className="h-4 w-4 text-accent" /> Detection Rules
            </h2>
            <div className="space-y-3">
              {relatedDetections.map((det) => (
                <Link
                  key={det.id}
                  to={`/detection-engineering?rule=${det.id}`}
                  className="block rounded-lg border border-border/50 bg-card p-4 hover:border-primary/30 transition-colors"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Badge variant="outline" className="text-xs border-border text-muted-foreground">{det.awsService}</Badge>
                    <span className="font-medium text-sm">{det.title}</span>
                    <Badge className={`text-xs border-0 ml-auto ${severityColor[det.severity]}`}>{det.severity}</Badge>
                  </div>
                  <p className="text-xs text-muted-foreground">{det.description}</p>
                </Link>
              ))}
            </div>
          </div>
        )}

        {/* Used in Attack Paths */}
        {usedInPaths.length > 0 && (
          <div className="border-t border-border pt-6 mb-8">
            <h2 className="flex items-center gap-2 font-display text-lg font-semibold mb-4">
              <Crosshair className="h-4 w-4 text-destructive" /> Used in Attack Paths
            </h2>
            <div className="space-y-3">
              {usedInPaths.map((ap) => (
                <Link
                  key={ap.slug}
                  to={`/attack-paths?technique=${ap.slug}`}
                  className="block rounded-lg border border-border/50 bg-card p-4 hover:border-primary/30 transition-colors"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Badge className={`text-xs border-0 ${severityColor[ap.severity]}`}>{ap.severity}</Badge>
                    <span className="font-medium text-sm">{ap.title}</span>
                  </div>
                  <p className="text-xs text-muted-foreground">{ap.description}</p>
                </Link>
              ))}
            </div>
          </div>
        )}

        {/* CloudTrail Sample */}
        {technique.cloudtrailSample && (
          <CloudTrailSample sample={technique.cloudtrailSample} />
        )}

        {/* Related Techniques */}
        {relatedTechniques.length > 0 && (
          <div className="border-t border-border pt-6 mb-8">
            <h2 className="flex items-center gap-2 font-display text-lg font-semibold mb-4">
              <Layers className="h-4 w-4 text-muted-foreground" /> Related Techniques
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {relatedTechniques.slice(0, 4).map((rt) => (
                <Link
                  key={rt.id}
                  to={`/attack-paths/technique/${rt.id}`}
                  className="block rounded-lg border border-border/50 bg-card p-3 hover:border-primary/30 transition-colors"
                >
                  <Badge className={`text-[10px] border-0 mb-1 ${categoryColor[rt.category]}`}>
                    {techniqueCategories[rt.category].label}
                  </Badge>
                  <p className="text-sm font-medium">{rt.name}</p>
                </Link>
              ))}
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
};

function CloudTrailSample({ sample }: { sample: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(sample);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="border-t border-border pt-6 mb-8">
      <h2 className="flex items-center gap-2 font-display text-lg font-semibold mb-3">
        <FileJson className="h-4 w-4 text-primary" /> CloudTrail Event Sample
      </h2>
      <p className="text-xs text-muted-foreground mb-3">
        Example CloudTrail log event showing what this technique looks like in your logs.
      </p>
      <div className="relative rounded-lg border border-border/50 bg-muted overflow-hidden">
        <div className="flex items-center justify-between px-4 py-2 border-b border-border/50 bg-card">
          <span className="text-xs font-mono text-muted-foreground">CloudTrail JSON</span>
          <button
            onClick={handleCopy}
            className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
            {copied ? "Copied" : "Copy"}
          </button>
        </div>
        <pre className="p-4 overflow-x-auto text-xs font-mono leading-relaxed text-foreground">
          {sample}
        </pre>
      </div>
    </div>
  );
}

export default TechniqueDetailPage;
