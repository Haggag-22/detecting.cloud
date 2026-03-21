import { useState } from "react";
import { Layout } from "@/components/Layout";
import { attackPaths } from "@/data/attackPaths";
import { getTechniqueById } from "@/data/techniques";
import { Badge } from "@/components/ui/badge";
import {
  ChevronRight, AlertTriangle, Link as LinkIcon, Network, Play, Crosshair,
} from "lucide-react";
import { PageTitleWithIcon } from "@/components/PageTitleWithIcon";
import { useSearchParams, Link, Navigate } from "react-router-dom";
import { AttackFlowChain } from "@/components/AttackFlowChain";

const severityColor: Record<string, string> = {
  Critical: "bg-severity-critical/15 text-severity-critical",
  High: "bg-severity-high/15 text-severity-high",
  Medium: "bg-severity-medium/15 text-severity-medium",
};

const AttackPathsPage = () => {
  const [searchParams] = useSearchParams();
  const techniqueParam = searchParams.get("technique");

  // Redirect old technique URLs to the new dedicated route
  if (techniqueParam?.startsWith("tech-")) {
    return <Navigate to={`/attack-paths/technique/${techniqueParam}`} replace />;
  }

  // ─── Attack Path Detail View ───
  const activeAttackPath = techniqueParam
    ? attackPaths.find((a) => a.slug === techniqueParam)
    : null;

  if (activeAttackPath) {
    return (
      <Layout>
        <div className="container py-12 max-w-4xl">
          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-6">
            <Link to="/attack-paths" className="hover:text-foreground transition-colors">
              Attack Paths
            </Link>
            <ChevronRight className="h-3.5 w-3.5" />
            <span className="text-foreground">{activeAttackPath.title}</span>
          </div>

          <div className="space-y-6">
            <div>
              <div className="flex flex-wrap gap-2 mb-3">
                <Badge className={`text-xs border-0 ${severityColor[activeAttackPath.severity]}`}>
                  {activeAttackPath.severity}
                </Badge>
                {activeAttackPath.tags.map((tag) => (
                  <Badge key={tag} variant="outline" className="text-xs border-border text-muted-foreground">
                    {tag}
                  </Badge>
                ))}
              </div>
              <PageTitleWithIcon team="red" icon={Crosshair} className="mb-3">
                {activeAttackPath.title}
              </PageTitleWithIcon>
              <p className="text-muted-foreground mb-4">{activeAttackPath.description}</p>
              <div className="flex flex-wrap gap-3">
                <Link
                  to={`/attack-graph?technique=${activeAttackPath.slug}`}
                  className="inline-flex items-center gap-2 rounded-lg border border-destructive/30 bg-destructive/10 px-4 py-2 text-sm font-medium text-destructive hover:bg-destructive/20 transition-colors"
                >
                  <Network className="h-4 w-4" />
                  View in Attack Graph
                </Link>
                <Link
                  to={`/simulator?path=${activeAttackPath.slug}`}
                  className="inline-flex items-center gap-2 rounded-lg border border-primary/30 bg-primary/10 px-4 py-2 text-sm font-medium text-primary hover:bg-primary/20 transition-colors"
                >
                  <Play className="h-4 w-4" />
                  Simulate this Attack Path
                </Link>
              </div>
            </div>

            {/* Visual Attack Flow */}
            <div>
              <h3 className="flex items-center gap-2 font-semibold mb-4">
                <AlertTriangle className="h-4 w-4 text-primary" /> Attack Flow
              </h3>
              <AttackFlowChain steps={activeAttackPath.steps} />
            </div>

            {/* References */}
            {activeAttackPath.references && activeAttackPath.references.length > 0 && (
              <div className="mt-6 rounded-lg border border-border p-6 bg-card">
                <h3 className="flex items-center gap-2 font-semibold mb-4">
                  <LinkIcon className="h-4 w-4 text-primary" /> References
                </h3>
                <ul className="space-y-2">
                  {activeAttackPath.references.map((ref, i) => (
                    <li key={i} className="text-sm text-muted-foreground flex items-center gap-2">
                      <span>{ref.source}</span>
                      {ref.url && (
                        <>
                          <span className="text-muted-foreground/50">—</span>
                          <a href={ref.url} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline break-all">
                            {ref.url}
                          </a>
                        </>
                      )}
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </div>
        </div>
      </Layout>
    );
  }

  // ─── List View ───
  return (
    <Layout>
      <div className="container py-12">
        <PageTitleWithIcon team="red" icon={Crosshair}>
          Attack Paths
        </PageTitleWithIcon>
        <p className="text-muted-foreground mb-8">
          Realistic attacker chains in cloud environments. Each path is composed of reusable technique steps that can be explored individually.
        </p>

        {/* Attack Paths */}
        <div className="mb-12">
          <h2 className="text-xs uppercase tracking-wider text-muted-foreground font-medium mb-4">
            Attack Chains
          </h2>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {attackPaths.map((ap) => (
              <Link
                key={ap.slug}
                to={`/attack-paths?technique=${ap.slug}`}
                className="rounded-lg border border-border/50 bg-card p-5 hover:border-primary/30 transition-colors group"
              >
                <div className="flex gap-2 mb-2">
                  <Badge className={`text-xs border-0 ${severityColor[ap.severity]}`}>
                    {ap.severity}
                  </Badge>
                </div>
                <h3 className="font-semibold text-sm mb-1 group-hover:text-primary transition-colors">{ap.title}</h3>
                <p className="text-xs text-muted-foreground line-clamp-2 mb-3">{ap.description}</p>
                {/* Mini flow preview */}
                <div className="flex items-center gap-1.5 flex-wrap">
                  {ap.steps.map((step, i) => {
                    const tech = getTechniqueById(step.techniqueId);
                    return (
                      <span key={i} className="flex items-center gap-1.5">
                        <span className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-mono">
                          {tech?.name || "?"}
                        </span>
                        {i < ap.steps.length - 1 && (
                          <ChevronRight className="h-3 w-3 text-muted-foreground/50" />
                        )}
                      </span>
                    );
                  })}
                </div>
              </Link>
            ))}
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default AttackPathsPage;
