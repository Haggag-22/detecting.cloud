import { Layout } from "@/components/Layout";
import {
  attackPaths,
  getAttackPathCloudProvider,
  getAttackPathCountsByCloudProvider,
} from "@/data/attackPaths";
import { Badge } from "@/components/ui/badge";
import {
  ChevronRight, AlertTriangle, Link as LinkIcon, Network, Play, Crosshair,
} from "lucide-react";
import { PageTitleWithIcon } from "@/components/PageTitleWithIcon";
import { useSearchParams, Link, Navigate } from "react-router-dom";
import { AttackFlowChain } from "@/components/AttackFlowChain";
import { CloudProviderTabs, parseCloudProviderId, type CloudProviderId } from "@/components/CloudProviderTabs";
import { SeverityPill } from "@/components/SeverityPill";

import { SEVERITY_BADGE_CLASS } from "@/lib/severityStyles";

const severityColor = SEVERITY_BADGE_CLASS;
function providerLabel(id: CloudProviderId): string | null {
  if (id === "all") return null;
  return id.toUpperCase();
}

const AttackPathsPage = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const techniqueParam = searchParams.get("technique");
  const activeProvider = parseCloudProviderId(searchParams.get("provider"));

  // Redirect old technique URLs to the new dedicated route
  if (techniqueParam?.startsWith("tech-")) {
    return <Navigate to={`/attack-paths/technique/${techniqueParam}`} replace />;
  }

  const setProvider = (id: CloudProviderId) => {
    const next = new URLSearchParams();
    if (id !== "all") next.set("provider", id);
    setSearchParams(next);
  };

  const scopedPaths =
    activeProvider === "all"
      ? attackPaths
      : attackPaths.filter((ap) => getAttackPathCloudProvider(ap) === activeProvider);
  const providerCounts = getAttackPathCountsByCloudProvider();

  // ─── Attack Path Detail View ───
  const activeAttackPath = techniqueParam
    ? attackPaths.find((a) => a.slug === techniqueParam)
    : null;

  if (activeAttackPath) {
    const label = providerLabel(getAttackPathCloudProvider(activeAttackPath));
    const listHref =
      getAttackPathCloudProvider(activeAttackPath) === "aws" && activeProvider === "all"
        ? "/attack-paths"
        : `/attack-paths?provider=${getAttackPathCloudProvider(activeAttackPath)}`;

    return (
      <Layout>
        <div className="container max-w-4xl">
          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-6">
            <Link to="/attack-paths" className="hover:text-foreground transition-colors">
              Attack Chains
            </Link>
            <ChevronRight className="h-3.5 w-3.5" />
            {label && (
              <>
                <Link to={listHref} className="hover:text-foreground transition-colors">
                  {label}
                </Link>
                <ChevronRight className="h-3.5 w-3.5" />
              </>
            )}
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
                  Simulate this Attack Chain
                </Link>
              </div>
            </div>

            {/* Visual Attack Flow */}
            <div>
              <h2 className="flex items-center gap-2 font-semibold mb-4">
                <AlertTriangle className="h-4 w-4 text-primary" /> Attack Flow
              </h2>
              <AttackFlowChain steps={activeAttackPath.steps} />
            </div>

            {/* References */}
            {activeAttackPath.references && activeAttackPath.references.length > 0 && (
              <div className="mt-6 rounded-lg border border-border/50 p-6 bg-card">
                <h2 className="flex items-center gap-2 font-semibold mb-4">
                  <LinkIcon className="h-4 w-4 text-primary" /> References
                </h2>
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
      <div className="container">
        <PageTitleWithIcon team="red" icon={Crosshair}>
          Attack Chains
        </PageTitleWithIcon>
        <p className="text-muted-foreground mb-6">
          Realistic attacker chains organized by cloud provider. Select a provider, then a chain to
          explore its technique steps.
        </p>

        <CloudProviderTabs
          value={activeProvider}
          counts={providerCounts}
          onChange={setProvider}
        />

        {scopedPaths.length > 0 ? (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {scopedPaths.map((ap) => (
              <Link
                key={ap.slug}
                to={`/attack-paths?technique=${ap.slug}`}
                className="flex flex-col h-full rounded-lg border border-border/50 bg-muted/20 p-4 hover:border-primary/30 transition-colors group"
              >
                <div className="flex items-start gap-2.5 mb-2">
                  <h3 className="font-semibold text-sm leading-snug flex-1 min-w-0 group-hover:text-primary transition-colors">
                    {ap.title}
                  </h3>
                  <SeverityPill severity={ap.severity} />
                </div>
                <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2 flex-1">
                  {ap.description}
                </p>
              </Link>
            ))}
          </div>
        ) : (
          <div className="rounded-lg border border-dashed border-border/50 bg-card/40 px-6 py-14 text-center">
            <p className="text-sm text-muted-foreground">
              {activeProvider === "all"
                ? "No attack chains yet."
                : `No ${activeProvider.toUpperCase()} attack chains yet. AWS chains are available under the AWS tab.`}
            </p>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default AttackPathsPage;
