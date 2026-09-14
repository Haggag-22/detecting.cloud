import { useState, useMemo, useRef } from "react";
import { Layout } from "@/components/Layout";
import { techniques, techniqueCategories, type TechniqueCategory } from "@/data/techniques";
import {
  detections,
  getDetectionsByService,
  getDetectionCountsByCloudProvider,
} from "@/data/detections";
import { attackPaths } from "@/data/attackPaths";
import { Badge } from "@/components/ui/badge";
import { Link } from "react-router-dom";
import {
  CheckCircle2, XCircle, AlertCircle, AlertTriangle, Filter, Search,
  BarChart3, ChevronRight,
} from "lucide-react";
import { PageTitleWithIcon } from "@/components/PageTitleWithIcon";
import { getServiceIconOrFallback } from "@/components/AwsIcons";
import { CloudProviderTabs, type CloudProviderId } from "@/components/CloudProviderTabs";
import { getServiceCardClassName } from "@/lib/serviceCardColors";
import { CountBadge } from "@/components/CountBadge";
import { cn } from "@/lib/utils";

const categoryColors: Record<TechniqueCategory, string> = {
  "initial-access": "bg-cyan-500/15 text-cyan-400",
  "credential-access": "bg-purple-500/15 text-purple-400",
  "privilege-escalation": "bg-red-500/15 text-red-400",
  "persistence": "bg-orange-500/15 text-orange-400",
  "lateral-movement": "bg-blue-500/15 text-blue-400",
  "exfiltration": "bg-emerald-500/15 text-emerald-400",
  "defense-evasion": "bg-amber-500/15 text-amber-400",
};

type CoverageStatus = "covered" | "partial" | "none";

function getCoverageStatus(detectionIds: string[]): CoverageStatus {
  if (detectionIds.length === 0) return "none";
  const matchedCount = detectionIds.filter((id) =>
    detections.some((d) => d.id === id)
  ).length;
  if (matchedCount === 0) return "none";
  if (matchedCount < detectionIds.length) return "partial";
  return "covered";
}

/** Technique service labels that map to a Detection Rules primary service */
function techniqueMatchesService(techniqueServices: string[], detectionService: string): boolean {
  const aliases =
    detectionService === "Route 53"
      ? ["Route 53", "Route53"]
      : detectionService === "Secrets Manager"
        ? ["Secrets Manager", "SecretsManager"]
        : detectionService === "IAM"
          ? ["IAM", "STS", "IAM Identity Center", "Directory Service", "SSO"]
          : [detectionService];
  return techniqueServices.some((s) => aliases.includes(s));
}

/** Coverage matrix uses AWS attack techniques only — hide other providers for now */
const COVERAGE_PROVIDER_TABS: CloudProviderId[] = ["all", "aws"];

const CoveragePage = () => {
  const [categoryFilter, setCategoryFilter] = useState<TechniqueCategory | "all">("all");
  const [serviceFilter, setServiceFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [serviceSearch, setServiceSearch] = useState("");
  const [provider, setProvider] = useState<CloudProviderId>("all");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");
  const matrixRef = useRef<HTMLDivElement>(null);

  const coverageProvider: CloudProviderId = COVERAGE_PROVIDER_TABS.includes(provider)
    ? provider
    : "all";

  const providerCounts = getDetectionCountsByCloudProvider();
  const detectionsByService = useMemo(
    () => getDetectionsByService(coverageProvider === "all" ? "all" : coverageProvider),
    [coverageProvider]
  );

  const analysis = useMemo(() => {
    // Same service categories as Detection Rules (primary awsService grouping)
    const services = Object.entries(detectionsByService).map(([service, rules]) => {
      const ruleIds = new Set(rules.map((r) => r.id));
      const svcTechs = techniques.filter(
        (t) =>
          techniqueMatchesService(t.services, service) ||
          t.detectionIds.some((id) => ruleIds.has(id))
      );
      const covered = svcTechs.filter((t) => getCoverageStatus(t.detectionIds) !== "none").length;
      const total = svcTechs.length;
      const pct = total > 0 ? Math.round((covered / total) * 100) : 0;
      return {
        service,
        ruleCount: rules.length,
        covered,
        total,
        pct,
      };
    });

    const partialTechs = techniques
      .filter((t) => getCoverageStatus(t.detectionIds) === "partial")
      .map((t) => {
        const matched = t.detectionIds.filter((id) => detections.some((d) => d.id === id)).length;
        return { ...t, matchedCount: matched, totalDetections: t.detectionIds.length };
      });

    const totalTechs = techniques.length;
    const totalCovered = techniques.filter((t) => getCoverageStatus(t.detectionIds) === "covered").length;
    const totalPartial = techniques.filter((t) => getCoverageStatus(t.detectionIds) === "partial").length;
    const totalNone = totalTechs - totalCovered - totalPartial;
    const overallPct = Math.round(((totalCovered + totalPartial * 0.5) / totalTechs) * 100);

    return { services, partialTechs, totalTechs, totalCovered, totalPartial, totalNone, overallPct };
  }, [detectionsByService]);

  const techniquesWithMeta = useMemo(() => {
    return techniques.map((t) => {
      const status = getCoverageStatus(t.detectionIds);
      const appearsIn = attackPaths.filter((ap) => ap.steps.some((s) => s.techniqueId === t.id));
      const pathCount = appearsIn.length;
      return { ...t, status, pathCount };
    });
  }, [attackPaths]);

  const filtered = techniquesWithMeta.filter((t) => {
    if (categoryFilter !== "all" && t.category !== categoryFilter) return false;
    if (serviceFilter !== "all") {
      const rules = detectionsByService[serviceFilter] ?? detections.filter((d) => d.awsService === serviceFilter);
      const ruleIds = new Set(rules.map((r) => r.id));
      const matches =
        techniqueMatchesService(t.services, serviceFilter) ||
        t.detectionIds.some((id) => ruleIds.has(id));
      if (!matches) return false;
    }
    if (searchQuery && !t.name.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  const sorted = useMemo(() => {
    const order = sortOrder === "desc" ? 1 : -1;
    const statusOrder = { none: 0, partial: 1, covered: 2 };
    return [...filtered].sort((a, b) => {
      const diff = (statusOrder[a.status] ?? 3) - (statusOrder[b.status] ?? 3);
      return diff * order;
    });
  }, [filtered, sortOrder]);

  const serviceRows = useMemo(() => {
    const q = serviceSearch.trim().toLowerCase();
    return analysis.services.filter((svc) => !q || svc.service.toLowerCase().includes(q));
  }, [analysis.services, serviceSearch]);

  const selectProvider = (id: CloudProviderId) => {
    setProvider(id);
    setServiceFilter("all");
    setServiceSearch("");
  };

  const selectService = (service: string) => {
    setServiceFilter(service);
    requestAnimationFrame(() => {
      matrixRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    });
  };

  const emptyProviderLabel =
    coverageProvider === "kubernetes"
      ? "Kubernetes"
      : coverageProvider === "all"
        ? null
        : coverageProvider.toUpperCase();

  return (
    <Layout>
      <div className="container py-12">
        <PageTitleWithIcon team="blue" icon={BarChart3}>
          Detection Coverage
        </PageTitleWithIcon>
        <p className="text-muted-foreground mb-8">
          Visualize which attack techniques have detection rules, identify coverage gaps, and prioritize rule development.
        </p>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
          <div className="rounded-lg border border-border/50 bg-card p-4">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Total Techniques</p>
            <p className="text-2xl font-bold">{analysis.totalTechs}</p>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Overall Coverage</p>
            <p className="text-2xl font-bold text-primary">{analysis.overallPct}%</p>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4 flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
            <div>
              <p className="text-2xl font-bold">{analysis.totalCovered}</p>
              <p className="text-xs text-muted-foreground">Covered</p>
            </div>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-yellow-400 shrink-0" />
            <div>
              <p className="text-2xl font-bold">{analysis.totalPartial}</p>
              <p className="text-xs text-muted-foreground">Partial</p>
            </div>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4 flex items-center gap-3">
            <XCircle className="h-5 w-5 text-destructive shrink-0" />
            <div>
              <p className="text-2xl font-bold">{analysis.totalNone}</p>
              <p className="text-xs text-muted-foreground">No Coverage</p>
            </div>
          </div>
        </div>

        {/* Service coverage — same services as Detection Rules */}
        <div className="mb-8">
          <CloudProviderTabs
            value={coverageProvider}
            counts={providerCounts}
            onChange={selectProvider}
            visibleProviders={COVERAGE_PROVIDER_TABS}
          />

          <div className="relative w-full sm:max-w-md mb-6">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              value={serviceSearch}
              onChange={(e) => setServiceSearch(e.target.value)}
              placeholder="Search services..."
              className="w-full h-[42px] rounded-lg border border-border bg-card pl-10 pr-4 text-sm outline-none focus:border-primary/50 transition-colors"
            />
          </div>

          {serviceRows.length > 0 ? (
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {serviceRows.map((svc) => {
                const ServiceIcon = getServiceIconOrFallback(svc.service);
                const active = serviceFilter === svc.service;
                return (
                  <button
                    key={svc.service}
                    type="button"
                    onClick={() => selectService(svc.service)}
                    className={cn(
                      getServiceCardClassName({ active }),
                      "px-4 py-3.5 text-left group flex items-center gap-3"
                    )}
                  >
                    <div className="flex items-center gap-3 min-w-0 flex-1">
                      <ServiceIcon size={28} className="shrink-0" />
                      <h3 className="font-display font-semibold text-base truncate group-hover:text-primary transition-colors">
                        {svc.service}
                      </h3>
                    </div>
                    <div className="flex flex-col items-end gap-0.5 shrink-0 text-xs text-muted-foreground">
                      <span className="tabular-nums">
                        {svc.ruleCount} {svc.ruleCount === 1 ? "rule" : "rules"}
                      </span>
                      {svc.total > 0 ? (
                        <span className="tabular-nums">
                          {svc.covered}/{svc.total} techniques
                        </span>
                      ) : (
                        <span className="text-muted-foreground/50">—</span>
                      )}
                    </div>
                    <CountBadge>{svc.total > 0 ? `${svc.pct}%` : svc.ruleCount}</CountBadge>
                    <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 group-hover:text-foreground transition-colors" />
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="rounded-lg border border-dashed border-border/60 bg-card/40 px-6 py-14 text-center">
              <p className="text-2xl font-bold text-muted-foreground mb-1">0%</p>
              <p className="text-sm text-muted-foreground">
                {serviceSearch.trim()
                  ? "No services match your search."
                  : emptyProviderLabel
                    ? `No ${emptyProviderLabel} detection services yet — 0% coverage.`
                    : "No services match your search."}
              </p>
            </div>
          )}
        </div>

        {/* Partial Coverage */}
        {analysis.partialTechs.length > 0 && (
          <div className="mb-8">
            <h2 className="font-display text-lg font-semibold mb-4 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-400" /> Partial Coverage
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {analysis.partialTechs.map((tech) => (
                <Link
                  key={tech.id}
                  to={`/attack-paths/technique/${tech.id}`}
                  className="rounded-lg border border-border/50 bg-card p-4 hover:border-primary/30 transition-colors"
                >
                  <p className="text-sm font-medium mb-1">{tech.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {tech.matchedCount} of {tech.totalDetections} detection rules matched
                  </p>
                </Link>
              ))}
            </div>
          </div>
        )}

        {/* Filters & Coverage Matrix */}
        <div ref={matrixRef}>
          <h2 className="font-display text-lg font-semibold mb-4">Coverage Matrix</h2>
          <div className="flex flex-wrap gap-3 mb-6 items-center">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <input
                placeholder="Search techniques..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="rounded-lg border border-border bg-card pl-8 pr-3 py-2 text-sm outline-none focus:border-primary/50 w-48"
              />
            </div>
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value as TechniqueCategory | "all")}
              className="rounded-lg border border-border bg-card px-3 py-2 text-sm outline-none focus:border-primary/50"
            >
              <option value="all">All Categories</option>
              {(Object.keys(techniqueCategories) as TechniqueCategory[]).map((cat) => (
                <option key={cat} value={cat}>{techniqueCategories[cat].label}</option>
              ))}
            </select>
            <select
              value={serviceFilter}
              onChange={(e) => setServiceFilter(e.target.value)}
              className="rounded-lg border border-border bg-card px-3 py-2 text-sm outline-none focus:border-primary/50"
            >
              <option value="all">All Services</option>
              {analysis.services.map((svc) => (
                <option key={svc.service} value={svc.service}>{svc.service}</option>
              ))}
            </select>
            <span className="text-xs text-muted-foreground ml-2">Sort by status:</span>
            <select
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value as "asc" | "desc")}
              className="rounded-lg border border-border bg-card px-3 py-2 text-sm outline-none focus:border-primary/50"
            >
              <option value="desc">Gaps first</option>
              <option value="asc">Covered first</option>
            </select>
          </div>

          <div className="rounded-lg border border-border/50 overflow-hidden">
            <div className="grid grid-cols-[1fr_140px_120px_100px_110px_120px] gap-x-6 gap-y-0 text-xs font-medium text-muted-foreground uppercase tracking-wider bg-muted px-4 py-3 border-b border-border">
              <span>Attack Technique</span>
              <span>Category</span>
              <span>Services</span>
              <span>In Paths</span>
              <span>Detections</span>
              <span>Status</span>
            </div>
            <div className="divide-y divide-border/50">
              {sorted.map((tech) => {
                const matchedDetections = tech.detectionIds
                  .map((id) => detections.find((d) => d.id === id))
                  .filter(Boolean);

                return (
                  <Link
                    key={tech.id}
                    to={`/attack-paths/technique/${tech.id}`}
                    className="grid grid-cols-[1fr_140px_120px_100px_110px_120px] gap-x-6 gap-y-0 px-4 py-3 hover:bg-muted/50 transition-colors items-center"
                  >
                    <span className="font-medium text-sm text-foreground">{tech.name}</span>
                    <Badge className={`text-[10px] border-0 w-fit ${categoryColors[tech.category]}`}>
                      {techniqueCategories[tech.category].label}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{tech.services.join(", ")}</span>
                    <span className="text-xs text-muted-foreground">{tech.pathCount} chains</span>
                    <span className="text-xs text-muted-foreground">{matchedDetections.length} rules</span>
                    <div className="flex items-center gap-1.5">
                      {tech.status === "covered" && (
                        <>
                          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                          <span className="text-xs text-emerald-400">Covered</span>
                        </>
                      )}
                      {tech.status === "partial" && (
                        <>
                          <AlertCircle className="h-3.5 w-3.5 text-yellow-400" />
                          <span className="text-xs text-yellow-400">Partial</span>
                        </>
                      )}
                      {tech.status === "none" && (
                        <>
                          <XCircle className="h-3.5 w-3.5 text-red-400" />
                          <span className="text-xs text-red-400">Gap</span>
                        </>
                      )}
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default CoveragePage;
