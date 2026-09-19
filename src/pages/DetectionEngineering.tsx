import { useState } from "react";
import { Layout } from "@/components/Layout";
import { detections, getDetectionsByService, getDetectionCountsByCloudProvider, getDefaultTelemetry, getDetectionCloudProvider, getBrowseService, type Detection } from "@/data/detections";
import { getTechniquesForDetection, getAttackPathsForDetection } from "@/lib/detectionCoverage";
import { Badge } from "@/components/ui/badge";
import { Search, ChevronRight, Copy, Download, Share2, Check, X, ShieldCheck } from "lucide-react";
import { PageTitleWithIcon } from "@/components/PageTitleWithIcon";
import { useSearchParams, Link } from "react-router-dom";
import { getAwsServiceIcon } from "@/components/AwsIcons";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useToast } from "@/hooks/use-toast";
import { DetectionLifecycleSections } from "@/components/DetectionLifecycleSections";
import { SeverityGauge } from "@/components/DetectionVisuals";
import { SigmaRulePanel } from "@/components/SigmaRulePanel";
import { renderCodeWithColoredKeys } from "@/lib/codeHighlight";
import { CloudProviderTabs, parseCloudProviderId, type CloudProviderId } from "@/components/CloudProviderTabs";
import { CountBadge } from "@/components/CountBadge";
import { getServiceCardClassName } from "@/lib/serviceCardColors";
import { cn } from "@/lib/utils";

const SEVERITY_OPTIONS = ["Critical", "High", "Medium", "Low"] as const;
type SeverityFilter = "all" | (typeof SEVERITY_OPTIONS)[number];
type SortOption = "severity" | "title-asc" | "title-desc";

const severityRank: Record<string, number> = {
  Critical: 0,
  High: 1,
  Medium: 2,
  Low: 3,
};

import { SeverityPill } from "@/components/SeverityPill";
import { SEVERITY_BADGE_CLASS } from "@/lib/severityStyles";

function downloadFile(content: string, filename: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const DetectionEngineeringPage = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const ruleParam = searchParams.get("rule");
  const serviceParamRaw = searchParams.get("service");
  const serviceParam = serviceParamRaw ? getBrowseService(serviceParamRaw) : null;
  const providerParam = searchParams.get("provider");
  const activeProvider = parseCloudProviderId(providerParam);
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<SeverityFilter>("all");
  const [sortBy, setSortBy] = useState<SortOption>("severity");
  const { toast } = useToast();

  const providerCounts = getDetectionCountsByCloudProvider();
  const detectionsByService = getDetectionsByService(
    activeProvider === "all" ? "all" : activeProvider
  );
  const services = Object.keys(detectionsByService);

  const setProvider = (id: CloudProviderId) => {
    const next = new URLSearchParams(searchParams);
    if (id === "all") next.delete("provider");
    else next.set("provider", id);
    next.delete("service");
    next.delete("rule");
    setSearchParams(next);
    setSearch("");
    setSeverityFilter("all");
  };

  // If a specific rule is selected, show detailed view
  const selectedDetection = ruleParam ? detections.find((d) => d.id === ruleParam) : null;

  const matchesSearch = (d: Detection) => {
    if (!search) return true;
    const s = search.toLowerCase();
    return (
      d.title.toLowerCase().includes(s) ||
      d.description.toLowerCase().includes(s) ||
      d.tags.some((t) => t.toLowerCase().includes(s)) ||
      d.awsService.toLowerCase().includes(s) ||
      d.severity.toLowerCase().includes(s) ||
      d.id.toLowerCase().includes(s)
    );
  };

  const matchesSeverity = (d: Detection) =>
    severityFilter === "all" || d.severity === severityFilter;

  const sortDetections = (list: Detection[]) => {
    const sorted = [...list];
    if (sortBy === "title-asc") {
      sorted.sort((a, b) => a.title.localeCompare(b.title));
    } else if (sortBy === "title-desc") {
      sorted.sort((a, b) => b.title.localeCompare(a.title));
    } else {
      sorted.sort((a, b) => {
        const ra = severityRank[a.severity] ?? 9;
        const rb = severityRank[b.severity] ?? 9;
        if (ra !== rb) return ra - rb;
        return a.title.localeCompare(b.title);
      });
    }
    return sorted;
  };

  const filterRules = (list: Detection[]) =>
    sortDetections(list.filter((d) => matchesSearch(d) && matchesSeverity(d)));

  const hasActiveFilters = !!search || severityFilter !== "all" || sortBy !== "severity";

  const clearFilters = () => {
    setSearch("");
    setSeverityFilter("all");
    setSortBy("severity");
  };

  if (selectedDetection) {
    const browseService = getBrowseService(selectedDetection.awsService);
    const ServiceIcon = getAwsServiceIcon(browseService);
    const coveredTechniques = getTechniquesForDetection(selectedDetection.id);
    const relatedAttackPaths = getAttackPathsForDetection(selectedDetection.id);
    const telemetry = selectedDetection.telemetry ?? getDefaultTelemetry(selectedDetection);
    const hasLifecycle = !!selectedDetection.lifecycle;

    return (
      <Layout>
        <div className="container max-w-4xl">
          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-6">
            <Link to="/detection-engineering" className="hover:text-foreground transition-colors">
              Detection Rules
            </Link>
            <ChevronRight className="h-3.5 w-3.5" />
            <Link
              to={`/detection-engineering?service=${browseService}`}
              className="hover:text-foreground transition-colors"
            >
              {browseService}
            </Link>
            <ChevronRight className="h-3.5 w-3.5" />
            <span className="text-foreground">{selectedDetection.title}</span>
          </div>

          {/* 1. Detection Overview */}
          <div className="flex items-start gap-5 mb-8">
            {ServiceIcon && <ServiceIcon size={40} />}
            <div className="flex-1 min-w-0">
              <h1 className="font-display text-2xl font-bold mb-2">{selectedDetection.title}</h1>
              <p className="text-muted-foreground">{selectedDetection.description}</p>
            </div>
            <SeverityGauge severity={selectedDetection.severity} />
          </div>

          {/* Export & Share Bar */}
          <div className="flex flex-wrap gap-2 mb-8">
            {selectedDetection.rules.sigma && (
              <Button variant="outline" size="sm" className="border-primary/30 text-primary hover:bg-primary/10"
                onClick={() => downloadFile(selectedDetection.rules.sigma!, `${selectedDetection.id}.yml`)}>
                <Download className="h-3.5 w-3.5 mr-1.5" /> Download Sigma
              </Button>
            )}
            <Button variant="outline" size="sm" className="border-accent/30 text-accent hover:bg-accent/10"
              onClick={() => {
                navigator.clipboard.writeText(window.location.href);
                toast({ title: "Link copied", description: "Detection rule link copied to clipboard." });
              }}>
              <Share2 className="h-3.5 w-3.5 mr-1.5" /> Copy Link
            </Button>
          </div>

          {hasLifecycle && selectedDetection.lifecycle ? (
            <DetectionLifecycleSections
              detection={selectedDetection}
              lifecycle={selectedDetection.lifecycle}
              severityColors={SEVERITY_BADGE_CLASS}
              copiedId={copiedId}
              setCopiedId={setCopiedId}
              coveredTechniques={coveredTechniques}
              relatedAttackPaths={relatedAttackPaths}
            />
          ) : (
            <>
              <DetectionSectionCard title="Detection Rule">
                {selectedDetection.rules.sigma ? (
                  <SigmaRulePanel
                    sigma={selectedDetection.rules.sigma}
                    rules={selectedDetection.rules}
                    detectionId={selectedDetection.id}
                    copiedId={copiedId}
                    setCopiedId={setCopiedId}
                  />
                ) : (
                  <p className="text-sm text-muted-foreground">No Sigma rule is available for this detection.</p>
                )}
              </DetectionSectionCard>

              <DetectionSectionCard title="False Positives">
                <ul className="space-y-2">
                  {selectedDetection.falsePositives.map((fp, i) => (
                    <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                      <span className="text-primary mt-0.5">•</span> {fp}
                    </li>
                  ))}
                </ul>
              </DetectionSectionCard>

              <DetectionSectionCard title="Telemetry Source">
                <p className="text-sm text-muted-foreground mb-4">
                  This section helps engineers understand what telemetry the detection depends on.
                </p>
                <div className="space-y-3 mb-4">
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Primary Log Source</p>
                    <p className="font-medium text-sm">{telemetry.primaryLogSource}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Generating Service</p>
                    <p className="font-medium text-sm">{telemetry.generatingService}</p>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Important Fields</p>
                    <ul className="flex flex-wrap gap-2">
                      {telemetry.importantFields.map((f) => (
                        <Badge key={f} variant="outline" className="text-xs font-mono border-border/70">
                          {f}
                        </Badge>
                      ))}
                    </ul>
                  </div>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Example Event (JSON)</p>
                  <CodeBlockWithCopy content={telemetry.exampleEvent} language="json" copiedId={copiedId} setCopiedId={setCopiedId} copyKey="telemetry" />
                </div>
              </DetectionSectionCard>

              <DetectionSectionCard title="Investigation Guide">
                <p className="text-sm text-muted-foreground mb-4">
                  Steps an analyst should take to investigate the alert after the detection triggers.
                </p>
                <ol className="space-y-2 list-decimal list-inside text-sm text-muted-foreground">
                  {(selectedDetection.investigationSteps ?? [
                    "Identify the IAM user or role that executed the action.",
                    "Verify whether the action was expected in the context of normal operations.",
                    "Review recent activity from the same identity across AWS services.",
                    "Check for related events in CloudTrail from the same source IP.",
                    "Correlate with other detections or alerts for the same identity.",
                  ]).map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              </DetectionSectionCard>

              <DetectionSectionCard title="Detection Coverage">
                <p className="text-sm text-muted-foreground mb-4">
                  Techniques and attack chains covered by this detection from the platform knowledge graph.
                </p>
                {coveredTechniques.length > 0 ? (
                  <>
                    <div className="mb-4">
                      <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Techniques Detected</p>
                      <ul className="space-y-2">
                        {coveredTechniques.map((t) => (
                          <li key={t.id}>
                            <Link
                              to={`/attack-paths/technique/${t.id}`}
                              className="text-sm font-medium text-primary hover:underline"
                            >
                              {t.name}
                            </Link>
                          </li>
                        ))}
                      </ul>
                    </div>
                    {relatedAttackPaths.length > 0 && (
                      <div>
                        <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Related Attack Chains</p>
                        <div className="space-y-3">
                          {relatedAttackPaths.map((ap) => (
                            <Link
                              key={ap.slug}
                              to={`/attack-paths?technique=${ap.slug}`}
                              className="block rounded-lg border border-border/50 bg-card p-4 hover:border-primary/30 transition-colors"
                            >
                              <div className="flex items-center gap-2 mb-1">
                                <Badge className={`text-xs border-0 ${SEVERITY_BADGE_CLASS[ap.severity] ?? SEVERITY_BADGE_CLASS.Low}`}>
                                  {ap.severity}
                                </Badge>
                                <span className="font-medium text-sm">{ap.title}</span>
                              </div>
                              <p className="text-xs text-muted-foreground">{ap.description.substring(0, 120)}…</p>
                            </Link>
                          ))}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <p className="text-sm text-muted-foreground">No techniques or attack chains are linked to this detection yet.</p>
                )}
              </DetectionSectionCard>

              <DetectionSectionCard title="Detection Testing">
                <p className="text-sm text-muted-foreground mb-4">
                  Safe lab testing procedures to validate the detection rule.
                </p>
                <ol className="space-y-2 list-decimal list-inside text-sm text-muted-foreground">
                  {(selectedDetection.testingSteps ?? [
                    "Set up an isolated AWS account or lab environment.",
                    "Simulate the behavior that triggers the detection.",
                    "Ensure CloudTrail (or relevant log source) is enabled and capturing events.",
                    "Run the detection query to confirm the alert triggers.",
                    "Document results and tune the rule if needed.",
                  ]).map((step, i) => (
                    <li key={i}>{step}</li>
                  ))}
                </ol>
              </DetectionSectionCard>
            </>
          )}
        </div>
      </Layout>
    );
  }

  // ─── Service drill-down: list rules for one service (scoped to active provider) ───
  const servicesByName = getDetectionsByService(
    activeProvider === "all" ? "all" : activeProvider
  );
  if (serviceParam && servicesByName[serviceParam]) {
    const ServiceIcon = getAwsServiceIcon(serviceParam);
    const baseRules = (servicesByName[serviceParam] || []).filter(
      (d) => activeProvider === "all" || getDetectionCloudProvider(d) === activeProvider
    );
    const serviceRules = filterRules(baseRules);
    const providerLabel =
      activeProvider === "all" ? null : activeProvider.toUpperCase();

    return (
      <Layout>
        <div className="container">
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-6">
            <Link to="/detection-engineering" className="hover:text-foreground transition-colors">
              Detection Rules
            </Link>
            <ChevronRight className="h-3.5 w-3.5" />
            {providerLabel && (
              <>
                <Link
                  to={`/detection-engineering?provider=${activeProvider}`}
                  className="hover:text-foreground transition-colors"
                >
                  {providerLabel}
                </Link>
                <ChevronRight className="h-3.5 w-3.5" />
              </>
            )}
            <span className="text-foreground">{serviceParam}</span>
          </div>

          <div className="flex items-center gap-4">
            {ServiceIcon && <ServiceIcon size={36} />}
            <h1 className="font-display text-3xl font-bold">{serviceParam}</h1>
          </div>

          <RuleFilterBar
            search={search}
            onSearchChange={setSearch}
            searchPlaceholder="Search rules by title, description, tag, id..."
            severityFilter={severityFilter}
            onSeverityChange={setSeverityFilter}
            sortBy={sortBy}
            onSortChange={setSortBy}
            hasActiveFilters={hasActiveFilters}
            onClear={clearFilters}
            resultLabel={`${serviceRules.length}${
              serviceRules.length !== baseRules.length ? ` of ${baseRules.length}` : ""
            } ${serviceRules.length === 1 ? "rule" : "rules"}`}
          />

          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {serviceRules.length > 0 ? (
              serviceRules.map((det) => <DetectionCard key={det.id} detection={det} />)
            ) : (
              <p className="text-muted-foreground text-sm py-8 text-center md:col-span-2">
                No detections match your search or filters.
              </p>
            )}
          </div>
        </div>
      </Layout>
    );
  }

  // ─── Overview: cloud provider tabs + services with rule counts ───
  const serviceRows = services
    .map((service) => {
      const allRules = detectionsByService[service] || [];
      const matchingRules = allRules.filter((d) => matchesSearch(d) && matchesSeverity(d));
      return { service, total: allRules.length, matching: matchingRules.length };
    })
    .filter((row) => (search || severityFilter !== "all" ? row.matching > 0 : true));

  return (
    <Layout>
      <div className="container">
        <PageTitleWithIcon team="blue" icon={ShieldCheck}>
          Detection Rules
        </PageTitleWithIcon>
        <p className="text-muted-foreground mb-6">
          Sigma-first detection rules organized by cloud provider and service. Select a provider, then a service to
          browse rules.
        </p>

        <CloudProviderTabs
          value={activeProvider}
          counts={providerCounts}
          onChange={setProvider}
        />

        <RuleFilterBar
          search={search}
          onSearchChange={setSearch}
          searchPlaceholder="Search services or detections..."
          severityFilter={severityFilter}
          onSeverityChange={setSeverityFilter}
          sortBy={sortBy}
          onSortChange={setSortBy}
          hasActiveFilters={hasActiveFilters}
          onClear={clearFilters}
          hideSort
        />

        {serviceRows.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {serviceRows.map(({ service, total, matching }) => {
              const ServiceIcon = getAwsServiceIcon(service);
              const count = search || severityFilter !== "all" ? matching : total;
              return (
                <button
                  key={service}
                  type="button"
                  onClick={() => {
                    const next: Record<string, string> = { service };
                    if (activeProvider !== "all") next.provider = activeProvider;
                    setSearchParams(next);
                  }}
                  className={cn(
                    getServiceCardClassName(),
                    "px-4 py-3.5 text-left group flex items-center gap-3"
                  )}
                >
                  {ServiceIcon && <ServiceIcon size={28} className="shrink-0" />}
                  <h2 className="font-display font-semibold text-base truncate flex-1 min-w-0 group-hover:text-primary transition-colors">
                    {service}
                  </h2>
                  <CountBadge>{count}</CountBadge>
                  <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 group-hover:text-foreground transition-colors" />
                </button>
              );
            })}
          </div>
        ) : (
          <div className="rounded-lg border border-dashed border-border/50 bg-card/40 px-6 py-14 text-center">
            <p className="text-sm text-muted-foreground">
              {hasActiveFilters
                ? "No services match your search or filters."
                : activeProvider === "all"
                  ? "No services match your search."
                  : `No ${activeProvider.toUpperCase()} detection rules yet. AWS rules are available under the AWS tab.`}
            </p>
          </div>
        )}
      </div>
    </Layout>
  );
};

function RuleFilterBar({
  search,
  onSearchChange,
  searchPlaceholder,
  severityFilter,
  onSeverityChange,
  sortBy,
  onSortChange,
  hasActiveFilters,
  onClear,
  hideSort = false,
  resultLabel,
}: {
  search: string;
  onSearchChange: (v: string) => void;
  searchPlaceholder: string;
  severityFilter: SeverityFilter;
  onSeverityChange: (v: SeverityFilter) => void;
  sortBy: SortOption;
  onSortChange: (v: SortOption) => void;
  hasActiveFilters: boolean;
  onClear: () => void;
  hideSort?: boolean;
  resultLabel?: string;
}) {
  const selectTriggerClass =
    "h-[42px] w-auto min-w-[10.5rem] rounded-lg border-border bg-card px-3.5 gap-2.5 text-sm shadow-none hover:bg-muted/40 focus:ring-1 focus:ring-primary/40 focus:ring-offset-0 [&>svg]:h-3.5 [&>svg]:w-3.5 [&>svg]:opacity-70 [&>svg]:shrink-0";

  return (
    <div className="flex flex-col sm:flex-row sm:flex-wrap sm:items-center gap-3 mt-6 mb-8">
      <div className="relative flex-1 min-w-[200px] sm:max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <input
          value={search}
          onChange={(e) => onSearchChange(e.target.value)}
          placeholder={searchPlaceholder}
          className="w-full h-[42px] rounded-lg border border-border bg-card pl-10 pr-4 text-sm outline-none focus:border-primary/50 transition-colors"
        />
      </div>

      <Select value={severityFilter} onValueChange={(v) => onSeverityChange(v as SeverityFilter)}>
        <SelectTrigger className={selectTriggerClass} aria-label="Filter by severity">
          <SelectValue placeholder="All severities" />
        </SelectTrigger>
        <SelectContent>
          <SelectItem value="all">All severities</SelectItem>
          {SEVERITY_OPTIONS.map((s) => (
            <SelectItem key={s} value={s}>
              {s}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>

      {!hideSort && (
        <Select value={sortBy} onValueChange={(v) => onSortChange(v as SortOption)}>
          <SelectTrigger className={selectTriggerClass} aria-label="Sort rules">
            <SelectValue placeholder="Sort: Severity" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="severity">Sort: Severity</SelectItem>
            <SelectItem value="title-asc">Sort: Title A–Z</SelectItem>
            <SelectItem value="title-desc">Sort: Title Z–A</SelectItem>
          </SelectContent>
        </Select>
      )}

      {hasActiveFilters && (
        <Button type="button" variant="ghost" size="sm" className="h-[42px] px-3 text-muted-foreground" onClick={onClear}>
          <X className="h-3.5 w-3.5 mr-1.5" />
          Clear
        </Button>
      )}

      {resultLabel && (
        <span className="sm:ml-auto text-sm text-muted-foreground tabular-nums whitespace-nowrap">
          {resultLabel}
        </span>
      )}
    </div>
  );
}

function DetectionSectionCard({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="mb-8 rounded-lg border border-border/50 bg-card p-6">
      <h2 className="font-display text-lg font-semibold mb-4">{title}</h2>
      {children}
    </div>
  );
}

function CodeBlockWithCopy({
  content,
  language,
  copiedId,
  setCopiedId,
  copyKey,
}: {
  content: string;
  language: string;
  copiedId: string | null;
  setCopiedId: (id: string | null) => void;
  copyKey: string;
}) {
  const id = `copy-${copyKey}`;
  return (
    <div className="rounded-lg border border-border/50 overflow-hidden">
      <div className="px-4 py-2 bg-muted text-xs text-muted-foreground font-mono border-b border-border/50 flex items-center justify-between">
        <span>{language}</span>
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
          onClick={() => {
            navigator.clipboard.writeText(content);
            setCopiedId(id);
            setTimeout(() => setCopiedId(null), 2000);
          }}
        >
          {copiedId === id ? <><Check className="h-3 w-3 mr-1" /> Copied</> : <><Copy className="h-3 w-3 mr-1" /> Copy</>}
        </Button>
      </div>
      <pre className="p-4 overflow-x-auto bg-muted/30 text-sm font-mono leading-relaxed">
        {["json", "hcl", "yaml"].includes(language)
          ? renderCodeWithColoredKeys(content, language)
          : <code>{content}</code>}
      </pre>
    </div>
  );
}

function DetectionCard({ detection: det }: { detection: Detection }) {
  const ServiceIcon = getAwsServiceIcon(det.awsService);

  return (
    <Link
      to={`/detection-engineering?rule=${det.id}`}
      className="flex flex-col h-full rounded-lg border border-border/50 bg-muted/20 p-4 hover:border-primary/30 transition-colors"
    >
      <div className="flex items-start gap-2.5 mb-2">
        {ServiceIcon && (
          <span className="mt-0.5 shrink-0">
            <ServiceIcon size={18} />
          </span>
        )}
        <h3 className="font-semibold text-sm leading-snug flex-1 min-w-0">{det.title}</h3>
        <SeverityPill severity={det.severity} />
      </div>
      <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2 flex-1">
        {det.description}
      </p>
    </Link>
  );
}

export default DetectionEngineeringPage;
