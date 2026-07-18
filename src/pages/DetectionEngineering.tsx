import { useState } from "react";
import { Layout } from "@/components/Layout";
import { detections, getDetectionsByService, getDefaultTelemetry, type Detection } from "@/data/detections";
import { getTechniquesForDetection, getAttackPathsForDetection } from "@/lib/detectionCoverage";
import { Badge } from "@/components/ui/badge";
import { Search, ChevronRight, Copy, Download, Share2, Check } from "lucide-react";
import { useSearchParams, Link } from "react-router-dom";
import { getAwsServiceIcon } from "@/components/AwsIcons";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { DetectionLifecycleSections } from "@/components/DetectionLifecycleSections";
import { SeverityGauge } from "@/components/DetectionVisuals";
import { SigmaRulePanel } from "@/components/SigmaRulePanel";
import { renderCodeWithColoredKeys } from "@/lib/codeHighlight";

const severityColors: Record<string, string> = {
  Critical: "bg-severity-critical/15 text-severity-critical",
  High: "bg-severity-high/15 text-severity-high",
  Medium: "bg-severity-medium/15 text-severity-medium",
  Low: "bg-muted text-muted-foreground",
};

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
  const serviceParam = searchParams.get("service");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const { toast } = useToast();

  const detectionsByService = getDetectionsByService();
  const services = Object.keys(detectionsByService);

  // If a specific rule is selected, show detailed view
  const selectedDetection = ruleParam ? detections.find((d) => d.id === ruleParam) : null;

  // Related rules (where service appears in relatedServices but not primary)
  const relatedRules = serviceParam
    ? detections.filter((d) => d.awsService !== serviceParam && d.relatedServices.includes(serviceParam))
    : [];

  const filterBySearch = (list: typeof detections) =>
    list.filter((d) => {
      if (!search) return true;
      const s = search.toLowerCase();
      return (
        d.title.toLowerCase().includes(s) ||
        d.description.toLowerCase().includes(s) ||
        d.tags.some((t) => t.toLowerCase().includes(s))
      );
    });

  const filteredRelated = filterBySearch(relatedRules);

  const matchesSearch = (d: Detection) => {
    if (!search) return true;
    const s = search.toLowerCase();
    return (
      d.title.toLowerCase().includes(s) ||
      d.description.toLowerCase().includes(s) ||
      d.tags.some((t) => t.toLowerCase().includes(s)) ||
      d.awsService.toLowerCase().includes(s)
    );
  };

  if (selectedDetection) {
    const ServiceIcon = getAwsServiceIcon(selectedDetection.awsService);
    const coveredTechniques = getTechniquesForDetection(selectedDetection.id);
    const relatedAttackPaths = getAttackPathsForDetection(selectedDetection.id);
    const availableFormats = Object.entries(selectedDetection.rules).filter(([, v]) => !!v);
    const telemetry = selectedDetection.telemetry ?? getDefaultTelemetry(selectedDetection);
    const hasLifecycle = !!selectedDetection.lifecycle;

    return (
      <Layout>
        <div className="container py-12 max-w-4xl">
          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-6">
            <Link to="/detection-engineering" className="hover:text-foreground transition-colors">
              Detection Rules
            </Link>
            <ChevronRight className="h-3.5 w-3.5" />
            <Link
              to={`/detection-engineering?service=${selectedDetection.awsService}`}
              className="hover:text-foreground transition-colors"
            >
              {selectedDetection.awsService}
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
              {hasLifecycle && selectedDetection.lifecycle?.whyItMatters && (
                <p className="mt-3 text-sm text-primary/90 font-medium">
                  Why it matters: {selectedDetection.lifecycle.whyItMatters}
                </p>
              )}
            </div>
            <SeverityGauge severity={selectedDetection.severity} />
          </div>

          {/* Export & Share Bar */}
          <div className="flex flex-wrap gap-2 mb-6">
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

          {/* Metadata */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
            <div className="rounded-lg border border-border/50 bg-card p-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Primary Service</p>
              <div className="flex items-center gap-2">
                {ServiceIcon && <ServiceIcon size={16} />}
                <span className="font-medium text-sm">{selectedDetection.awsService}</span>
              </div>
            </div>
            <div className="rounded-lg border border-border/50 bg-card p-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Severity</p>
              <Badge className={`text-xs border-0 ${severityColors[selectedDetection.severity]}`}>
                {selectedDetection.severity}
              </Badge>
            </div>
            <div className="rounded-lg border border-border/50 bg-card p-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Log Sources</p>
              <p className="text-sm font-medium">{selectedDetection.logSources.join(", ")}</p>
            </div>
            <div className="rounded-lg border border-border/50 bg-card p-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Rule Format</p>
              <p className="text-sm font-medium">Sigma{availableFormats.length > 1 ? ` + convert` : ""}</p>
            </div>
          </div>

          {/* Related AWS Services */}
          {selectedDetection.relatedServices.length > 0 && (
            <div className="mb-6">
              <h2 className="text-sm font-medium text-muted-foreground uppercase tracking-wider mb-3">Related AWS Services</h2>
              <div className="flex flex-wrap gap-2">
                {selectedDetection.relatedServices.map((svc) => {
                  const SvcIcon = getAwsServiceIcon(svc);
                  return (
                    <Link key={svc} to={`/detection-engineering?service=${svc}`}
                      className="flex items-center gap-2 rounded-lg border border-border/50 bg-card px-3 py-2 hover:border-primary/30 transition-colors">
                      {SvcIcon && <SvcIcon size={16} />}
                      <span className="text-sm font-medium">{svc}</span>
                    </Link>
                  );
                })}
              </div>
            </div>
          )}

          {/* Tags */}
          <div className="flex flex-wrap gap-1.5 mb-8">
            {selectedDetection.tags.map((tag) => (
              <Badge key={tag} variant="outline" className="text-xs border-border/70 text-muted-foreground">
                {tag}
              </Badge>
            ))}
          </div>

          {hasLifecycle && selectedDetection.lifecycle ? (
            <DetectionLifecycleSections
              detection={selectedDetection}
              lifecycle={selectedDetection.lifecycle}
              severityColors={severityColors}
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
                  Techniques and attack paths covered by this detection from the platform knowledge graph.
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
                        <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Related Attack Paths</p>
                        <div className="space-y-3">
                          {relatedAttackPaths.map((ap) => (
                            <Link
                              key={ap.slug}
                              to={`/attack-paths?technique=${ap.slug}`}
                              className="block rounded-lg border border-border/50 bg-card p-4 hover:border-primary/30 transition-colors"
                            >
                              <div className="flex items-center gap-2 mb-1">
                                <Badge className={`text-xs border-0 ${severityColors[ap.severity]}`}>
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
                  <p className="text-sm text-muted-foreground">No techniques or attack paths are linked to this detection yet.</p>
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

  // ─── Service drill-down: list rules for one AWS service ───
  if (serviceParam && services.includes(serviceParam)) {
    const ServiceIcon = getAwsServiceIcon(serviceParam);
    const serviceRules = filterBySearch(detectionsByService[serviceParam] || []);

    return (
      <Layout>
        <div className="container py-12">
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-6">
            <Link to="/detection-engineering" className="hover:text-foreground transition-colors">
              Detection Rules
            </Link>
            <ChevronRight className="h-3.5 w-3.5" />
            <span className="text-foreground">{serviceParam}</span>
          </div>

          <div className="flex items-start gap-4 mb-2">
            {ServiceIcon && <ServiceIcon size={36} />}
            <div>
              <h1 className="font-display text-3xl font-bold mb-1">{serviceParam}</h1>
              <p className="text-muted-foreground">
                {(detectionsByService[serviceParam] || []).length} detection{" "}
                {(detectionsByService[serviceParam] || []).length === 1 ? "rule" : "rules"} for this service.
              </p>
            </div>
          </div>

          <div className="relative max-w-md mt-6 mb-8">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search rules in this service..."
              className="w-full rounded-lg border border-border bg-card pl-10 pr-4 py-2.5 text-sm outline-none focus:border-primary/50 transition-colors"
            />
          </div>

          <div className="space-y-3">
            {serviceRules.length > 0 ? (
              serviceRules.map((det) => <DetectionCard key={det.id} detection={det} />)
            ) : (
              <p className="text-muted-foreground text-sm py-8 text-center">No detections found.</p>
            )}
          </div>

          {filteredRelated.length > 0 && (
            <div className="mt-10 pt-8 border-t border-border">
              <h2 className="text-sm font-medium text-muted-foreground uppercase tracking-wider mb-4">
                Related Detection Rules
              </h2>
              <p className="text-xs text-muted-foreground mb-4">
                These rules belong to other services but involve {serviceParam} in the attack chain.
              </p>
              <div className="space-y-3">
                {filteredRelated.map((det) => (
                  <DetectionCard key={det.id} detection={det} />
                ))}
              </div>
            </div>
          )}
        </div>
      </Layout>
    );
  }

  // ─── Overview: AWS services with rule counts ───
  const serviceRows = services
    .map((service) => {
      const allRules = detectionsByService[service] || [];
      const matchingRules = allRules.filter(matchesSearch);
      return { service, total: allRules.length, matching: matchingRules.length };
    })
    .filter((row) => (search ? row.matching > 0 : true));

  return (
    <Layout>
      <div className="container py-12">
        <h1 className="font-display text-3xl font-bold mb-2">Detection Rules</h1>
        <p className="text-muted-foreground mb-8">
          Sigma-first cloud detection rules organized by AWS service. Select a service to browse its rules.
        </p>

        <div className="relative max-w-md mb-8">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Search services or detections..."
            className="w-full rounded-lg border border-border bg-card pl-10 pr-4 py-2.5 text-sm outline-none focus:border-primary/50 transition-colors"
          />
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {serviceRows.map(({ service, total, matching }) => {
            const ServiceIcon = getAwsServiceIcon(service);
            const count = search ? matching : total;
            return (
              <button
                key={service}
                type="button"
                onClick={() => setSearchParams({ service })}
                className="rounded-lg border border-border/50 bg-card p-5 text-left hover:border-primary/30 transition-colors group flex items-center gap-3"
              >
                {ServiceIcon && <ServiceIcon size={28} />}
                <div className="flex-1 min-w-0">
                  <h2 className="font-display font-semibold text-base group-hover:text-primary transition-colors">
                    {service}
                  </h2>
                  <p className="text-xs text-muted-foreground">
                    {count} {count === 1 ? "rule" : "rules"}
                    {search && matching !== total ? ` matching` : ""}
                  </p>
                </div>
                <Badge variant="outline" className="text-xs border-border text-muted-foreground shrink-0">
                  {count}
                </Badge>
                <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 group-hover:text-foreground transition-colors" />
              </button>
            );
          })}
        </div>

        {serviceRows.length === 0 && (
          <p className="text-muted-foreground text-sm py-8 text-center">No services match your search.</p>
        )}
      </div>
    </Layout>
  );
};

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
    <div className="rounded-lg border border-border overflow-hidden">
      <div className="px-4 py-2 bg-muted text-xs text-muted-foreground font-mono border-b border-border flex items-center justify-between">
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
      className="block rounded-lg border border-border/50 bg-muted/20 p-5 hover:border-primary/30 transition-colors"
    >
      <div className="flex items-center gap-3 mb-2">
        {ServiceIcon && <ServiceIcon size={20} />}
        <h3 className="font-semibold text-sm">{det.title}</h3>
        <Badge className={`text-xs border-0 ml-auto ${severityColors[det.severity]}`}>
          {det.severity}
        </Badge>
      </div>
      <p className="text-xs text-muted-foreground mb-3">{det.description}</p>
      <div className="flex items-center gap-2 flex-wrap">
        {det.tags.slice(0, 4).map((tag) => (
          <Badge key={tag} variant="outline" className="text-[10px] border-border/70 text-muted-foreground">
            {tag}
          </Badge>
        ))}
        <span className="text-[10px] text-muted-foreground ml-auto">
          {det.rules.sigma ? "Sigma" : "No Sigma"}
        </span>
      </div>
    </Link>
  );
}

export default DetectionEngineeringPage;
