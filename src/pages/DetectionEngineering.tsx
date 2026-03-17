import { useState } from "react";
import { Layout } from "@/components/Layout";
import { detections, getDetectionsByService, getDefaultTelemetry, type Detection } from "@/data/detections";
import { getTechniquesForDetection, getAttackPathsForDetection } from "@/lib/detectionCoverage";
import { Badge } from "@/components/ui/badge";
import { Search, Link as LinkIcon, ChevronRight, Copy, Download, Share2, Check } from "lucide-react";
import { useSearchParams, Link } from "react-router-dom";
import { getAwsServiceIcon } from "@/components/AwsIcons";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { DetectionLifecycleSections } from "@/components/DetectionLifecycleSections";
import { SeverityGauge, MitreTimeline } from "@/components/DetectionVisuals";

const severityColors: Record<string, string> = {
  Critical: "bg-severity-critical/15 text-severity-critical",
  High: "bg-severity-high/15 text-severity-high",
  Medium: "bg-severity-medium/15 text-severity-medium",
  Low: "bg-muted text-muted-foreground",
};

const formatLabels: Record<string, string> = {
  sigma: "Sigma Rule",
  splunk: "Splunk Query",
  cloudtrail: "CloudTrail Athena",
  cloudwatch: "CloudWatch Insights",
  eventbridge: "EventBridge Rule Pattern",
};

import { renderCodeWithColoredKeys } from "@/lib/codeHighlight";

// Lightweight syntax highlighting for YAML and SPL (detection rules)
function highlightCode(code: string, format: string): React.ReactNode {
  if (format === "sigma") {
    // Highlight YAML keys and values
    return code.split("\n").map((line, i) => {
      const highlighted = line
        .replace(/^(\s*)([\w-]+)(:)/gm, "$1<k>$2</k>$3")
        .replace(/'([^']+)'/g, "<s>'$1'</s>");
      return (
        <span key={i}>
          <span dangerouslySetInnerHTML={{ __html: highlighted.replace(/<k>/g, '<span class="text-yellow-400">').replace(/<\/k>/g, '</span>').replace(/<s>/g, '<span class="text-emerald-400">').replace(/<\/s>/g, '</span>') }} />
          {"\n"}
        </span>
      );
    });
  }
  if (format === "splunk") {
    const highlighted = code
      .replace(/\b(index|sourcetype|where|table|stats|sort|like|OR|AND|NOT|IN|by|as)\b/gi, '<span class="text-yellow-400">$1</span>')
      .replace(/\|/g, '<span class="text-accent">|</span>');
    return <span dangerouslySetInnerHTML={{ __html: highlighted }} />;
  }
  if (format === "cloudtrail") {
    const highlighted = code
      .replace(/\b(SELECT|FROM|WHERE|AND|OR|ORDER BY|GROUP BY|HAVING|IN|LIKE|NOT|DESC|ASC|COUNT|SUM)\b/gi, '<span class="text-yellow-400">$1</span>');
    return <span dangerouslySetInnerHTML={{ __html: highlighted }} />;
  }
  if (format === "cloudwatch") {
    const highlighted = code
      .replace(/\b(fields|filter|sort|stats|count|like|in|by|desc|asc|not)\b/gi, '<span class="text-yellow-400">$1</span>')
      .replace(/\|/g, '<span class="text-accent">|</span>');
    return <span dangerouslySetInnerHTML={{ __html: highlighted }} />;
  }
  if (format === "eventbridge") {
    return renderCodeWithColoredKeys(code, "json");
  }
  return code;
}

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

  // Filter detections
  // Primary rules for the selected service
  const primaryRules = serviceParam
    ? detections.filter((d) => d.awsService === serviceParam)
    : detections;

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

  const filtered = filterBySearch(primaryRules);
  const filteredRelated = filterBySearch(relatedRules);

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
              Detection Engineering
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
          <div className="flex items-start gap-4 mb-8">
            {ServiceIcon && <ServiceIcon size={40} />}
            <div className="flex-1">
              <h1 className="font-display text-2xl font-bold mb-2">{selectedDetection.title}</h1>
              <p className="text-muted-foreground">{selectedDetection.description}</p>
            </div>
          </div>

          {/* Export & Share Bar */}
          <div className="flex flex-wrap gap-2 mb-6">
            {selectedDetection.rules.sigma && (
              <Button variant="outline" size="sm" className="border-primary/30 text-primary hover:bg-primary/10"
                onClick={() => downloadFile(selectedDetection.rules.sigma!, `${selectedDetection.id}.yml`)}>
                <Download className="h-3.5 w-3.5 mr-1.5" /> Download .yml
              </Button>
            )}
            {selectedDetection.rules.splunk && (
              <Button variant="outline" size="sm" className="border-primary/30 text-primary hover:bg-primary/10"
                onClick={() => downloadFile(selectedDetection.rules.splunk!, `${selectedDetection.id}.spl`)}>
                <Download className="h-3.5 w-3.5 mr-1.5" /> Download .spl
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

          {/* Metadata + MITRE */}
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
              <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Rule Formats</p>
              <p className="text-sm font-medium">{availableFormats.length} formats</p>
            </div>
          </div>

          {/* MITRE ATT&CK mapping (lifecycle) */}
          {hasLifecycle && selectedDetection.lifecycle?.mitre && selectedDetection.lifecycle.mitre.length > 0 && (
            <div className="flex flex-wrap gap-2 mb-6">
              <p className="text-xs text-muted-foreground uppercase tracking-wider w-full mb-1">MITRE ATT&CK</p>
              {selectedDetection.lifecycle.mitre.map((m, i) => (
                <Badge key={i} variant="outline" className="text-xs border-border/70">
                  {m.tactic}
                  {m.techniqueId && ` — ${m.techniqueId}`}
                  {m.techniqueName && ` (${m.techniqueName})`}
                </Badge>
              ))}
            </div>
          )}

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
            />
          ) : (
            <>
              {/* Legacy: Rule Formats Tabs */}
              <DetectionSectionCard title="Detection Rules">
                <Tabs defaultValue={availableFormats[0]?.[0] || "sigma"}>
                  <TabsList className="bg-muted border border-border/50">
                    {availableFormats.map(([key]) => (
                      <TabsTrigger key={key} value={key} className="text-xs">
                        {formatLabels[key] || key}
                      </TabsTrigger>
                    ))}
                  </TabsList>
                  {availableFormats.map(([key, value]) => (
                    <TabsContent key={key} value={key}>
                      <div className="rounded-lg border border-border overflow-hidden">
                        <div className="px-4 py-2 bg-muted text-xs text-muted-foreground font-mono border-b border-border flex items-center justify-between">
                          <span>{formatLabels[key]}</span>
                          <Button variant="ghost" size="sm" className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
                            onClick={() => {
                              navigator.clipboard.writeText(value as string);
                              setCopiedId(key);
                              setTimeout(() => setCopiedId(null), 2000);
                            }}>
                            {copiedId === key ? <><Check className="h-3 w-3 mr-1" /> Copied</> : <><Copy className="h-3 w-3 mr-1" /> Copy</>}
                          </Button>
                        </div>
                        <pre className="p-4 overflow-x-auto bg-muted/30 text-sm font-mono leading-relaxed">
                          <code>{highlightCode(value as string, key)}</code>
                        </pre>
                      </div>
                    </TabsContent>
                  ))}
                </Tabs>
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

          {/* Detection Coverage - show for both layouts when techniques exist */}
          {hasLifecycle && coveredTechniques.length > 0 && (
            <DetectionSectionCard title="Detection Coverage">
              <p className="text-sm text-muted-foreground mb-4">
                Techniques and attack paths covered by this detection from the platform knowledge graph.
              </p>
              <div className="mb-4">
                <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Techniques Detected</p>
                <ul className="space-y-2">
                  {coveredTechniques.map((t) => (
                    <Link key={t.id} to={`/attack-paths/technique/${t.id}`} className="block text-sm font-medium text-primary hover:underline">
                      {t.name}
                    </Link>
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
                          <Badge className={`text-xs border-0 ${severityColors[ap.severity]}`}>{ap.severity}</Badge>
                          <span className="font-medium text-sm">{ap.title}</span>
                        </div>
                        <p className="text-xs text-muted-foreground">{ap.description.substring(0, 120)}…</p>
                      </Link>
                    ))}
                  </div>
                </div>
              )}
            </DetectionSectionCard>
          )}
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="container py-12">
        <h1 className="font-display text-3xl font-bold mb-2">Detection Engineering</h1>
        <p className="text-muted-foreground mb-8">
          Cloud security detection rules organized by AWS service.
        </p>

        {/* Search & Service Filter */}
        <div className="flex flex-col sm:flex-row gap-3 mb-8">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search detections..."
              className="w-full rounded-lg border border-border bg-card pl-10 pr-4 py-2.5 text-sm outline-none focus:border-primary/50 transition-colors"
            />
          </div>
          <div className="flex gap-2 flex-wrap">
            <Badge
              variant={!serviceParam ? "default" : "outline"}
              className={`cursor-pointer ${
                !serviceParam ? "bg-primary text-primary-foreground" : "border-border text-muted-foreground"
              }`}
              onClick={() => setSearchParams({})}
            >
              All Services
            </Badge>
            {services.map((service) => {
              const Icon = getAwsServiceIcon(service);
              return (
                <Badge
                  key={service}
                  variant={serviceParam === service ? "default" : "outline"}
                  className={`cursor-pointer flex items-center gap-1.5 ${
                    serviceParam === service
                      ? "bg-primary text-primary-foreground"
                      : "border-border text-muted-foreground"
                  }`}
                  onClick={() => setSearchParams({ service })}
                >
                  {Icon && <Icon size={14} />}
                  {service}
                </Badge>
              );
            })}
          </div>
        </div>

        {/* Rules grouped by service */}
        {serviceParam ? (
          <div className="space-y-3">
            {filtered.map((det) => (
              <DetectionCard key={det.id} detection={det} />
            ))}
            {filtered.length === 0 && (
              <p className="text-muted-foreground text-sm py-8 text-center">No detections found.</p>
            )}

            {/* Related rules from other primary services */}
            {filteredRelated.length > 0 && (
              <div className="mt-10 pt-6 border-t border-border">
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
        ) : (
          <div className="space-y-10">
            {services.map((service) => {
              const serviceRules = (detectionsByService[service] || []).filter((d) => {
                if (!search) return true;
                const s = search.toLowerCase();
                return d.title.toLowerCase().includes(s) || d.description.toLowerCase().includes(s);
              });
              if (serviceRules.length === 0) return null;

              const ServiceIcon = getAwsServiceIcon(service);
              return (
                <div key={service}>
                  <div className="flex items-center gap-3 mb-4">
                    {ServiceIcon && <ServiceIcon size={28} />}
                    <h2 className="font-display text-xl font-bold">{service}</h2>
                    <Badge variant="outline" className="text-xs border-border text-muted-foreground">
                      {serviceRules.length} rules
                    </Badge>
                  </div>
                  <div className="space-y-3">
                    {serviceRules.map((det) => (
                      <DetectionCard key={det.id} detection={det} />
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
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
  const formatCount = Object.values(det.rules).filter(Boolean).length;

  return (
    <Link
      to={`/detection-engineering?rule=${det.id}`}
      className="block rounded-lg border border-border/50 bg-card p-5 hover:border-primary/30 transition-colors"
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
        <span className="text-[10px] text-muted-foreground ml-auto">{formatCount} rule formats</span>
      </div>
    </Link>
  );
}

export default DetectionEngineeringPage;
