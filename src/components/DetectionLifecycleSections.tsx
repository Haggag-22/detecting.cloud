import React, { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { ChevronDown, ChevronRight, ExternalLink } from "lucide-react";
import { CountBadge } from "@/components/CountBadge";
import { SigmaRulePanel } from "@/components/SigmaRulePanel";
import { Link } from "react-router-dom";
import { techniqueCategories } from "@/data/techniques";
import type {
  Detection,
  DetectionLifecycle,
  ThreatContext,
  TelemetryValidation,
  EnrichmentContext,
} from "@/data/detections";

function DetectionRuleSection({
  detection,
  copiedId,
  setCopiedId,
}: {
  detection: Detection;
  copiedId: string | null;
  setCopiedId: (id: string | null) => void;
}) {
  const sigma = detection.rules.sigma;

  if (!sigma) {
    return <p className="text-sm text-muted-foreground">No Sigma rule is available for this detection.</p>;
  }

  return (
    <SigmaRulePanel
      sigma={sigma}
      rules={detection.rules}
      detectionId={detection.id}
      copiedId={copiedId}
      setCopiedId={setCopiedId}
    />
  );
}

function SectionCard({
  title,
  phase,
  children,
  collapsible = false,
  defaultOpen = true,
}: {
  title: string;
  phase?: number;
  children: React.ReactNode;
  collapsible?: boolean;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);
  const header = (
    <span className="flex items-center gap-3 min-w-0">
      {phase != null && (
        <CountBadge size="md">{String(phase).padStart(2, "0")}</CountBadge>
      )}
      <span className="truncate text-foreground">{title}</span>
    </span>
  );

  if (!collapsible) {
    return (
      <div className="mb-4 rounded-lg border border-border/50 bg-card">
        <div className="px-5 py-3.5 border-b border-border/50 bg-primary/10">
          <h2 className="font-display text-base font-semibold tracking-tight text-foreground">{header}</h2>
        </div>
        <div className="px-5 py-4">{children}</div>
      </div>
    );
  }

  return (
    <Collapsible open={open} onOpenChange={setOpen} className="mb-4">
      <div className="rounded-lg border border-border/50 bg-card overflow-hidden">
        <CollapsibleTrigger
          className={`w-full flex items-center gap-2.5 px-5 py-3.5 text-left bg-primary/10 hover:bg-primary/15 transition-colors ${
            open ? "border-b border-border/50" : ""
          }`}
        >
          {open ? (
            <ChevronDown className="h-3.5 w-3.5 text-primary shrink-0" />
          ) : (
            <ChevronRight className="h-3.5 w-3.5 text-primary shrink-0" />
          )}
          <h2 className="font-display text-base font-semibold tracking-tight text-foreground">{header}</h2>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="px-5 py-4">{children}</div>
        </CollapsibleContent>
      </div>
    </Collapsible>
  );
}

export function DetectionLifecycleSections({
  detection,
  lifecycle,
  severityColors,
  copiedId,
  setCopiedId,
  coveredTechniques = [],
  relatedAttackPaths = [],
}: {
  detection: Detection;
  lifecycle: DetectionLifecycle;
  severityColors: Record<string, string>;
  copiedId: string | null;
  setCopiedId: (id: string | null) => void;
  coveredTechniques?: Array<{ id: string; name: string; description: string; category: string }>;
  relatedAttackPaths?: Array<{ slug: string; title: string; severity: string; description: string }>;
}) {
  return (
    <>
      {/* 1. Detection Overview - not collapsible, rendered by parent */}

      {/* Phase 1: Threat Context */}
      {lifecycle.threatContext && (
        <SectionCard title="Threat Research and Prioritization" phase={1} collapsible defaultOpen>
          <ThreatContextSection context={lifecycle.threatContext} />
        </SectionCard>
      )}

      {/* Phase 2: Telemetry & Data Validation */}
      {lifecycle.telemetryValidation && (
        <SectionCard title="Telemetry and Data Analysis" phase={2} collapsible defaultOpen>
          <TelemetryValidationSection validation={lifecycle.telemetryValidation} />
        </SectionCard>
      )}

      {/* Phase 3: Enrichment & Context */}
      {lifecycle.enrichment && lifecycle.enrichment.length > 0 && (
        <SectionCard title="Enrichment and Context" phase={3} collapsible defaultOpen>
          <EnrichmentSection enrichment={lifecycle.enrichment} />
        </SectionCard>
      )}

      {/* Phase 4: Sigma rule + converter */}
      <SectionCard title="Writing the Detection Rule" phase={4} collapsible defaultOpen>
        <DetectionRuleSection
          detection={detection}
          copiedId={copiedId}
          setCopiedId={setCopiedId}
        />
      </SectionCard>

      {/* Phase 5: Detection Testing */}
      <SectionCard title="Testing the Detection" phase={5} collapsible defaultOpen>
        <DetectionTestingSection detection={detection} simulationCommand={lifecycle.simulationCommand} />
      </SectionCard>

      {/* Detection Coverage */}
      {(coveredTechniques.length > 0 || relatedAttackPaths.length > 0) && (
        <SectionCard title="Detection Coverage" collapsible defaultOpen>
          <DetectionCoverageSection
            techniques={coveredTechniques}
            attackPaths={relatedAttackPaths}
            severityColors={severityColors}
          />
        </SectionCard>
      )}
    </>
  );
}

const sectionLabelClass = "text-[11px] font-medium uppercase tracking-wider mb-1.5 text-muted-foreground";

function ThreatContextSection({ context }: { context: ThreatContext }) {
  return (
    <div className="space-y-4 text-sm">
      <div>
        <p className={sectionLabelClass}>Attacker Behavior</p>
        <p className="text-muted-foreground">{context.attackerBehavior}</p>
      </div>
      {context.realWorldUsage && (
        <div>
          <p className={sectionLabelClass}>Real-World Usage</p>
          <p className="text-muted-foreground">{context.realWorldUsage}</p>
        </div>
      )}
      <div>
        <p className={sectionLabelClass}>Why It Matters</p>
        <p className="text-muted-foreground">{context.whyItMatters}</p>
      </div>
      <div>
        <p className={sectionLabelClass}>Risk and Impact</p>
        <p className="text-muted-foreground">{context.riskAndImpact}</p>
      </div>
    </div>
  );
}

function TelemetryValidationSection({ validation }: { validation: TelemetryValidation }) {
  return (
    <div className="space-y-4 text-sm">
      <div>
        <p className={`${sectionLabelClass} mb-2`}>Required Log Sources</p>
        <ul className="list-disc list-inside text-muted-foreground space-y-1">
          {validation.requiredLogSources.map((s, i) => (
            <li key={i}>{s}</li>
          ))}
        </ul>
      </div>
      <div>
        <p className={`${sectionLabelClass} mb-2`}>Required Fields</p>
        <div className="flex flex-wrap gap-2">
          {validation.requiredFields.map((f) => (
            <Badge key={f} variant="outline" className="text-xs font-mono border-border/70">
              {f}
            </Badge>
          ))}
        </div>
      </div>
      <div>
        <p className={`${sectionLabelClass} mb-2`}>Logging Requirements</p>
        <ul className="list-disc list-inside text-muted-foreground space-y-1">
          {validation.loggingRequirements.map((r, i) => (
            <li key={i}>{r}</li>
          ))}
        </ul>
      </div>
      {validation.limitations && validation.limitations.length > 0 && (
        <div>
          <p className={`${sectionLabelClass} mb-2`}>Known Limitations</p>
          <ul className="list-disc list-inside text-muted-foreground space-y-1">
            {validation.limitations.map((l, i) => (
              <li key={i}>{l}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

function EnrichmentSection({ enrichment }: { enrichment: EnrichmentContext[] }) {
  return (
    <div className="space-y-4">
      {enrichment.map((e, i) => (
        <div key={i} className="rounded-md border border-border/50 bg-muted/10 px-4 py-3 space-y-2">
          <p className="text-[11px] font-medium uppercase tracking-wider text-muted-foreground">{e.dimension}</p>
          <p className="text-sm text-muted-foreground">{e.description}</p>
          <ul className="list-disc list-inside text-xs text-muted-foreground space-y-1">
            {e.examples.map((ex, j) => (
              <li key={j}>{ex}</li>
            ))}
          </ul>
          {e.falsePositiveReduction && (
            <p className="text-xs text-muted-foreground pt-1">
              <span className="text-foreground/80">FP reduction:</span> {e.falsePositiveReduction}
            </p>
          )}
        </div>
      ))}
    </div>
  );
}

function DetectionTestingSection({
  detection,
  simulationCommand,
}: {
  detection: Detection;
  simulationCommand?: string;
}) {
  const telemetry = detection.telemetry;
  const exampleEvent = telemetry?.exampleEvent
    ? (() => {
        try {
          return JSON.stringify(JSON.parse(telemetry.exampleEvent), null, 2);
        } catch {
          return telemetry.exampleEvent;
        }
      })()
    : null;

  return (
    <div className="space-y-4 text-sm">
      <div>
        <p className={`${sectionLabelClass} mb-2`}>Simulation</p>
        <p className="text-muted-foreground mb-2">Use the following command to simulate the attack in a lab environment:</p>
        <pre className="rounded-lg border border-border/50 bg-muted/20 p-4 font-mono text-[13px] overflow-x-auto leading-relaxed">
          {simulationCommand ?? "Run the relevant API call or CLI command for this detection."}
        </pre>
      </div>
      {exampleEvent && (
        <div>
          <p className={`${sectionLabelClass} mb-2`}>Expected Log Output</p>
          <pre className="rounded-lg border border-border/50 bg-muted/20 p-4 font-mono text-[13px] overflow-x-auto leading-relaxed">
            {exampleEvent}
          </pre>
        </div>
      )}
      <div>
        <p className={`${sectionLabelClass} mb-2`}>Validation Steps</p>
        <ol className="list-decimal list-inside text-muted-foreground space-y-1">
          {(detection.testingSteps ?? []).map((step, i) => (
            <li key={i}>{step}</li>
          ))}
        </ol>
      </div>
    </div>
  );
}

function DetectionCoverageSection({
  techniques,
  attackPaths,
  severityColors,
}: {
  techniques: Array<{ id: string; name: string; description: string; category: string }>;
  attackPaths: Array<{ slug: string; title: string; severity: string; description: string }>;
  severityColors: Record<string, string>;
}) {
  return (
    <div className="space-y-4 text-sm">
      {techniques.length > 0 && (
        <div>
          <p className={`${sectionLabelClass} mb-2`}>Techniques Detected</p>
          <div className="space-y-3">
            {techniques.map((t) => {
              const categoryLabel = techniqueCategories[t.category as keyof typeof techniqueCategories]?.label ?? t.category;
              return (
                <Link
                  key={t.id}
                  to={`/attack-paths/technique/${t.id}`}
                  className="block rounded-lg border border-border/50 bg-card p-4 hover:border-primary/30 transition-colors"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Badge className="text-xs border-0 rounded-full bg-severity-critical/15 text-severity-critical">
                      {categoryLabel}
                    </Badge>
                    <span className="font-medium text-sm">{t.name}</span>
                  </div>
                  <p className="text-xs text-muted-foreground line-clamp-2">{t.description}</p>
                </Link>
              );
            })}
          </div>
        </div>
      )}
      {attackPaths.length > 0 && (
        <div>
          <p className={`${sectionLabelClass} mb-2`}>Related Attack Chains</p>
          <div className="rounded-lg border border-border/50 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  <th className="px-4 py-2 text-left font-medium text-muted-foreground">Path</th>
                  <th className="px-4 py-2 text-left font-medium text-muted-foreground w-24">Severity</th>
                  <th className="px-4 py-2 w-12" />
                </tr>
              </thead>
              <tbody>
                {attackPaths.map((ap) => (
                  <tr key={ap.slug} className="border-b border-border/50 last:border-0 hover:bg-muted/20">
                    <td className="px-4 py-2">
                      <Link to={`/attack-paths?technique=${ap.slug}`} className="font-medium text-primary hover:underline">
                        {ap.title}
                      </Link>
                      <p className="text-xs text-muted-foreground mt-0.5 line-clamp-1">{ap.description.substring(0, 80)}…</p>
                    </td>
                    <td className="px-4 py-2">
                      <Badge className={`text-xs border-0 ${severityColors[ap.severity] ?? ""}`}>{ap.severity}</Badge>
                    </td>
                    <td className="px-4 py-2">
                      <Link
                        to={`/attack-paths?technique=${ap.slug}`}
                        className="text-muted-foreground hover:text-foreground"
                        aria-label={`View ${ap.title}`}
                      >
                        <ExternalLink className="h-3.5 w-3.5" />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}

