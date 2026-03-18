import React, { useState, useCallback } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ChevronDown, ChevronRight, ThumbsUp, AlertTriangle, ThumbsDown, Copy, Check, ExternalLink, MoreHorizontal } from "lucide-react";
import { renderCodeWithColoredKeys } from "@/lib/codeHighlight";
import { QualityMetricsVisual } from "@/components/DetectionVisuals";
import { Link } from "react-router-dom";
import { techniqueCategories } from "@/data/techniques";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type {
  Detection,
  DetectionLifecycle,
  ThreatContext,
  TelemetryValidation,
  DataModeling,
  EnrichmentContext,
  DetectionQuality,
  CommunityConfidence,
  DeploymentInfo,
  DetectionLogicExplanation,
} from "@/data/detections";

const formatLabels: Record<string, string> = {
  "detection-logic": "Detection Logic",
  sigma: "Sigma",
  cloudtrail: "CloudTrail Athena",
  splunk: "Splunk",
  lambda: "Lambda",
  cloudwatch: "CloudWatch Insights",
  eventbridge: "EventBridge",
};

function highlightCode(code: string, format: string): React.ReactNode {
  if (format === "sigma") {
    return code.split("\n").map((line, i) => {
      const highlighted = line
        .replace(/^(\s*)([\w-]+)(:)/gm, "$1<k>$2</k>$3")
        .replace(/'([^']+)'/g, "<s>'$1'</s>");
      return (
        <span key={i}>
          <span
            dangerouslySetInnerHTML={{
              __html: highlighted
                .replace(/<k>/g, '<span class="text-yellow-400">')
                .replace(/<\/k>/g, "</span>")
                .replace(/<s>/g, '<span class="text-emerald-400">')
                .replace(/<\/s>/g, "</span>"),
            }}
          />
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
    const highlighted = code.replace(
      /\b(SELECT|FROM|WHERE|AND|OR|ORDER BY|GROUP BY|HAVING|IN|LIKE|NOT|DESC|ASC|COUNT|SUM)\b/gi,
      '<span class="text-yellow-400">$1</span>'
    );
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
  if (format === "lambda") {
    const highlighted = code
      .replace(/\b(def|import|from|return|if|else|for|in|and|or|not|True|False|None)\b/g, '<span class="text-yellow-400">$1</span>')
      .replace(/\b(lambda_handler|event|context|detail|get)\b/g, '<span class="text-blue-400">$1</span>')
      .replace(/#[^\n]*/g, '<span class="text-muted-foreground">$&</span>');
    return <span dangerouslySetInnerHTML={{ __html: highlighted }} />;
  }
  return code;
}

const CORE_TAB_ORDER = ["detection-logic", "sigma", "cloudtrail", "splunk", "lambda"] as const;
const MORE_TAB_KEYS = ["cloudwatch", "eventbridge"] as const;

function DetectionRuleSection({
  detection,
  lifecycle,
  formatLabels,
  highlightCode,
  copiedId,
  setCopiedId,
}: {
  detection: Detection;
  lifecycle: DetectionLifecycle;
  formatLabels: Record<string, string>;
  highlightCode: (code: string, format: string) => React.ReactNode;
  copiedId: string | null;
  setCopiedId: (id: string | null) => void;
}) {
  const [activeTab, setActiveTab] = useState<string>("");
  const logic = lifecycle.logicExplanation;
  const rules = detection.rules;

  const coreTabs = CORE_TAB_ORDER.filter((key) => {
    if (key === "detection-logic") return !!logic;
    return !!rules[key as keyof typeof rules];
  });
  const moreTabs = MORE_TAB_KEYS.filter((key) => !!rules[key as keyof typeof rules]);
  const defaultTab = coreTabs[0] ?? "sigma";
  const effectiveTab = activeTab || defaultTab;

  return (
    <Tabs value={effectiveTab} onValueChange={setActiveTab} className="mt-4">
      <div className="flex flex-wrap items-center gap-1 border-b border-border/50 pb-2 mb-4">
        <TabsList className="bg-muted border border-border/50 h-auto p-1 flex-wrap">
          {coreTabs.map((key) => (
            <TabsTrigger key={key} value={key} className="text-xs">
              {formatLabels[key] || key}
            </TabsTrigger>
          ))}
          {moreTabs.length > 0 && (
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button
                   variant={moreTabs.includes(effectiveTab as typeof MORE_TAB_KEYS[number]) ? "secondary" : "ghost"}
                   size="sm"
                   className="h-8 px-2 text-xs text-muted-foreground hover:text-foreground gap-1"
                 >
                   <MoreHorizontal className="h-3.5 w-3.5" />
                   {moreTabs.includes(effectiveTab as typeof MORE_TAB_KEYS[number]) ? formatLabels[effectiveTab] || effectiveTab : "More"}
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="start">
                {moreTabs.map((key) => (
                  <DropdownMenuItem key={key} onSelect={() => setActiveTab(key)}>
                    {formatLabels[key] || key}
                  </DropdownMenuItem>
                ))}
              </DropdownMenuContent>
            </DropdownMenu>
          )}
        </TabsList>
      </div>

      {/* Detection Logic tab */}
      {logic && (
        <TabsContent value="detection-logic" className="mt-0">
          <DetectionLogicTab logic={logic} copiedId={copiedId} setCopiedId={setCopiedId} />
        </TabsContent>
      )}

      {/* Rule format tabs */}
      {[...coreTabs.filter((k) => k !== "detection-logic"), ...moreTabs].map((key) => {
        const value = rules[key as keyof typeof rules];
        if (!value || typeof value !== "string") return null;
        return (
          <TabsContent key={key} value={key} className="mt-0">
            <div className="rounded-lg border border-border overflow-hidden">
              <div className="px-4 py-2 bg-muted text-xs text-muted-foreground font-mono border-b border-border flex items-center justify-between">
                <span>{formatLabels[key] || key}</span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
                  onClick={() => {
                    navigator.clipboard.writeText(value);
                    setCopiedId(key);
                    setTimeout(() => setCopiedId(null), 2000);
                  }}
                >
                  {copiedId === key ? <><Check className="h-3 w-3 mr-1" /> Copied</> : <><Copy className="h-3 w-3 mr-1" /> Copy</>}
                </Button>
              </div>
              <pre className="p-4 overflow-x-auto bg-muted/30 text-sm font-mono leading-relaxed">
                <code>{highlightCode(value, key)}</code>
              </pre>
            </div>
          </TabsContent>
        );
      })}
    </Tabs>
  );
}

function DetectionLogicTab({
  logic,
  copiedId,
  setCopiedId,
}: {
  logic: DetectionLogicExplanation;
  copiedId: string | null;
  setCopiedId: (id: string | null) => void;
}) {
  const fullText = [
    logic.humanReadable,
    logic.conditions?.length ? "\n\nConditions:\n" + logic.conditions.map((c) => `• ${c}`).join("\n") : "",
    logic.tuningGuidance ? `\n\nTuning:\n${logic.tuningGuidance}` : "",
    logic.whenToFire ? `\n\nWhen to fire:\n${logic.whenToFire}` : "",
  ].join("");
  return (
    <div className="space-y-4 text-sm">
      <p className="text-muted-foreground leading-relaxed">{logic.humanReadable}</p>
      {logic.conditions && logic.conditions.length > 0 && (
        <div>
          <p className={sectionLabelClass}>Exact Conditions</p>
          <ul className="list-disc list-inside text-muted-foreground space-y-1">
            {logic.conditions.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
      )}
      {logic.tuningGuidance && (
        <div>
          <p className={sectionLabelClass}>Tuning Guidance</p>
          <p className="text-muted-foreground">{logic.tuningGuidance}</p>
        </div>
      )}
      {logic.whenToFire && (
        <div>
          <p className={sectionLabelClass}>When to Fire</p>
          <p className="text-muted-foreground">{logic.whenToFire}</p>
        </div>
      )}
      <div className="pt-2">
        <Button
          variant="outline"
          size="sm"
          className="text-xs"
          onClick={() => {
            navigator.clipboard.writeText(fullText);
            setCopiedId("detection-logic");
            setTimeout(() => setCopiedId(null), 2000);
          }}
        >
          {copiedId === "detection-logic" ? <><Check className="h-3 w-3 mr-1" /> Copied</> : <><Copy className="h-3 w-3 mr-1" /> Copy</>}
          Copy full explanation
        </Button>
      </div>
    </div>
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
  const header = phase != null ? (
    <span className="flex items-center gap-2">
      <span className="text-xs font-mono text-muted-foreground bg-muted px-2 py-0.5 rounded">Phase {phase}</span>
      {title}
    </span>
  ) : title;

  if (!collapsible) {
    return (
      <div className="mb-8 rounded-lg border border-border/50 bg-card p-6">
        <h2 className="font-display text-lg font-semibold mb-4">{header}</h2>
        {children}
      </div>
    );
  }

  return (
    <Collapsible open={open} onOpenChange={setOpen} className="mb-8">
      <div className="rounded-lg border border-border/50 bg-card overflow-hidden">
        <CollapsibleTrigger className="w-full flex items-center gap-2 px-6 py-4 text-left hover:bg-muted/30 transition-colors">
          {open ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
          <h2 className="font-display text-lg font-semibold">{header}</h2>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <div className="px-6 pb-6 pt-0">{children}</div>
        </CollapsibleContent>
      </div>
    </Collapsible>
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
        {["json", "hcl", "yaml"].includes(language) ? renderCodeWithColoredKeys(content, language) : <code>{content}</code>}
      </pre>
    </div>
  );
}

const COMMUNITY_VOTES_KEY = "detecting-cloud-community-votes";
const COMMUNITY_VOTED_KEY = "detecting-cloud-community-voted";

function getCommunityVotes(detectionId: string): CommunityConfidence {
  try {
    const stored = localStorage.getItem(COMMUNITY_VOTES_KEY);
    if (stored) {
      const parsed = JSON.parse(stored) as Record<string, CommunityConfidence>;
      return parsed[detectionId] ?? { accurate: 0, needsTuning: 0, noisy: 0 };
    }
  } catch {
    // ignore
  }
  return { accurate: 0, needsTuning: 0, noisy: 0 };
}

function hasUserVoted(detectionId: string): boolean {
  try {
    const stored = localStorage.getItem(COMMUNITY_VOTED_KEY);
    if (stored) {
      const parsed = JSON.parse(stored) as Record<string, boolean>;
      return !!parsed[detectionId];
    }
  } catch {
    // ignore
  }
  return false;
}

function setCommunityVote(detectionId: string, vote: "accurate" | "needsTuning" | "noisy") {
  try {
    // Save vote
    const stored = localStorage.getItem(COMMUNITY_VOTES_KEY);
    const parsed: Record<string, CommunityConfidence> = stored ? JSON.parse(stored) : {};
    const current = parsed[detectionId] ?? { accurate: 0, needsTuning: 0, noisy: 0 };
    current[vote] = (current[vote] ?? 0) + 1;
    parsed[detectionId] = current;
    localStorage.setItem(COMMUNITY_VOTES_KEY, JSON.stringify(parsed));

    // Mark as voted
    const votedStored = localStorage.getItem(COMMUNITY_VOTED_KEY);
    const votedParsed: Record<string, boolean> = votedStored ? JSON.parse(votedStored) : {};
    votedParsed[detectionId] = true;
    localStorage.setItem(COMMUNITY_VOTED_KEY, JSON.stringify(votedParsed));
  } catch {
    // ignore
  }
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
  const [communityVotes, setCommunityVotesState] = useState<CommunityConfidence>(() =>
    getCommunityVotes(detection.id)
  );
  const [hasVoted, setHasVoted] = useState(() => hasUserVoted(detection.id));

  const handleVote = useCallback(
    (vote: "accurate" | "needsTuning" | "noisy") => {
      if (hasVoted) return;
      setCommunityVote(detection.id, vote);
      setCommunityVotesState(getCommunityVotes(detection.id));
      setHasVoted(true);
    },
    [detection.id, hasVoted]
  );

  const availableFormats = Object.entries(detection.rules).filter(([, v]) => !!v);

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

      {/* Phase 3: Data Modeling & Normalization */}
      {lifecycle.dataModeling && (
        <SectionCard title="Data Modeling and Log Normalization" phase={3} collapsible defaultOpen>
          <DataModelingSection modeling={lifecycle.dataModeling} copiedId={copiedId} setCopiedId={setCopiedId} />
        </SectionCard>
      )}

      {/* Phase 4: Enrichment & Context */}
      {lifecycle.enrichment && lifecycle.enrichment.length > 0 && (
        <SectionCard title="Enrichment and Context" phase={4} collapsible defaultOpen>
          <EnrichmentSection enrichment={lifecycle.enrichment} />
        </SectionCard>
      )}

      {/* Phase 5: Detection Logic */}
      <SectionCard title="Writing the Detection Rule" phase={5} collapsible defaultOpen>
        <DetectionRuleSection
          detection={detection}
          lifecycle={lifecycle}
          formatLabels={formatLabels}
          highlightCode={highlightCode}
          copiedId={copiedId}
          setCopiedId={setCopiedId}
        />
      </SectionCard>

      {/* Phase 6: Detection Testing */}
      <SectionCard title="Testing the Detection" phase={6} collapsible defaultOpen>
        <DetectionTestingSection detection={detection} simulationCommand={lifecycle.simulationCommand} />
      </SectionCard>

      {/* Phase 7: Deployment */}
      {lifecycle.deployment && (
        <SectionCard title="Deployment and CI/CD" phase={7} collapsible defaultOpen>
          <DeploymentSection deployment={lifecycle.deployment} />
        </SectionCard>
      )}

      {/* Detection Quality & Community */}
      <SectionCard title="Detection Quality & Community" collapsible defaultOpen>
        <DetectionQualitySection
          quality={lifecycle.quality}
          communityVotes={communityVotes}
          onVote={handleVote}
          hasVoted={hasVoted}
        />
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

const sectionLabelClass = "text-xs font-semibold uppercase tracking-wider mb-1 text-amber-400";

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

function DataModelingSection({
  modeling,
  copiedId,
  setCopiedId,
}: {
  modeling: DataModeling;
  copiedId: string | null;
  setCopiedId: (id: string | null) => void;
}) {
  return (
    <div className="space-y-4">
      <div>
        <p className={`${sectionLabelClass} mb-2`}>Field Mappings (Raw → Normalized)</p>
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/50">
                <th className="px-4 py-2 text-left font-medium">Raw Path</th>
                <th className="px-4 py-2 text-left font-medium">Normalized Path</th>
                <th className="px-4 py-2 text-left font-medium">Notes</th>
              </tr>
            </thead>
            <tbody>
              {modeling.rawToNormalized.map((m, i) => (
                <tr key={i} className="border-b border-border/50 last:border-0">
                  <td className="px-4 py-2 font-mono text-xs">{m.rawPath}</td>
                  <td className="px-4 py-2 font-mono text-xs">{m.normalizedPath}</td>
                  <td className="px-4 py-2 text-muted-foreground text-xs">{m.notes ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
      <div>
        <p className={`${sectionLabelClass} mb-2`}>Example Normalized Event</p>
        <CodeBlockWithCopy content={modeling.exampleNormalizedEvent} language="json" copiedId={copiedId} setCopiedId={setCopiedId} copyKey="normalized" />
      </div>
    </div>
  );
}

function EnrichmentSection({ enrichment }: { enrichment: EnrichmentContext[] }) {
  return (
    <div className="space-y-4">
      {enrichment.map((e, i) => (
        <div key={i} className="rounded-lg border border-border/50 p-4 space-y-2">
          <p className="text-xs font-semibold uppercase tracking-wider text-amber-400">{e.dimension}</p>
          <p className="text-sm text-muted-foreground">{e.description}</p>
          <ul className="list-disc list-inside text-xs text-muted-foreground space-y-1">
            {e.examples.map((ex, j) => (
              <li key={j}>{ex}</li>
            ))}
          </ul>
          {e.falsePositiveReduction && (
            <p className="text-xs text-primary/90 pt-1">
              <strong>FP reduction:</strong> {e.falsePositiveReduction}
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
        <pre className="rounded-lg border border-border bg-muted/30 p-4 font-mono text-xs overflow-x-auto">
          {simulationCommand ?? "Run the relevant API call or CLI command for this detection."}
        </pre>
      </div>
      {exampleEvent && (
        <div>
          <p className={`${sectionLabelClass} mb-2`}>Expected Log Output</p>
          <pre className="rounded-lg border border-border bg-muted/30 p-4 font-mono text-xs overflow-x-auto">
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

function DeploymentSection({ deployment }: { deployment: DeploymentInfo }) {
  return (
    <div className="space-y-4 text-sm">
      <div>
        <p className={`${sectionLabelClass} mb-2`}>Where It Runs</p>
        <ul className="list-disc list-inside text-muted-foreground space-y-1">
          {deployment.whereItRuns.map((w, i) => (
            <li key={i}>{w}</li>
          ))}
        </ul>
      </div>
      {deployment.scheduling && (
        <div>
          <p className={`${sectionLabelClass} mb-2`}>Scheduling</p>
          <p className="text-muted-foreground">{deployment.scheduling}</p>
        </div>
      )}
      {deployment.considerations && deployment.considerations.length > 0 && (
        <div>
          <p className={`${sectionLabelClass} mb-2`}>Practical Considerations</p>
          <ul className="list-disc list-inside text-muted-foreground space-y-1">
            {deployment.considerations.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
      )}
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
          <p className={`${sectionLabelClass} mb-2`}>Related Attack Paths</p>
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

function DetectionQualitySection({
  quality,
  communityVotes,
  onVote,
  hasVoted,
}: {
  quality?: DetectionQuality;
  communityVotes: CommunityConfidence;
  onVote: (vote: "accurate" | "needsTuning" | "noisy") => void;
  hasVoted: boolean;
}) {
  return (
    <div className="space-y-6">
      {quality && <QualityMetricsVisual quality={quality} />}

      <div>
        <p className={`${sectionLabelClass} mb-3`}>Community Confidence</p>
        {hasVoted && (
          <p className="text-xs text-muted-foreground mb-2">Thanks for voting!</p>
        )}
        <div className="flex flex-wrap gap-4 items-center">
          <Button variant="outline" size="sm" className="gap-1.5" onClick={() => onVote("accurate")} disabled={hasVoted}>
            <ThumbsUp className="h-3.5 w-3.5" />
            Accurate ({communityVotes.accurate})
          </Button>
          <Button variant="outline" size="sm" className="gap-1.5" onClick={() => onVote("needsTuning")} disabled={hasVoted}>
            <AlertTriangle className="h-3.5 w-3.5" />
            Needs tuning ({communityVotes.needsTuning})
          </Button>
          <Button variant="outline" size="sm" className="gap-1.5" onClick={() => onVote("noisy")} disabled={hasVoted}>
            <ThumbsDown className="h-3.5 w-3.5" />
            Noisy ({communityVotes.noisy})
          </Button>
        </div>
      </div>
    </div>
  );
}
