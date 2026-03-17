import React, { useState, useCallback } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { ChevronDown, ChevronRight, ThumbsUp, AlertTriangle, ThumbsDown, Copy, Check } from "lucide-react";
import { renderCodeWithColoredKeys } from "@/lib/codeHighlight";
import { QualityMetricsVisual } from "@/components/DetectionVisuals";
import type {
  Detection,
  DetectionLifecycle,
  ThreatContext,
  TelemetryValidation,
  DataModeling,
  EnrichmentContext,
  DetectionQuality,
  CommunityConfidence,
} from "@/data/detections";

const formatLabels: Record<string, string> = {
  sigma: "Sigma Rule",
  splunk: "Splunk Query",
  cloudtrail: "CloudTrail Athena",
  cloudwatch: "CloudWatch Insights",
  eventbridge: "EventBridge Rule Pattern",
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
  return code;
}

function SectionCard({
  title,
  children,
  collapsible = false,
  defaultOpen = true,
}: {
  title: string;
  children: React.ReactNode;
  collapsible?: boolean;
  defaultOpen?: boolean;
}) {
  const [open, setOpen] = useState(defaultOpen);

  if (!collapsible) {
    return (
      <div className="mb-8 rounded-lg border border-border/50 bg-card p-6">
        <h2 className="font-display text-lg font-semibold mb-4">{title}</h2>
        {children}
      </div>
    );
  }

  return (
    <Collapsible open={open} onOpenChange={setOpen} className="mb-8">
      <div className="rounded-lg border border-border/50 bg-card overflow-hidden">
        <CollapsibleTrigger className="w-full flex items-center gap-2 px-6 py-4 text-left hover:bg-muted/30 transition-colors">
          {open ? <ChevronDown className="h-4 w-4 text-muted-foreground" /> : <ChevronRight className="h-4 w-4 text-muted-foreground" />}
          <h2 className="font-display text-lg font-semibold">{title}</h2>
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

function setCommunityVote(detectionId: string, vote: "accurate" | "needsTuning" | "noisy") {
  try {
    const stored = localStorage.getItem(COMMUNITY_VOTES_KEY);
    const parsed: Record<string, CommunityConfidence> = stored ? JSON.parse(stored) : {};
    const current = parsed[detectionId] ?? { accurate: 0, needsTuning: 0, noisy: 0 };
    current[vote] = (current[vote] ?? 0) + 1;
    parsed[detectionId] = current;
    localStorage.setItem(COMMUNITY_VOTES_KEY, JSON.stringify(parsed));
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
}: {
  detection: Detection;
  lifecycle: DetectionLifecycle;
  severityColors: Record<string, string>;
  copiedId: string | null;
  setCopiedId: (id: string | null) => void;
}) {
  const [communityVotes, setCommunityVotesState] = useState<CommunityConfidence>(() =>
    getCommunityVotes(detection.id)
  );

  const handleVote = useCallback(
    (vote: "accurate" | "needsTuning" | "noisy") => {
      setCommunityVote(detection.id, vote);
      setCommunityVotesState(getCommunityVotes(detection.id));
    },
    [detection.id]
  );

  const availableFormats = Object.entries(detection.rules).filter(([, v]) => !!v);

  return (
    <>
      {/* 1. Detection Overview - not collapsible, rendered by parent with MITRE from lifecycle */}

      {/* 2. Threat Context */}
      {lifecycle.threatContext && (
        <SectionCard title="Threat Context" collapsible defaultOpen>
          <ThreatContextSection context={lifecycle.threatContext} />
        </SectionCard>
      )}

      {/* 3. Telemetry & Data Validation */}
      {lifecycle.telemetryValidation && (
        <SectionCard title="Telemetry & Data Validation" collapsible defaultOpen>
          <TelemetryValidationSection validation={lifecycle.telemetryValidation} />
        </SectionCard>
      )}

      {/* 4. Data Modeling & Normalization */}
      {lifecycle.dataModeling && (
        <SectionCard title="Data Modeling & Normalization" collapsible defaultOpen>
          <DataModelingSection modeling={lifecycle.dataModeling} copiedId={copiedId} setCopiedId={setCopiedId} />
        </SectionCard>
      )}

      {/* 5. Enrichment & Context */}
      {lifecycle.enrichment && lifecycle.enrichment.length > 0 && (
        <SectionCard title="Enrichment & Context" collapsible defaultOpen>
          <EnrichmentSection enrichment={lifecycle.enrichment} />
        </SectionCard>
      )}

      {/* 6. Detection Logic - not collapsible */}
      <SectionCard title="Detection Logic" collapsible={false}>
        {lifecycle.logicExplanation && (
          <p className="text-sm text-muted-foreground mb-4">{lifecycle.logicExplanation.humanReadable}</p>
        )}
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
              <div className="rounded-lg border border-border overflow-hidden mt-4">
                <div className="px-4 py-2 bg-muted text-xs text-muted-foreground font-mono border-b border-border flex items-center justify-between">
                  <span>{formatLabels[key]}</span>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
                    onClick={() => {
                      navigator.clipboard.writeText(value as string);
                      setCopiedId(key);
                      setTimeout(() => setCopiedId(null), 2000);
                    }}
                  >
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
      </SectionCard>

      {/* 7. Detection Testing */}
      <SectionCard title="Detection Testing" collapsible defaultOpen>
        <DetectionTestingSection detection={detection} simulationCommand={lifecycle.simulationCommand} />
      </SectionCard>

      {/* 8. Detection Quality & Community */}
      <SectionCard title="Detection Quality & Community" collapsible defaultOpen>
        <DetectionQualitySection
          quality={lifecycle.quality}
          communityVotes={communityVotes}
          onVote={handleVote}
        />
      </SectionCard>
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

function DetectionQualitySection({
  quality,
  communityVotes,
  onVote,
}: {
  quality?: DetectionQuality;
  communityVotes: CommunityConfidence;
  onVote: (vote: "accurate" | "needsTuning" | "noisy") => void;
}) {
  return (
    <div className="space-y-6">
      {quality && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="rounded-lg border border-border/50 p-4">
            <p className={sectionLabelClass}>Signal Quality</p>
            <p className="font-semibold text-lg">{quality.signalQuality}/10</p>
          </div>
          <div className="rounded-lg border border-border/50 p-4">
            <p className={sectionLabelClass}>False Positive Rate</p>
            <p className="font-medium text-sm">{quality.falsePositiveRate}</p>
          </div>
          <div className="rounded-lg border border-border/50 p-4">
            <p className={sectionLabelClass}>Expected Volume</p>
            <p className="font-medium text-sm">{quality.expectedVolume}</p>
          </div>
          <div className="rounded-lg border border-border/50 p-4">
            <p className={sectionLabelClass}>Production Readiness</p>
            <Badge variant="outline" className="capitalize">{quality.productionReadiness}</Badge>
          </div>
        </div>
      )}

      <div>
        <p className={`${sectionLabelClass} mb-3`}>Community Confidence</p>
        <div className="flex flex-wrap gap-4 items-center">
          <Button variant="outline" size="sm" className="gap-1.5" onClick={() => onVote("accurate")}>
            <ThumbsUp className="h-3.5 w-3.5" />
            Accurate ({communityVotes.accurate})
          </Button>
          <Button variant="outline" size="sm" className="gap-1.5" onClick={() => onVote("needsTuning")}>
            <AlertTriangle className="h-3.5 w-3.5" />
            Needs tuning ({communityVotes.needsTuning})
          </Button>
          <Button variant="outline" size="sm" className="gap-1.5" onClick={() => onVote("noisy")}>
            <ThumbsDown className="h-3.5 w-3.5" />
            Noisy ({communityVotes.noisy})
          </Button>
        </div>
      </div>
    </div>
  );
}
