import { getTechniqueById, type Technique } from "@/data/techniques";
import { Badge } from "@/components/ui/badge";
import { ChevronRight } from "lucide-react";
import { Link } from "react-router-dom";
import type { AttackPathStep } from "@/data/attackPaths";

const categoryColor: Record<string, string> = {
  "initial-access": "bg-orange-500/15 text-orange-400 border-orange-500/30",
  "credential-access": "bg-red-500/15 text-red-400 border-red-500/30",
  "privilege-escalation": "bg-destructive/15 text-destructive border-destructive/30",
  "persistence": "bg-purple-500/15 text-purple-400 border-purple-500/30",
  "lateral-movement": "bg-accent/15 text-accent border-accent/30",
  "exfiltration": "bg-primary/15 text-primary border-primary/30",
  "defense-evasion": "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
};

interface AttackFlowChainProps {
  steps: AttackPathStep[];
  /** Show compact version (no context text) */
  compact?: boolean;
}

export function AttackFlowChain({ steps, compact = false }: AttackFlowChainProps) {
  const resolvedSteps = steps
    .map((step) => ({ ...step, technique: getTechniqueById(step.techniqueId) }))
    .filter((s) => s.technique) as (AttackPathStep & { technique: Technique })[];

  return (
    <div className="flex flex-col gap-0">
      {resolvedSteps.map((step, i) => (
        <div key={step.techniqueId + i} className="flex flex-col items-stretch">
          {/* Step node */}
          <Link
            to={`/attack-paths?technique=${step.techniqueId}`}
            className="group flex items-start gap-3 rounded-lg border border-border/50 bg-card p-3 hover:border-primary/40 hover:bg-primary/5 transition-all"
          >
            {/* Step number */}
            <div className="shrink-0 w-7 h-7 rounded-full bg-muted flex items-center justify-center text-xs font-mono font-bold text-foreground mt-0.5">
              {i + 1}
            </div>

            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1">
                <span className="font-semibold text-sm text-foreground group-hover:text-primary transition-colors">
                  {step.technique.shortName}
                </span>
                <Badge
                  className={`text-[10px] border px-1.5 py-0 ${categoryColor[step.technique.category] || "bg-muted text-muted-foreground border-border"}`}
                >
                  {step.technique.category.replace(/-/g, " ")}
                </Badge>
              </div>
              {!compact && step.context && (
                <p className="text-xs text-muted-foreground leading-relaxed">{step.context}</p>
              )}
              {!compact && (
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {step.technique.services.map((svc) => (
                    <span
                      key={svc}
                      className="text-[10px] px-1.5 py-0.5 rounded bg-accent/10 text-accent font-mono"
                    >
                      {svc}
                    </span>
                  ))}
                </div>
              )}
            </div>

            <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 mt-1 group-hover:text-primary transition-colors" />
          </Link>

          {/* Connector arrow */}
          {i < resolvedSteps.length - 1 && (
            <div className="flex justify-start ml-[13px]">
              <div className="w-px h-5 bg-border relative">
                <div className="absolute bottom-0 left-1/2 -translate-x-1/2 translate-y-[2px] w-0 h-0 border-l-[4px] border-l-transparent border-r-[4px] border-r-transparent border-t-[5px] border-t-border" />
              </div>
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
