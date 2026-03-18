import React from "react";
import { motion } from "framer-motion";
import { Badge } from "@/components/ui/badge";
import { Shield, ShieldAlert, ShieldCheck, Activity, Zap } from "lucide-react";
import type { DetectionQuality } from "@/data/detections";

/** Animated severity gauge with arc visual */
export function SeverityGauge({ severity }: { severity: string }) {
  const severityConfig: Record<string, { angle: number; color: string; glow: string; icon: React.ReactNode }> = {
    Critical: { angle: 270, color: "hsl(0, 84%, 60%)", glow: "hsl(0, 84%, 60%)", icon: <ShieldAlert className="h-5 w-5" /> },
    High: { angle: 200, color: "hsl(25, 95%, 53%)", glow: "hsl(25, 95%, 53%)", icon: <Shield className="h-5 w-5" /> },
    Medium: { angle: 140, color: "hsl(43, 96%, 56%)", glow: "hsl(43, 96%, 56%)", icon: <Activity className="h-5 w-5" /> },
    Low: { angle: 80, color: "hsl(142, 71%, 45%)", glow: "hsl(142, 71%, 45%)", icon: <ShieldCheck className="h-5 w-5" /> },
  };

  const config = severityConfig[severity] ?? severityConfig.Medium;
  const radius = 40;
  const strokeWidth = 6;
  const circumference = Math.PI * radius; // half circle
  const progress = config.angle / 270;
  const dashOffset = circumference * (1 - progress);

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative w-24 h-14">
        <svg viewBox="0 0 100 55" className="w-full h-full">
          {/* Background arc */}
          <path
            d="M 10 50 A 40 40 0 0 1 90 50"
            fill="none"
            stroke="hsl(var(--muted))"
            strokeWidth={strokeWidth}
            strokeLinecap="round"
          />
          {/* Animated progress arc */}
          <motion.path
            d="M 10 50 A 40 40 0 0 1 90 50"
            fill="none"
            stroke={config.color}
            strokeWidth={strokeWidth}
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: dashOffset }}
            transition={{ duration: 1.2, ease: "easeOut", delay: 0.3 }}
            style={{
              filter: `drop-shadow(0 0 6px ${config.glow})`,
            }}
          />
        </svg>
        <motion.div
          className="absolute bottom-0 left-1/2 -translate-x-1/2 translate-y-1"
          initial={{ opacity: 0, scale: 0.5 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ delay: 0.6, duration: 0.4 }}
          style={{ color: config.color }}
        >
          {config.icon}
        </motion.div>
      </div>
      <motion.span
        className="text-xs font-semibold uppercase tracking-wider"
        style={{ color: config.color }}
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ delay: 0.8 }}
      >
        {severity}
      </motion.span>
    </div>
  );
}

/** MITRE ATT&CK kill chain timeline */
const KILL_CHAIN_ORDER = [
  "Reconnaissance",
  "Resource Development",
  "Initial Access",
  "Execution",
  "Persistence",
  "Privilege Escalation",
  "Defense Evasion",
  "Credential Access",
  "Discovery",
  "Lateral Movement",
  "Collection",
  "Command and Control",
  "Exfiltration",
  "Impact",
];

export function MitreTimeline({ mappings }: { mappings: MitreMapping[] }) {
  const activeTactics = new Set(mappings.map((m) => m.tactic));

  return (
    <div className="rounded-lg border border-border/50 bg-card p-5 mb-8">
      <p className="text-xs font-semibold uppercase tracking-wider text-amber-400 mb-4">MITRE ATT&CK Kill Chain</p>
      <div className="flex items-center gap-0.5 overflow-x-auto pb-2">
        {KILL_CHAIN_ORDER.map((tactic, i) => {
          const isActive = activeTactics.has(tactic);
          const mapping = mappings.find((m) => m.tactic === tactic);

          return (
            <React.Fragment key={tactic}>
              <motion.div
                className={`relative flex-shrink-0 px-2.5 py-2 rounded text-[10px] font-medium leading-tight text-center transition-colors cursor-default ${
                  isActive
                    ? "bg-primary/20 text-primary border border-primary/40 shadow-[0_0_12px_-3px_hsl(var(--primary)/0.4)]"
                    : "bg-muted/30 text-muted-foreground/50 border border-border/30"
                }`}
                style={{ minWidth: 72 }}
                initial={isActive ? { scale: 0.9, opacity: 0 } : {}}
                animate={isActive ? { scale: 1, opacity: 1 } : {}}
                transition={{ delay: 0.1 * i, duration: 0.4 }}
                title={mapping ? `${mapping.techniqueId ?? ""} ${mapping.techniqueName ?? ""}`.trim() : tactic}
              >
                <span className="block">{tactic}</span>
                {isActive && mapping?.techniqueId && (
                  <motion.span
                    className="block text-[9px] text-primary/70 mt-0.5 font-mono"
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: 0.1 * i + 0.3 }}
                  >
                    {mapping.techniqueId}
                  </motion.span>
                )}
                {isActive && (
                  <motion.div
                    className="absolute -top-1 -right-1 w-2.5 h-2.5 rounded-full bg-primary"
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ delay: 0.1 * i + 0.2, type: "spring", stiffness: 300 }}
                  />
                )}
              </motion.div>
              {i < KILL_CHAIN_ORDER.length - 1 && (
                <div className={`w-3 h-px flex-shrink-0 ${isActive ? "bg-primary/40" : "bg-border/30"}`} />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}

/** Animated quality metrics cards — no readiness card */
export function QualityMetricsVisual({ quality }: { quality: DetectionQuality }) {
  const signalPercent = (quality.signalQuality / 10) * 100;

  return (
    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
      {/* Signal Quality - circular progress */}
      <div className="rounded-lg border border-border/50 p-4 flex flex-col items-center gap-2">
        <p className="text-xs font-semibold uppercase tracking-wider text-amber-400">Signal Quality</p>
        <div className="relative w-16 h-16">
          <svg viewBox="0 0 40 40" className="w-full h-full -rotate-90">
            <circle cx="20" cy="20" r="16" fill="none" stroke="hsl(var(--muted))" strokeWidth="3" />
            <motion.circle
              cx="20"
              cy="20"
              r="16"
              fill="none"
              stroke="hsl(var(--primary))"
              strokeWidth="3"
              strokeLinecap="round"
              strokeDasharray={100.5}
              initial={{ strokeDashoffset: 100.5 }}
              animate={{ strokeDashoffset: 100.5 * (1 - signalPercent / 100) }}
              transition={{ duration: 1.2, ease: "easeOut", delay: 0.3 }}
              style={{ filter: "drop-shadow(0 0 4px hsl(var(--primary) / 0.4))" }}
            />
          </svg>
          <motion.span
            className="absolute inset-0 flex items-center justify-center text-sm font-bold text-foreground"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ delay: 0.8 }}
          >
            {quality.signalQuality}
          </motion.span>
        </div>
      </div>

      {/* False Positive Rate */}
      <div className="rounded-lg border border-border/50 p-4">
        <p className="text-xs font-semibold uppercase tracking-wider text-amber-400 mb-2">False Positive Rate</p>
        <p className="font-medium text-sm text-foreground">{quality.falsePositiveRate}</p>
      </div>

      {/* Expected Volume */}
      <div className="rounded-lg border border-border/50 p-4">
        <p className="text-xs font-semibold uppercase tracking-wider text-amber-400 mb-2">Expected Volume</p>
        <p className="font-medium text-sm text-foreground">{quality.expectedVolume}</p>
      </div>
    </div>
  );
}
