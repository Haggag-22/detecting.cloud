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
