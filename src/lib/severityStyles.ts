/** Shared severity badge / pill colors (Critical → Low). */
export const SEVERITY_BADGE_CLASS: Record<string, string> = {
  Critical: "bg-severity-critical/15 text-severity-critical",
  High: "bg-severity-high/15 text-severity-high",
  Medium: "bg-severity-medium/15 text-severity-medium",
  Low: "bg-severity-low/15 text-severity-low",
};

/** Outline badges (Attack Simulator, Community Rules, CloudTrail). */
export const SEVERITY_OUTLINE_CLASS: Record<string, string> = {
  Critical: "bg-severity-critical/15 text-severity-critical border-severity-critical/30",
  High: "bg-severity-high/15 text-severity-high border-severity-high/30",
  Medium: "bg-severity-medium/15 text-severity-medium border-severity-medium/30",
  Low: "bg-severity-low/15 text-severity-low border-severity-low/30",
};

export const SEVERITY_PILL_CLASS: Record<string, string> = {
  Critical: "border-severity-critical/35 bg-severity-critical/10 text-severity-critical",
  High: "border-severity-high/35 bg-severity-high/10 text-severity-high",
  Medium: "border-severity-medium/35 bg-severity-medium/10 text-severity-medium",
  Low: "border-severity-low/35 bg-severity-low/10 text-severity-low",
};

export const SEVERITY_PILL_DOT: Record<string, string> = {
  Critical: "bg-severity-critical",
  High: "bg-severity-high",
  Medium: "bg-severity-medium",
  Low: "bg-severity-low",
};

export function severityBadgeClass(severity: string): string {
  return SEVERITY_BADGE_CLASS[severity] ?? SEVERITY_BADGE_CLASS.Low;
}

export function severityOutlineClass(severity: string): string {
  return SEVERITY_OUTLINE_CLASS[severity] ?? SEVERITY_OUTLINE_CLASS.Low;
}
