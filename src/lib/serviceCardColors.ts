import { cn } from "@/lib/utils";

/** Default service card surface — 1px border, visible but not heavy. */
export function getServiceCardClassName(options?: { active?: boolean }): string {
  if (options?.active) {
    return cn(
      "rounded-lg border border-primary/40 bg-primary/5 transition-colors"
    );
  }
  return cn(
    "rounded-lg border border-border/50 bg-card transition-colors",
    "hover:border-primary/30"
  );
}
