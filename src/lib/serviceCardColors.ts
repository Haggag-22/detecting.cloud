import { cn } from "@/lib/utils";

/** Default service card surface — neutral fill, stronger visible border. */
export function getServiceCardClassName(options?: { active?: boolean }): string {
  if (options?.active) {
    return cn(
      "rounded-lg border-2 border-primary/45 bg-primary/5 transition-colors"
    );
  }
  return cn(
    "rounded-lg border-2 border-border/80 bg-card transition-colors",
    "hover:border-primary/35"
  );
}
