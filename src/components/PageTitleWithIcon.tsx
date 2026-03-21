import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

export type PageTeam = "red" | "blue" | "neutral";

const teamIconClass: Record<PageTeam, string> = {
  red: "text-red-400/90",
  blue: "text-blue-400/90",
  neutral: "text-primary",
};

type PageTitleWithIconProps = {
  team: PageTeam;
  icon: LucideIcon;
  children: React.ReactNode;
  /** Classes on the flex wrapper (includes mb-2 by default) */
  className?: string;
  iconClassName?: string;
  titleClassName?: string;
};

/**
 * Page heading with the same icon + team accent as the app sidebar (red / blue / neutral).
 */
export function PageTitleWithIcon({
  team,
  icon: Icon,
  children,
  className,
  iconClassName,
  titleClassName,
}: PageTitleWithIconProps) {
  return (
    <div className={cn("flex items-center gap-3 mb-2", className)}>
      <Icon className={cn("h-8 w-8 shrink-0", teamIconClass[team], iconClassName)} aria-hidden />
      <h1 className={cn("font-display text-3xl font-bold tracking-tight", titleClassName)}>{children}</h1>
    </div>
  );
}
