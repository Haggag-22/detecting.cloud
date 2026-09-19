import { cn } from "@/lib/utils";

/** Shared styling for numeric counts — teal accent (matches provider tab underline). */
export const countBadgeClassName =
  "inline-flex shrink-0 items-center justify-center rounded-md border border-teal-400/30 bg-teal-400/[0.12] font-mono font-semibold tabular-nums text-teal-200";

type CountBadgeProps = {
  children: React.ReactNode;
  className?: string;
  size?: "sm" | "md";
};

export function CountBadge({ children, className, size = "sm" }: CountBadgeProps) {
  return (
    <span
      className={cn(
        countBadgeClassName,
        size === "sm" && "min-w-[1.625rem] h-6 px-1.5 text-[11px]",
        size === "md" && "min-w-[2rem] h-7 px-2 text-xs",
        className
      )}
    >
      {children}
    </span>
  );
}
