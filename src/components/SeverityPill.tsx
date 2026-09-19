import { SEVERITY_PILL_CLASS, SEVERITY_PILL_DOT } from "@/lib/severityStyles";

export function SeverityPill({ severity }: { severity: string }) {
  const pillClass = SEVERITY_PILL_CLASS[severity] ?? SEVERITY_PILL_CLASS.Low;
  const dotClass = SEVERITY_PILL_DOT[severity] ?? SEVERITY_PILL_DOT.Low;

  return (
    <span
      className={`inline-flex shrink-0 items-center gap-1.5 rounded-full border px-2.5 py-1 text-[11px] font-medium leading-none ${pillClass}`}
    >
      <span className={`h-1.5 w-1.5 rounded-full shrink-0 ${dotClass}`} />
      {severity}
    </span>
  );
}
