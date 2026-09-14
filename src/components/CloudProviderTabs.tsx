import { cn } from "@/lib/utils";
import { CountBadge } from "@/components/CountBadge";

export type CloudProviderId = "all" | "aws" | "azure" | "gcp" | "kubernetes";

export const CLOUD_PROVIDERS: {
  id: CloudProviderId;
  label: string;
}[] = [
  { id: "all", label: "All" },
  { id: "aws", label: "AWS" },
  { id: "azure", label: "Azure" },
  { id: "gcp", label: "GCP" },
  { id: "kubernetes", label: "Kubernetes" },
];

const PROVIDER_LOGOS: Partial<Record<CloudProviderId, string>> = {
  aws: "/cloud-providers/aws.png",
  azure: "/cloud-providers/azure.png",
  gcp: "/cloud-providers/gcp.png",
  kubernetes: "/cloud-providers/kubernetes.png",
};

function ProviderIcon({ id }: { id: CloudProviderId }) {
  const src = PROVIDER_LOGOS[id];
  if (!src) return null;

  // AWS mark includes the smile under the letters — keep it a touch shorter
  // so it optically matches the adjacent label height.
  const aws = id === "aws";
  return (
    <img
      src={src}
      alt=""
      width={aws ? 36 : 22}
      height={aws ? 18 : 22}
      className={cn(
        "object-contain object-center shrink-0",
        aws ? "h-[18px] w-9" : "h-[22px] w-[22px]"
      )}
      draggable={false}
    />
  );
}

type CloudProviderTabsProps = {
  value: CloudProviderId;
  counts: Record<CloudProviderId, number>;
  onChange: (id: CloudProviderId) => void;
  className?: string;
  /** Omit providers not listed; defaults to all tabs */
  visibleProviders?: CloudProviderId[];
};

export function CloudProviderTabs({
  value,
  counts,
  onChange,
  className,
  visibleProviders,
}: CloudProviderTabsProps) {
  const providers = visibleProviders
    ? CLOUD_PROVIDERS.filter((p) => visibleProviders.includes(p.id))
    : CLOUD_PROVIDERS;

  return (
    <div
      className={cn(
        "flex flex-wrap items-end gap-6 border-b border-border/60 mb-8",
        className
      )}
      role="tablist"
      aria-label="Cloud providers"
    >
      {providers.map((p) => {
        const active = value === p.id;
        const count = counts[p.id] ?? 0;
        return (
          <button
            key={p.id}
            type="button"
            role="tab"
            aria-selected={active}
            onClick={() => onChange(p.id)}
            className={cn(
              "relative flex items-center gap-2.5 pb-3 text-base leading-none transition-colors",
              "text-muted-foreground hover:text-foreground/80"
            )}
          >
            {p.id !== "all" && <ProviderIcon id={p.id} />}
            <span className="font-medium leading-none">{p.label}</span>
            <CountBadge>{count}</CountBadge>
            {active && (
              <span className="absolute inset-x-0 -bottom-px h-0.5 rounded-full bg-teal-400" />
            )}
          </button>
        );
      })}
    </div>
  );
}
