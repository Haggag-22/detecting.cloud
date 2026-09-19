import { Layout } from "@/components/Layout";
import {
  techniques,
  techniqueCategories,
  getTechniqueCloudProvider,
  getTechniqueCountsByCloudProvider,
  type TechniqueCategory,
} from "@/data/techniques";
import { CountBadge } from "@/components/CountBadge";
import { Route, ChevronRight } from "lucide-react";
import { PageTitleWithIcon } from "@/components/PageTitleWithIcon";
import { Link, useSearchParams } from "react-router-dom";
import { CloudProviderTabs, parseCloudProviderId, type CloudProviderId } from "@/components/CloudProviderTabs";
import { getServiceCardClassName } from "@/lib/serviceCardColors";
import { cn } from "@/lib/utils";
import {
  TECHNIQUE_CATEGORY_ICON,
  TECHNIQUE_CATEGORY_ICON_COLOR,
} from "@/lib/techniqueCategoryStyles";

function techniquesHref(provider: CloudProviderId, category?: TechniqueCategory) {
  const params = new URLSearchParams();
  if (provider !== "all") params.set("provider", provider);
  if (category) params.set("category", category);
  const query = params.toString();
  return query ? `/techniques?${query}` : "/techniques";
}

function providerLabel(id: CloudProviderId): string | null {
  if (id === "all") return null;
  return id.toUpperCase();
}

function TechniqueCard({ tech }: { tech: (typeof techniques)[number] }) {
  const TechCatIcon = TECHNIQUE_CATEGORY_ICON[tech.category];
  return (
    <Link
      to={`/attack-paths/technique/${tech.id}`}
      className="flex flex-col h-full rounded-lg border border-border/50 bg-muted/20 p-4 hover:border-primary/30 transition-colors group"
    >
      <div className="flex items-start gap-2.5 mb-2">
        {TechCatIcon && (
          <TechCatIcon className={`h-[18px] w-[18px] mt-0.5 shrink-0 ${TECHNIQUE_CATEGORY_ICON_COLOR[tech.category] || "text-muted-foreground"}`} />
        )}
        <h3 className="font-semibold text-sm leading-snug flex-1 min-w-0 group-hover:text-primary transition-colors">
          {tech.name}
        </h3>
      </div>
      <p className="text-xs text-muted-foreground leading-relaxed line-clamp-2 flex-1">
        {tech.description}
      </p>
    </Link>
  );
}

export default function TechniquesLibrary() {
  const [searchParams, setSearchParams] = useSearchParams();
  const categoryParam = searchParams.get("category") as TechniqueCategory | null;
  const activeCategory =
    categoryParam && categoryParam in techniqueCategories ? categoryParam : null;
  const activeProvider = parseCloudProviderId(searchParams.get("provider"));

  const providerCounts = getTechniqueCountsByCloudProvider();
  const scopedTechniques =
    activeProvider === "all"
      ? techniques
      : techniques.filter((t) => getTechniqueCloudProvider(t) === activeProvider);

  const categories = (Object.keys(techniqueCategories) as TechniqueCategory[]).filter((catKey) =>
    scopedTechniques.some((t) => t.category === catKey),
  );

  const setProvider = (id: CloudProviderId) => {
    const next = new URLSearchParams(searchParams);
    if (id === "all") next.delete("provider");
    else next.set("provider", id);
    next.delete("category");
    setSearchParams(next);
  };

  if (activeCategory) {
    const catTechniques = scopedTechniques.filter((t) => t.category === activeCategory);
    const CatIcon = TECHNIQUE_CATEGORY_ICON[activeCategory];
    const label = providerLabel(activeProvider);

    return (
      <Layout>
        <div className="container">
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-6">
            <Link to={techniquesHref(activeProvider)} className="hover:text-foreground transition-colors">
              Attack Techniques
            </Link>
            <ChevronRight className="h-3.5 w-3.5" />
            {label && (
              <>
                <Link
                  to={techniquesHref(activeProvider)}
                  className="hover:text-foreground transition-colors"
                >
                  {label}
                </Link>
                <ChevronRight className="h-3.5 w-3.5" />
              </>
            )}
            <span className="text-foreground">{techniqueCategories[activeCategory].label}</span>
          </div>

          <div className="flex items-center gap-3 mb-2">
            {CatIcon && <CatIcon className={`h-8 w-8 shrink-0 ${TECHNIQUE_CATEGORY_ICON_COLOR[activeCategory]}`} />}
            <h1 className="font-display text-3xl font-bold tracking-tight">
              {techniqueCategories[activeCategory].label}
            </h1>
          </div>
          <p className="text-muted-foreground mb-8">
            {catTechniques.length} {catTechniques.length === 1 ? "technique" : "techniques"} in this category
            {label ? ` · ${label}` : ""}.
          </p>

          {catTechniques.length > 0 ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {catTechniques.map((tech) => (
                <TechniqueCard key={tech.id} tech={tech} />
              ))}
            </div>
          ) : (
            <div className="rounded-lg border border-dashed border-border/50 bg-card/40 px-6 py-14 text-center">
              <p className="text-sm text-muted-foreground">
                No {label ?? ""} techniques in this category.
              </p>
            </div>
          )}
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="container">
        <PageTitleWithIcon team="red" icon={Route}>
          Attack Techniques
        </PageTitleWithIcon>
        <p className="text-muted-foreground mb-6">
          Attack techniques organized by cloud provider and category. Select a provider, then a category to
          browse techniques.
        </p>

        <CloudProviderTabs
          value={activeProvider}
          counts={providerCounts}
          onChange={setProvider}
        />

        {categories.length > 0 ? (
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
            {categories.map((catKey) => {
              const count = scopedTechniques.filter((t) => t.category === catKey).length;
              const CatIcon = TECHNIQUE_CATEGORY_ICON[catKey];
              return (
                <button
                  key={catKey}
                  type="button"
                  onClick={() => setSearchParams({
                    category: catKey,
                    ...(activeProvider !== "all" ? { provider: activeProvider } : {}),
                  })}
                  className={cn(
                    getServiceCardClassName(),
                    "px-4 py-3.5 text-left group flex items-center gap-3"
                  )}
                >
                  {CatIcon && (
                    <CatIcon className={`h-7 w-7 shrink-0 ${TECHNIQUE_CATEGORY_ICON_COLOR[catKey] || "text-muted-foreground"}`} />
                  )}
                  <h2 className="font-display font-semibold text-base truncate flex-1 min-w-0 group-hover:text-primary transition-colors">
                    {techniqueCategories[catKey].label}
                  </h2>
                  <CountBadge>{count}</CountBadge>
                  <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 group-hover:text-foreground transition-colors" />
                </button>
              );
            })}
          </div>
        ) : (
          <div className="rounded-lg border border-dashed border-border/50 bg-card/40 px-6 py-14 text-center">
            <p className="text-sm text-muted-foreground">
              {activeProvider === "all"
                ? "No techniques yet."
                : `No ${activeProvider.toUpperCase()} techniques yet. AWS techniques are available under the AWS tab.`}
            </p>
          </div>
        )}
      </div>
    </Layout>
  );
}
