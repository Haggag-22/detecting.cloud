import { Layout } from "@/components/Layout";
import { techniques, techniqueCategories, type TechniqueCategory } from "@/data/techniques";
import { Badge } from "@/components/ui/badge";
import {
  Crosshair, KeyRound, TrendingUp, Server, Wifi, Database, ShieldOff, Route, ChevronRight,
} from "lucide-react";
import { PageTitleWithIcon } from "@/components/PageTitleWithIcon";
import { Link, useSearchParams } from "react-router-dom";
import { LucideIcon } from "lucide-react";

const categoryIcon: Record<string, LucideIcon> = {
  "initial-access": Crosshair,
  "credential-access": KeyRound,
  "privilege-escalation": TrendingUp,
  "persistence": Server,
  "lateral-movement": Wifi,
  "exfiltration": Database,
  "defense-evasion": ShieldOff,
};

const categoryIconColor: Record<string, string> = {
  "initial-access": "text-cyan-400",
  "credential-access": "text-purple-400",
  "privilege-escalation": "text-red-400",
  "persistence": "text-orange-400",
  "lateral-movement": "text-blue-400",
  "exfiltration": "text-emerald-400",
  "defense-evasion": "text-amber-400",
};

const categoryColor: Record<string, string> = {
  "initial-access": "bg-cyan-500/15 text-cyan-400",
  "credential-access": "bg-purple-500/15 text-purple-400",
  "privilege-escalation": "bg-red-500/15 text-red-400",
  "persistence": "bg-orange-500/15 text-orange-400",
  "lateral-movement": "bg-blue-500/15 text-blue-400",
  "exfiltration": "bg-emerald-500/15 text-emerald-400",
  "defense-evasion": "bg-amber-500/15 text-amber-400",
};

const categoryBorderHover: Record<string, string> = {
  "initial-access": "hover:border-cyan-500/40",
  "credential-access": "hover:border-purple-500/40",
  "privilege-escalation": "hover:border-red-500/40",
  "persistence": "hover:border-orange-500/40",
  "lateral-movement": "hover:border-blue-500/40",
  "exfiltration": "hover:border-emerald-500/40",
  "defense-evasion": "hover:border-amber-500/40",
};

function TechniqueCard({ tech }: { tech: (typeof techniques)[number] }) {
  const TechCatIcon = categoryIcon[tech.category];
  return (
    <Link
      to={`/attack-paths/technique/${tech.id}`}
      className="rounded-lg border border-border/50 bg-card p-4 hover:border-primary/30 transition-colors group"
    >
      <div className="flex items-center gap-2 mb-1">
        <Badge className={`text-[10px] border-0 uppercase tracking-wide flex items-center gap-1 ${categoryColor[tech.category] || "bg-muted text-muted-foreground"}`}>
          {TechCatIcon && <TechCatIcon className={`h-3 w-3 ${categoryIconColor[tech.category] || ""}`} />}
          {tech.category.replace(/-/g, " ")}
        </Badge>
      </div>
      <h4 className="font-semibold text-sm mb-1 group-hover:text-primary transition-colors">{tech.name}</h4>
      <p className="text-xs text-muted-foreground line-clamp-2">{tech.description}</p>
      <div className="flex flex-wrap gap-1 mt-2">
        {tech.services.map((svc) => (
          <span key={svc} className="text-[10px] px-1.5 py-0.5 rounded bg-muted text-muted-foreground font-mono">
            {svc}
          </span>
        ))}
      </div>
    </Link>
  );
}

export default function TechniquesLibrary() {
  const [searchParams, setSearchParams] = useSearchParams();
  const categoryParam = searchParams.get("category") as TechniqueCategory | null;
  const activeCategory =
    categoryParam && categoryParam in techniqueCategories ? categoryParam : null;

  const categories = (Object.keys(techniqueCategories) as TechniqueCategory[]).filter(
    (catKey) => techniques.some((t) => t.category === catKey),
  );

  if (activeCategory) {
    const catTechniques = techniques.filter((t) => t.category === activeCategory);
    const CatIcon = categoryIcon[activeCategory];

    return (
      <Layout>
        <div className="container py-12">
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-6">
            <Link to="/techniques" className="hover:text-foreground transition-colors">
              Techniques Library
            </Link>
            <ChevronRight className="h-3.5 w-3.5" />
            <span className="text-foreground">{techniqueCategories[activeCategory].label}</span>
          </div>

          <div className="flex items-center gap-3 mb-2">
            {CatIcon && <CatIcon className={`h-8 w-8 shrink-0 ${categoryIconColor[activeCategory]}`} />}
            <h1 className="font-display text-3xl font-bold tracking-tight">
              {techniqueCategories[activeCategory].label}
            </h1>
          </div>
          <p className="text-muted-foreground mb-8">
            {catTechniques.length} {catTechniques.length === 1 ? "technique" : "techniques"} in this category.
          </p>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {catTechniques.map((tech) => (
              <TechniqueCard key={tech.id} tech={tech} />
            ))}
          </div>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="container py-12">
        <PageTitleWithIcon team="red" icon={Route}>
          Techniques Library
        </PageTitleWithIcon>
        <p className="text-muted-foreground mb-8">
          Browse attack techniques by category. Select a category to explore individual techniques.
        </p>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {categories.map((catKey) => {
            const count = techniques.filter((t) => t.category === catKey).length;
            const CatIcon = categoryIcon[catKey];
            return (
              <button
                key={catKey}
                type="button"
                onClick={() => setSearchParams({ category: catKey })}
                className={`rounded-lg border border-border/50 bg-card p-5 text-left transition-colors group ${categoryBorderHover[catKey] || "hover:border-primary/30"}`}
              >
                <div className="flex items-start gap-3">
                  {CatIcon && (
                    <CatIcon className={`h-6 w-6 shrink-0 mt-0.5 ${categoryIconColor[catKey] || "text-muted-foreground"}`} />
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2 mb-1">
                      <h2 className={`font-display font-semibold text-base group-hover:opacity-90 ${categoryIconColor[catKey] || ""}`}>
                        {techniqueCategories[catKey].label}
                      </h2>
                      <Badge variant="outline" className="text-xs border-border text-muted-foreground shrink-0">
                        {count}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {count} {count === 1 ? "technique" : "techniques"}
                    </p>
                  </div>
                  <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0 mt-1 group-hover:text-foreground transition-colors" />
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </Layout>
  );
}
