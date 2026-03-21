import { Layout } from "@/components/Layout";
import { techniques, techniqueCategories, type TechniqueCategory } from "@/data/techniques";
import { Badge } from "@/components/ui/badge";
import {
  Crosshair, KeyRound, TrendingUp, Server, Wifi, Database, ShieldOff, Route,
} from "lucide-react";
import { PageTitleWithIcon } from "@/components/PageTitleWithIcon";
import { Link } from "react-router-dom";
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

export default function TechniquesLibrary() {
  return (
    <Layout>
      <div className="container py-12">
        <PageTitleWithIcon team="red" icon={Route}>
          Techniques Library
        </PageTitleWithIcon>
        <p className="text-muted-foreground mb-8">
          Browse all attack techniques by category. Each technique represents a single attacker action that can appear in multiple attack chains.
        </p>

        {(Object.keys(techniqueCategories) as TechniqueCategory[]).map((catKey) => {
          const catTechniques = techniques.filter((t) => t.category === catKey);
          if (catTechniques.length === 0) return null;
          return (
            <div key={catKey} className="mb-6">
              {(() => {
                const CatIcon = categoryIcon[catKey];
                return (
                  <h2 className={`text-sm font-medium mb-3 flex items-center gap-2 ${categoryIconColor[catKey] || "text-muted-foreground"}`}>
                    {CatIcon && <CatIcon className="h-4 w-4" />}
                    <span>{techniqueCategories[catKey].label}</span>
                  </h2>
                );
              })()}
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {catTechniques.map((tech) => {
                  const TechCatIcon = categoryIcon[tech.category];
                  return (
                    <Link
                      key={tech.id}
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
                })}
              </div>
            </div>
          );
        })}
      </div>
    </Layout>
  );
}
