import { useState } from "react";
import { Layout } from "@/components/Layout";
import { techniques, techniqueCategories, type TechniqueCategory } from "@/data/techniques";
import { detections } from "@/data/detections";
import { Badge } from "@/components/ui/badge";
import { Link } from "react-router-dom";
import { CheckCircle2, XCircle, AlertCircle, Filter } from "lucide-react";

const categoryColors: Record<TechniqueCategory, string> = {
  "initial-access": "bg-muted text-muted-foreground",
  "credential-access": "bg-purple-500/15 text-purple-400",
  "privilege-escalation": "bg-red-500/15 text-red-400",
  "persistence": "bg-orange-500/15 text-orange-400",
  "lateral-movement": "bg-blue-500/15 text-blue-400",
  "exfiltration": "bg-emerald-500/15 text-emerald-400",
  "defense-evasion": "bg-muted text-muted-foreground",
};

type CoverageStatus = "covered" | "partial" | "none";

function getCoverageStatus(detectionIds: string[]): CoverageStatus {
  if (detectionIds.length === 0) return "none";
  const matchedCount = detectionIds.filter((id) =>
    detections.some((d) => d.id === id)
  ).length;
  if (matchedCount === 0) return "none";
  if (matchedCount < detectionIds.length) return "partial";
  return "covered";
}

const CoveragePage = () => {
  const [categoryFilter, setCategoryFilter] = useState<TechniqueCategory | "all">("all");
  const [serviceFilter, setServiceFilter] = useState<string>("all");

  // Collect unique services
  const allServices = Array.from(new Set(techniques.flatMap((t) => t.services))).sort();

  const filtered = techniques.filter((t) => {
    if (categoryFilter !== "all" && t.category !== categoryFilter) return false;
    if (serviceFilter !== "all" && !t.services.includes(serviceFilter)) return false;
    return true;
  });

  const coveredCount = filtered.filter((t) => getCoverageStatus(t.detectionIds) === "covered").length;
  const partialCount = filtered.filter((t) => getCoverageStatus(t.detectionIds) === "partial").length;
  const noneCount = filtered.filter((t) => getCoverageStatus(t.detectionIds) === "none").length;

  return (
    <Layout>
      <div className="container py-12">
        <h1 className="font-display text-3xl font-bold mb-2">Detection Coverage</h1>
        <p className="text-muted-foreground mb-8">
          Visualize which attack techniques have detection rules and identify coverage gaps.
        </p>

        {/* Summary Stats */}
        <div className="grid grid-cols-3 gap-4 mb-8">
          <div className="rounded-lg border border-border/50 bg-card p-4 flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 text-emerald-400" />
            <div>
              <p className="text-2xl font-bold text-foreground">{coveredCount}</p>
              <p className="text-xs text-muted-foreground">Fully Covered</p>
            </div>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4 flex items-center gap-3">
            <AlertCircle className="h-5 w-5 text-yellow-400" />
            <div>
              <p className="text-2xl font-bold text-foreground">{partialCount}</p>
              <p className="text-xs text-muted-foreground">Partial Coverage</p>
            </div>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4 flex items-center gap-3">
            <XCircle className="h-5 w-5 text-red-400" />
            <div>
              <p className="text-2xl font-bold text-foreground">{noneCount}</p>
              <p className="text-xs text-muted-foreground">No Coverage</p>
            </div>
          </div>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-3 mb-6 items-center">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <select
            value={categoryFilter}
            onChange={(e) => setCategoryFilter(e.target.value as TechniqueCategory | "all")}
            className="rounded-lg border border-border bg-card px-3 py-2 text-sm outline-none focus:border-primary/50"
          >
            <option value="all">All Categories</option>
            {(Object.keys(techniqueCategories) as TechniqueCategory[]).map((cat) => (
              <option key={cat} value={cat}>{techniqueCategories[cat].label}</option>
            ))}
          </select>
          <select
            value={serviceFilter}
            onChange={(e) => setServiceFilter(e.target.value)}
            className="rounded-lg border border-border bg-card px-3 py-2 text-sm outline-none focus:border-primary/50"
          >
            <option value="all">All Services</option>
            {allServices.map((svc) => (
              <option key={svc} value={svc}>{svc}</option>
            ))}
          </select>
        </div>

        {/* Coverage Matrix */}
        <div className="rounded-lg border border-border/50 overflow-hidden">
          <div className="grid grid-cols-[1fr_140px_120px_100px_100px] gap-0 text-xs font-medium text-muted-foreground uppercase tracking-wider bg-muted px-4 py-3 border-b border-border">
            <span>Technique</span>
            <span>Category</span>
            <span>Services</span>
            <span>Detections</span>
            <span>Status</span>
          </div>
          <div className="divide-y divide-border/50">
            {filtered.map((tech) => {
              const status = getCoverageStatus(tech.detectionIds);
              const matchedDetections = tech.detectionIds
                .map((id) => detections.find((d) => d.id === id))
                .filter(Boolean);

              return (
                <Link
                  key={tech.id}
                  to={`/attack-paths?technique=${tech.id}`}
                  className="grid grid-cols-[1fr_140px_120px_100px_100px] gap-0 px-4 py-3 hover:bg-muted/50 transition-colors items-center"
                >
                  <span className="font-medium text-sm text-foreground">{tech.name}</span>
                  <Badge className={`text-[10px] border-0 w-fit ${categoryColors[tech.category]}`}>
                    {techniqueCategories[tech.category].label}
                  </Badge>
                  <span className="text-xs text-muted-foreground">{tech.services.join(", ")}</span>
                  <span className="text-xs text-muted-foreground">{matchedDetections.length} rules</span>
                  <div className="flex items-center gap-1.5">
                    {status === "covered" && (
                      <>
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                        <span className="text-xs text-emerald-400">Covered</span>
                      </>
                    )}
                    {status === "partial" && (
                      <>
                        <AlertCircle className="h-3.5 w-3.5 text-yellow-400" />
                        <span className="text-xs text-yellow-400">Partial</span>
                      </>
                    )}
                    {status === "none" && (
                      <>
                        <XCircle className="h-3.5 w-3.5 text-red-400" />
                        <span className="text-xs text-red-400">Gap</span>
                      </>
                    )}
                  </div>
                </Link>
              );
            })}
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default CoveragePage;
