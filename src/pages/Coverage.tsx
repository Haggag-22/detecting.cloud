import { useState, useMemo } from "react";
import { Layout } from "@/components/Layout";
import { techniques, techniqueCategories, type TechniqueCategory } from "@/data/techniques";
import { detections } from "@/data/detections";
import { attackPaths } from "@/data/attackPaths";
import { Badge } from "@/components/ui/badge";
import { Link } from "react-router-dom";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell,
} from "recharts";
import {
  CheckCircle2, XCircle, AlertCircle, AlertTriangle, Filter, Search,
  TrendingUp,
} from "lucide-react";

const categoryColors: Record<TechniqueCategory, string> = {
  "initial-access": "bg-cyan-500/15 text-cyan-400",
  "credential-access": "bg-purple-500/15 text-purple-400",
  "privilege-escalation": "bg-red-500/15 text-red-400",
  "persistence": "bg-orange-500/15 text-orange-400",
  "lateral-movement": "bg-blue-500/15 text-blue-400",
  "exfiltration": "bg-emerald-500/15 text-emerald-400",
  "defense-evasion": "bg-amber-500/15 text-amber-400",
};

const categoryBarColors: Record<TechniqueCategory, string> = {
  "initial-access": "hsl(187, 85%, 53%)",
  "credential-access": "hsl(270, 70%, 65%)",
  "privilege-escalation": "hsl(0, 84%, 60%)",
  "persistence": "hsl(25, 95%, 53%)",
  "lateral-movement": "hsl(210, 79%, 46%)",
  "exfiltration": "hsl(160, 84%, 39%)",
  "defense-evasion": "hsl(38, 92%, 50%)",
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

const severityScore: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };

function getPriorityLabel(score: number): string {
  if (score >= 9) return "Critical";
  if (score >= 7) return "High";
  if (score >= 4) return "Medium";
  if (score >= 1) return "Low";
  return "—";
}

const CoveragePage = () => {
  const [categoryFilter, setCategoryFilter] = useState<TechniqueCategory | "all">("all");
  const [serviceFilter, setServiceFilter] = useState<string>("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [sortBy, setSortBy] = useState<"status" | "priority">("status");
  const [sortOrder, setSortOrder] = useState<"asc" | "desc">("desc");

  const analysis = useMemo(() => {
    const categories = (Object.keys(techniqueCategories) as TechniqueCategory[]).map((cat) => {
      const catTechs = techniques.filter((t) => t.category === cat);
      const covered = catTechs.filter((t) => getCoverageStatus(t.detectionIds) === "covered").length;
      const partial = catTechs.filter((t) => getCoverageStatus(t.detectionIds) === "partial").length;
      const pct = catTechs.length > 0 ? Math.round(((covered + partial * 0.5) / catTechs.length) * 100) : 0;
      return {
        key: cat,
        label: techniqueCategories[cat].label,
        total: catTechs.length,
        covered,
        partial,
        none: catTechs.length - covered - partial,
        pct,
      };
    });

    const allServices = Array.from(new Set(techniques.flatMap((t) => t.services))).sort();
    const services = allServices.map((svc) => {
      const svcTechs = techniques.filter((t) => t.services.includes(svc));
      const covered = svcTechs.filter((t) => getCoverageStatus(t.detectionIds) !== "none").length;
      return { service: svc, total: svcTechs.length, covered, pct: svcTechs.length > 0 ? Math.round((covered / svcTechs.length) * 100) : 0 };
    });

    const partialTechs = techniques
      .filter((t) => getCoverageStatus(t.detectionIds) === "partial")
      .map((t) => {
        const matched = t.detectionIds.filter((id) => detections.some((d) => d.id === id)).length;
        return { ...t, matchedCount: matched, totalDetections: t.detectionIds.length };
      });

    const totalTechs = techniques.length;
    const totalCovered = techniques.filter((t) => getCoverageStatus(t.detectionIds) === "covered").length;
    const totalPartial = techniques.filter((t) => getCoverageStatus(t.detectionIds) === "partial").length;
    const totalNone = totalTechs - totalCovered - totalPartial;
    const overallPct = Math.round(((totalCovered + totalPartial * 0.5) / totalTechs) * 100);

    return { categories, services, partialTechs, totalTechs, totalCovered, totalPartial, totalNone, overallPct };
  }, []);

  const techniquesWithMeta = useMemo(() => {
    return techniques.map((t) => {
      const status = getCoverageStatus(t.detectionIds);
      const appearsIn = attackPaths.filter((ap) => ap.steps.some((s) => s.techniqueId === t.id));
      const pathCount = appearsIn.length;
      const maxSeverity = appearsIn.reduce((max, ap) => Math.max(max, severityScore[ap.severity] || 0), 0);
      const priorityScore = status === "none" ? maxSeverity * 2 + pathCount : 0;
      const priorityLabel = status === "none" ? getPriorityLabel(priorityScore) : "—";
      return { ...t, status, pathCount, priorityScore, priorityLabel };
    });
  }, [attackPaths]);

  const filtered = techniquesWithMeta.filter((t) => {
    if (categoryFilter !== "all" && t.category !== categoryFilter) return false;
    if (serviceFilter !== "all" && !t.services.includes(serviceFilter)) return false;
    if (searchQuery && !t.name.toLowerCase().includes(searchQuery.toLowerCase())) return false;
    return true;
  });

  const sorted = useMemo(() => {
    const order = sortOrder === "desc" ? 1 : -1;
    return [...filtered].sort((a, b) => {
      if (sortBy === "status") {
        const statusOrder = { none: 0, partial: 1, covered: 2 };
        const diff = (statusOrder[a.status] ?? 3) - (statusOrder[b.status] ?? 3);
        return diff * order;
      }
      if (sortBy === "priority") {
        const diff = a.priorityScore - b.priorityScore;
        return diff * order;
      }
      return 0;
    });
  }, [filtered, sortBy, sortOrder]);

  return (
    <Layout>
      <div className="container py-12">
        <h1 className="font-display text-3xl font-bold mb-2">Detection Coverage</h1>
        <p className="text-muted-foreground mb-8">
          Visualize which attack techniques have detection rules, identify coverage gaps, and prioritize rule development.
        </p>

        {/* Summary Stats */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-8">
          <div className="rounded-lg border border-border/50 bg-card p-4">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Total Techniques</p>
            <p className="text-2xl font-bold">{analysis.totalTechs}</p>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4">
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Overall Coverage</p>
            <p className="text-2xl font-bold text-primary">{analysis.overallPct}%</p>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4 flex items-center gap-3">
            <CheckCircle2 className="h-5 w-5 text-emerald-400 shrink-0" />
            <div>
              <p className="text-2xl font-bold">{analysis.totalCovered}</p>
              <p className="text-xs text-muted-foreground">Covered</p>
            </div>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4 flex items-center gap-3">
            <AlertTriangle className="h-5 w-5 text-yellow-400 shrink-0" />
            <div>
              <p className="text-2xl font-bold">{analysis.totalPartial}</p>
              <p className="text-xs text-muted-foreground">Partial</p>
            </div>
          </div>
          <div className="rounded-lg border border-border/50 bg-card p-4 flex items-center gap-3">
            <XCircle className="h-5 w-5 text-destructive shrink-0" />
            <div>
              <p className="text-2xl font-bold">{analysis.totalNone}</p>
              <p className="text-xs text-muted-foreground">No Coverage</p>
            </div>
          </div>
        </div>

        {/* Coverage by Category Chart */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-8">
          <div className="rounded-lg border border-border/50 bg-card p-6">
            <h2 className="font-display text-lg font-semibold mb-4 flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-primary" /> Coverage by Category
            </h2>
            <ResponsiveContainer width="100%" height={280}>
              <BarChart data={analysis.categories} layout="vertical" margin={{ left: 10, right: 20 }}>
                <XAxis type="number" domain={[0, 100]} tick={{ fill: "hsl(215, 20%, 55%)", fontSize: 11 }} tickFormatter={(v) => `${v}%`} />
                <YAxis type="category" dataKey="label" width={130} tick={{ fill: "hsl(215, 20%, 55%)", fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: "hsl(215, 38%, 8%)", border: "1px solid hsl(215, 24%, 15%)", borderRadius: 8, fontSize: 12 }}
                  labelStyle={{ color: "hsl(210, 40%, 94%)" }}
                  formatter={(value: number) => [`${value}%`, "Coverage"]}
                />
                <Bar dataKey="pct" radius={[0, 4, 4, 0]}>
                  {analysis.categories.map((entry) => (
                    <Cell key={entry.key} fill={categoryBarColors[entry.key]} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Coverage by Service */}
          <div className="rounded-lg border border-border/50 bg-card p-6">
            <h2 className="font-display text-lg font-semibold mb-4">Coverage by AWS Service</h2>
            <div className="space-y-3 max-h-[280px] overflow-y-auto">
              {analysis.services.map((svc) => (
                <div key={svc.service}>
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-sm font-medium">{svc.service}</span>
                    <span className="text-xs text-muted-foreground">{svc.covered}/{svc.total} techniques</span>
                  </div>
                  <div className="h-2 rounded-full bg-muted overflow-hidden">
                    <div
                      className="h-full rounded-full bg-primary transition-all"
                      style={{ width: `${svc.pct}%` }}
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>

        {/* Partial Coverage */}
        {analysis.partialTechs.length > 0 && (
          <div className="mb-8">
            <h2 className="font-display text-lg font-semibold mb-4 flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-yellow-400" /> Partial Coverage
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {analysis.partialTechs.map((tech) => (
                <Link
                  key={tech.id}
                  to={`/attack-paths/technique/${tech.id}`}
                  className="rounded-lg border border-border/50 bg-card p-4 hover:border-primary/30 transition-colors"
                >
                  <p className="text-sm font-medium mb-1">{tech.name}</p>
                  <p className="text-xs text-muted-foreground">
                    {tech.matchedCount} of {tech.totalDetections} detection rules matched
                  </p>
                </Link>
              ))}
            </div>
          </div>
        )}

        {/* Filters & Coverage Matrix */}
        <div>
          <h2 className="font-display text-lg font-semibold mb-4">Coverage Matrix</h2>
          <div className="flex flex-wrap gap-3 mb-6 items-center">
            <Filter className="h-4 w-4 text-muted-foreground" />
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <input
                placeholder="Search techniques..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="rounded-lg border border-border bg-card pl-8 pr-3 py-2 text-sm outline-none focus:border-primary/50 w-48"
              />
            </div>
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
              {analysis.services.map((svc) => (
                <option key={svc.service} value={svc.service}>{svc.service}</option>
              ))}
            </select>
            <span className="text-xs text-muted-foreground ml-2">Sort by:</span>
            <select
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as "status" | "priority")}
              className="rounded-lg border border-border bg-card px-3 py-2 text-sm outline-none focus:border-primary/50"
            >
              <option value="status">Status (Gap / Covered)</option>
              <option value="priority">Priority</option>
            </select>
            <select
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value as "asc" | "desc")}
              className="rounded-lg border border-border bg-card px-3 py-2 text-sm outline-none focus:border-primary/50"
            >
              <option value="desc">Descending</option>
              <option value="asc">Ascending</option>
            </select>
          </div>

          <div className="rounded-lg border border-border/50 overflow-hidden">
            <div className="grid grid-cols-[1fr_140px_120px_100px_110px_120px_100px] gap-x-6 gap-y-0 text-xs font-medium text-muted-foreground uppercase tracking-wider bg-muted px-4 py-3 border-b border-border">
              <span>Technique</span>
              <span>Category</span>
              <span>Services</span>
              <span>In Paths</span>
              <span>Detections</span>
              <span>Status</span>
              <span>Priority</span>
            </div>
            <div className="divide-y divide-border/50">
              {sorted.map((tech) => {
                const matchedDetections = tech.detectionIds
                  .map((id) => detections.find((d) => d.id === id))
                  .filter(Boolean);

                return (
                  <Link
                    key={tech.id}
                    to={`/attack-paths/technique/${tech.id}`}
                    className="grid grid-cols-[1fr_140px_120px_100px_110px_120px_100px] gap-x-6 gap-y-0 px-4 py-3 hover:bg-muted/50 transition-colors items-center"
                  >
                    <span className="font-medium text-sm text-foreground">{tech.name}</span>
                    <Badge className={`text-[10px] border-0 w-fit ${categoryColors[tech.category]}`}>
                      {techniqueCategories[tech.category].label}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{tech.services.join(", ")}</span>
                    <span className="text-xs text-muted-foreground">{tech.pathCount} chains</span>
                    <span className="text-xs text-muted-foreground">{matchedDetections.length} rules</span>
                    <div className="flex items-center gap-1.5">
                      {tech.status === "covered" && (
                        <>
                          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                          <span className="text-xs text-emerald-400">Covered</span>
                        </>
                      )}
                      {tech.status === "partial" && (
                        <>
                          <AlertCircle className="h-3.5 w-3.5 text-yellow-400" />
                          <span className="text-xs text-yellow-400">Partial</span>
                        </>
                      )}
                      {tech.status === "none" && (
                        <>
                          <XCircle className="h-3.5 w-3.5 text-red-400" />
                          <span className="text-xs text-red-400">Gap</span>
                        </>
                      )}
                    </div>
                    <div className="flex items-center gap-1.5">
                      {tech.priorityLabel !== "—" && (
                        <div className={`w-2 h-2 rounded-full shrink-0 ${
                          tech.priorityLabel === "Critical" ? "bg-destructive" :
                          tech.priorityLabel === "High" ? "bg-orange-400" :
                          tech.priorityLabel === "Medium" ? "bg-yellow-400" : "bg-muted-foreground"
                        }`} />
                      )}
                      <span className="text-xs text-muted-foreground">{tech.priorityLabel}</span>
                    </div>
                  </Link>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default CoveragePage;
