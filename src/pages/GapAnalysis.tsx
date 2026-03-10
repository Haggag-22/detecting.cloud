import { useMemo } from "react";
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
  ShieldAlert, CheckCircle2, XCircle, AlertTriangle, TrendingUp,
} from "lucide-react";

type CoverageStatus = "covered" | "partial" | "none";

function getCoverage(detectionIds: string[]): CoverageStatus {
  if (detectionIds.length === 0) return "none";
  const matched = detectionIds.filter((id) => detections.some((d) => d.id === id)).length;
  if (matched === 0) return "none";
  if (matched < detectionIds.length) return "partial";
  return "covered";
}

const categoryBarColors: Record<TechniqueCategory, string> = {
  "initial-access": "hsl(215, 20%, 55%)",
  "credential-access": "hsl(270, 70%, 65%)",
  "privilege-escalation": "hsl(0, 84%, 60%)",
  "persistence": "hsl(25, 95%, 53%)",
  "lateral-movement": "hsl(210, 79%, 46%)",
  "exfiltration": "hsl(160, 84%, 39%)",
  "defense-evasion": "hsl(215, 20%, 55%)",
};

const severityScore: Record<string, number> = { Critical: 4, High: 3, Medium: 2, Low: 1 };

const GapAnalysisPage = () => {
  const analysis = useMemo(() => {
    // Coverage by category
    const categories = (Object.keys(techniqueCategories) as TechniqueCategory[]).map((cat) => {
      const catTechs = techniques.filter((t) => t.category === cat);
      const covered = catTechs.filter((t) => getCoverage(t.detectionIds) === "covered").length;
      const partial = catTechs.filter((t) => getCoverage(t.detectionIds) === "partial").length;
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

    // Coverage by service
    const allServices = Array.from(new Set(techniques.flatMap((t) => t.services))).sort();
    const services = allServices.map((svc) => {
      const svcTechs = techniques.filter((t) => t.services.includes(svc));
      const covered = svcTechs.filter((t) => getCoverage(t.detectionIds) !== "none").length;
      return { service: svc, total: svcTechs.length, covered, pct: svcTechs.length > 0 ? Math.round((covered / svcTechs.length) * 100) : 0 };
    });

    // Uncovered techniques with priority score
    const uncovered = techniques
      .filter((t) => getCoverage(t.detectionIds) === "none")
      .map((t) => {
        const appearsIn = attackPaths.filter((ap) => ap.steps.some((s) => s.techniqueId === t.id));
        const maxSeverity = appearsIn.reduce((max, ap) => Math.max(max, severityScore[ap.severity] || 0), 0);
        return { ...t, pathCount: appearsIn.length, priorityScore: maxSeverity * 2 + appearsIn.length };
      })
      .sort((a, b) => b.priorityScore - a.priorityScore);

    // Partial techniques
    const partialTechs = techniques
      .filter((t) => getCoverage(t.detectionIds) === "partial")
      .map((t) => {
        const matched = t.detectionIds.filter((id) => detections.some((d) => d.id === id)).length;
        return { ...t, matchedCount: matched, totalDetections: t.detectionIds.length };
      });

    const totalTechs = techniques.length;
    const totalCovered = techniques.filter((t) => getCoverage(t.detectionIds) === "covered").length;
    const totalPartial = techniques.filter((t) => getCoverage(t.detectionIds) === "partial").length;
    const totalNone = totalTechs - totalCovered - totalPartial;
    const overallPct = Math.round(((totalCovered + totalPartial * 0.5) / totalTechs) * 100);

    return { categories, services, uncovered, partialTechs, totalTechs, totalCovered, totalPartial, totalNone, overallPct };
  }, []);

  return (
    <Layout>
      <div className="container py-12">
        <h1 className="font-display text-3xl font-bold mb-2">Detection Gap Analysis</h1>
        <p className="text-muted-foreground mb-8">
          Identify which attack techniques lack detection coverage and prioritize rule development.
        </p>

        {/* Summary */}
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

        {/* Uncovered Techniques */}
        {analysis.uncovered.length > 0 && (
          <div className="mb-8">
            <h2 className="font-display text-lg font-semibold mb-4 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-destructive" /> Coverage Gaps — Priority List
            </h2>
            <p className="text-xs text-muted-foreground mb-4">
              Techniques with no detection rules, sorted by priority (based on severity of attack paths they appear in).
            </p>
            <div className="rounded-lg border border-border/50 overflow-hidden">
              <div className="grid grid-cols-[1fr_140px_80px_80px] gap-0 text-xs font-medium text-muted-foreground uppercase tracking-wider bg-muted px-4 py-3 border-b border-border">
                <span>Technique</span>
                <span>Category</span>
                <span>In Paths</span>
                <span>Priority</span>
              </div>
              <div className="divide-y divide-border/50">
                {analysis.uncovered.map((tech) => (
                  <Link
                    key={tech.id}
                    to={`/attack-paths/technique/${tech.id}`}
                    className="grid grid-cols-[1fr_140px_80px_80px] gap-0 px-4 py-3 hover:bg-muted/50 transition-colors items-center"
                  >
                    <span className="font-medium text-sm">{tech.name}</span>
                    <Badge variant="outline" className="text-[10px] w-fit border-border">
                      {techniqueCategories[tech.category].label}
                    </Badge>
                    <span className="text-xs text-muted-foreground">{tech.pathCount} chains</span>
                    <div className="flex items-center gap-1.5">
                      <div className={`w-2 h-2 rounded-full ${
                        tech.priorityScore >= 8 ? "bg-destructive" :
                        tech.priorityScore >= 4 ? "bg-yellow-400" : "bg-muted-foreground"
                      }`} />
                      <span className="text-xs">{tech.priorityScore > 0 ? tech.priorityScore : "—"}</span>
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Partial Coverage */}
        {analysis.partialTechs.length > 0 && (
          <div>
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
      </div>
    </Layout>
  );
};

export default GapAnalysisPage;
