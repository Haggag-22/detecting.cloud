import { useMemo, useState, useCallback, useEffect } from "react";
import { Link } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { LayoutGrid, Filter, Sparkles, Plus, Minus } from "lucide-react";
import { PageTitleWithIcon } from "@/components/PageTitleWithIcon";
import { cn } from "@/lib/utils";
import {
  MATRIX_TACTIC_ORDER,
  matrixTacticLabels,
  type MatrixTactic,
  type TechniqueMatrixEntry,
  type CoverageBand,
  buildTechniqueMatrixEntries,
  getAllMatrixServices,
} from "@/lib/coverageMatrixModel";

type CoverageFilter = "all" | "covered" | "partial" | "gaps";

const MATRIX_ZOOM_KEY = "threat-matrix-zoom";
const ZOOM_MIN = 0.45;
const ZOOM_MAX = 1.25;
const ZOOM_STEP = 0.1;
const ZOOM_DEFAULT = 1;

/** Matches Techniques Library sidebar accent colors */
const TACTIC_HEADER_COLOR: Record<MatrixTactic, string> = {
  "initial-access": "text-cyan-400",
  "credential-access": "text-purple-400",
  "privilege-escalation": "text-red-400",
  persistence: "text-orange-400",
  "lateral-movement": "text-blue-400",
  exfiltration: "text-emerald-400",
  "defense-evasion": "text-amber-400",
};

function coverageStyles(band: CoverageBand): string {
  switch (band) {
    case "covered":
      return "border-emerald-500/50 bg-emerald-950/25 hover:border-emerald-400/70 hover:bg-emerald-950/40";
    case "partial":
      return "border-amber-500/50 bg-amber-950/20 hover:border-amber-400/70 hover:bg-amber-950/35";
    default:
      return "border-red-500/45 bg-red-950/15 hover:border-red-400/60 hover:bg-red-950/30";
  }
}

function TechniqueCard({ entry }: { entry: TechniqueMatrixEntry }) {
  const { technique, coverage, detectionCount, attackPathCount } = entry;
  const to = `/attack-paths/technique/${technique.id}`;

  return (
    <Tooltip delayDuration={200}>
      <TooltipTrigger asChild>
        <Link
          to={to}
          className={cn(
            "group block rounded-lg border p-3.5 text-left transition-all duration-200",
            "shadow-sm hover:shadow-md hover:-translate-y-0.5 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary/60",
            coverageStyles(coverage)
          )}
        >
          <div className="flex items-start gap-2.5">
            <span
              className={cn(
                "h-2.5 w-2.5 shrink-0 rounded-full mt-1.5",
                coverage === "covered" && "bg-emerald-400",
                coverage === "partial" && "bg-amber-400",
                coverage === "none" && "bg-red-400"
              )}
            />
            <div className="min-w-0 flex-1">
              <p className="text-sm font-semibold text-foreground leading-snug break-words hyphens-auto group-hover:text-primary transition-colors">
                {technique.name}
              </p>
            </div>
          </div>
          <div className="mt-3 flex flex-wrap gap-x-4 gap-y-0.5 text-[10px] text-muted-foreground">
            <span>
              Rules: <strong className="text-foreground">{detectionCount}</strong>
            </span>
            <span>
              Paths: <strong className="text-foreground">{attackPathCount}</strong>
            </span>
          </div>
        </Link>
      </TooltipTrigger>
      <TooltipContent side="right" className="max-w-xs text-xs">
        <p className="font-semibold text-foreground mb-1">{technique.name}</p>
        <p className="text-muted-foreground line-clamp-4">{technique.description}</p>
        <p className="mt-2 text-primary">Click for attack paths, detections &amp; simulations →</p>
      </TooltipContent>
    </Tooltip>
  );
}

export default function DetectionMatrix() {
  const baseEntries = useMemo(() => buildTechniqueMatrixEntries(), []);
  const allServices = useMemo(() => getAllMatrixServices(), []);

  const [serviceFilter, setServiceFilter] = useState<string>("all");
  const [coverageFilter, setCoverageFilter] = useState<CoverageFilter>("all");
  const [onlyWithDetections, setOnlyWithDetections] = useState(false);
  const [matrixZoom, setMatrixZoom] = useState(() => {
    try {
      const raw = sessionStorage.getItem(MATRIX_ZOOM_KEY);
      if (raw == null) return ZOOM_DEFAULT;
      const n = Number.parseFloat(raw);
      if (!Number.isFinite(n)) return ZOOM_DEFAULT;
      return Math.min(ZOOM_MAX, Math.max(ZOOM_MIN, n));
    } catch {
      return ZOOM_DEFAULT;
    }
  });

  useEffect(() => {
    try {
      sessionStorage.setItem(MATRIX_ZOOM_KEY, String(matrixZoom));
    } catch {
      /* ignore */
    }
  }, [matrixZoom]);

  const zoomIn = useCallback(() => {
    setMatrixZoom((z) => Math.min(ZOOM_MAX, Math.round((z + ZOOM_STEP) * 100) / 100));
  }, []);

  const zoomOut = useCallback(() => {
    setMatrixZoom((z) => Math.max(ZOOM_MIN, Math.round((z - ZOOM_STEP) * 100) / 100));
  }, []);

  const resetZoom = useCallback(() => setMatrixZoom(ZOOM_DEFAULT), []);

  const filtered = useMemo(() => {
    return baseEntries.filter((e) => {
      if (serviceFilter !== "all" && !e.technique.services.includes(serviceFilter)) return false;
      if (onlyWithDetections && e.detectionCount === 0) return false;
      if (coverageFilter === "covered" && e.coverage !== "covered") return false;
      if (coverageFilter === "partial" && e.coverage !== "partial") return false;
      if (coverageFilter === "gaps" && e.coverage !== "none") return false;
      return true;
    });
  }, [baseEntries, serviceFilter, coverageFilter, onlyWithDetections]);

  const byTactic = useMemo(() => {
    const map = new Map<MatrixTactic, TechniqueMatrixEntry[]>();
    MATRIX_TACTIC_ORDER.forEach((t) => map.set(t, []));
    filtered.forEach((e) => {
      const list = map.get(e.tactic);
      if (list) list.push(e);
    });
    MATRIX_TACTIC_ORDER.forEach((t) => {
      map.get(t)!.sort((a, b) => a.technique.name.localeCompare(b.technique.name));
    });
    return map;
  }, [filtered]);

  const resetFilters = useCallback(() => {
    setServiceFilter("all");
    setCoverageFilter("all");
    setOnlyWithDetections(false);
  }, []);

  const visibleCount = filtered.length;
  const zoomPercent = Math.round(matrixZoom * 100);
  const canZoomIn = matrixZoom < ZOOM_MAX - 1e-6;
  const canZoomOut = matrixZoom > ZOOM_MIN + 1e-6;

  return (
    <Layout>
      <div className="container min-w-0 max-w-full overflow-x-hidden py-8 space-y-6">
        <div>
          <PageTitleWithIcon team="red" icon={LayoutGrid} className="mb-0">
            Threat Matrix
          </PageTitleWithIcon>
        </div>

        <Card className="min-w-0 max-w-full overflow-hidden border-border/60">
            <CardHeader className="pb-3 space-y-4">
              <div className="flex flex-wrap items-center gap-2">
                <Filter className="h-4 w-4 text-muted-foreground" />
                <CardTitle className="text-base">Filters</CardTitle>
                <Badge variant="secondary" className="font-mono text-xs">
                  {visibleCount} / {baseEntries.length} techniques
                </Badge>
                <Button variant="ghost" size="sm" className="h-7 text-xs ml-auto" onClick={resetFilters}>
                  Reset
                </Button>
              </div>
              <div className="flex flex-wrap gap-4 items-end">
                <div className="space-y-1.5 min-w-[140px]">
                  <Label className="text-xs text-muted-foreground">Cloud service</Label>
                  <Select value={serviceFilter} onValueChange={setServiceFilter}>
                    <SelectTrigger className="h-9 text-sm">
                      <SelectValue placeholder="Service" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All services</SelectItem>
                      {allServices.map((s) => (
                        <SelectItem key={s} value={s}>
                          {s}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5 min-w-[160px]">
                  <Label className="text-xs text-muted-foreground">Detection coverage</Label>
                  <Select value={coverageFilter} onValueChange={(v) => setCoverageFilter(v as CoverageFilter)}>
                    <SelectTrigger className="h-9 text-sm">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All</SelectItem>
                      <SelectItem value="covered">Covered only</SelectItem>
                      <SelectItem value="partial">Partial only</SelectItem>
                      <SelectItem value="gaps">Gaps only (no coverage)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex items-center gap-2 pb-1">
                  <Switch id="only-dets" checked={onlyWithDetections} onCheckedChange={setOnlyWithDetections} />
                  <Label htmlFor="only-dets" className="text-sm cursor-pointer">
                    Has detections only
                  </Label>
                </div>
              </div>
            </CardHeader>
            <CardContent className="pt-0 space-y-2">
              <div className="flex flex-wrap items-start justify-between gap-3 px-0.5">
                <p className="text-xs text-muted-foreground flex items-center gap-2 min-w-0 flex-1">
                  <span className="inline-block shrink-0 rounded border border-border/60 px-1.5 py-0.5 font-mono text-[10px]">
                    ↔
                  </span>
                  <span>
                    Scroll horizontally to browse tactics. Use <strong className="text-foreground/80 font-medium">−</strong> /{" "}
                    <strong className="text-foreground/80 font-medium">+</strong> to zoom out (see more columns) or zoom in.
                  </span>
                </p>
                <div className="flex items-center gap-1 shrink-0" role="group" aria-label="Matrix zoom">
                  <span className="text-[10px] tabular-nums text-muted-foreground w-10 text-right mr-0.5">{zoomPercent}%</span>
                  <Button
                    type="button"
                    variant="outline"
                    size="icon"
                    className="h-8 w-8"
                    onClick={zoomOut}
                    disabled={!canZoomOut}
                    aria-label="Zoom out matrix"
                    title="Zoom out (see more)"
                  >
                    <Minus className="h-4 w-4" />
                  </Button>
                  <Button
                    type="button"
                    variant="outline"
                    size="icon"
                    className="h-8 w-8"
                    onClick={zoomIn}
                    disabled={!canZoomIn}
                    aria-label="Zoom in matrix"
                    title="Zoom in"
                  >
                    <Plus className="h-4 w-4" />
                  </Button>
                  <Button
                    type="button"
                    variant="ghost"
                    size="sm"
                    className="h-8 px-2 text-[10px] text-muted-foreground"
                    onClick={resetZoom}
                    disabled={Math.abs(matrixZoom - ZOOM_DEFAULT) < 1e-6}
                    title="Reset zoom to 100%"
                  >
                    Reset
                  </Button>
                </div>
              </div>
              <ScrollArea
                id="threat-matrix-scroll"
                className="max-w-full min-w-0 rounded-md border border-border/50"
              >
                {/* CSS zoom reflows layout so scroll bounds match the scaled view (better than transform for “see more columns”). */}
                <div
                  className="flex w-max min-w-0 gap-10 px-6 py-5"
                  style={{ zoom: matrixZoom } as React.CSSProperties}
                >
                  {MATRIX_TACTIC_ORDER.map((tactic) => {
                    const col = byTactic.get(tactic) ?? [];
                    return (
                      <div
                        key={tactic}
                        className="flex w-[22rem] min-w-[280px] max-w-[22rem] shrink-0 flex-col gap-3"
                      >
                        <div className="flex min-h-[5.25rem] flex-col items-center justify-center border-b border-border/40 bg-background/95 px-2 py-4 text-center backdrop-blur">
                          <div className="flex flex-col items-center justify-center gap-1.5">
                            <h3
                              className={cn(
                                "font-display text-balance text-[11px] font-bold uppercase leading-snug tracking-[0.12em] antialiased sm:text-xs",
                                TACTIC_HEADER_COLOR[tactic]
                              )}
                            >
                              {matrixTacticLabels[tactic]}
                            </h3>
                            <p className="text-[10px] font-normal tabular-nums leading-normal text-muted-foreground">
                              {col.length} {col.length === 1 ? "technique" : "techniques"}
                            </p>
                          </div>
                        </div>
                        <div className="flex flex-col gap-3 pr-1 pb-2">
                          {col.length === 0 ? (
                            <p className="text-[10px] text-muted-foreground italic px-1 py-4 text-center">
                              No matches
                            </p>
                          ) : (
                            col.map((entry) => <TechniqueCard key={entry.technique.id} entry={entry} />)
                          )}
                        </div>
                      </div>
                    );
                  })}
                </div>
                <ScrollBar
                  orientation="horizontal"
                  className="h-3.5 border-t border-border/40 bg-muted/20 [&>[data-radix-scroll-area-thumb]]:bg-muted-foreground/40"
                />
              </ScrollArea>
              <p className="text-xs text-muted-foreground mt-3 flex items-center gap-1">
                <Sparkles className="h-3.5 w-3.5" />
                Submit new rules for uncovered techniques via{" "}
                <Link to="/community-rules" className="text-primary hover:underline">
                  Community Rules
                </Link>
                .
              </p>
            </CardContent>
          </Card>
      </div>
    </Layout>
  );
}
