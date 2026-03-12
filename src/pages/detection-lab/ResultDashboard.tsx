import { useDetectionLab } from "./DetectionLabContext";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { BarChart3, Trash2 } from "lucide-react";

export function ResultDashboard() {
  const lab = useDetectionLab();
  const results = lab?.results ?? [];

  if (results.length === 0) return null;

  const datasetsTested = results.filter((r) => r.type === "dataset").length;
  const totalRulesEvaluated = results.reduce((sum, r) => sum + (r.rulesEvaluated ?? 0), 0);
  const totalDetectionsTriggered = results.reduce((sum, r) => sum + (r.detectionsTriggered ?? 0), 0);
  const totalFailures = results.reduce((sum, r) => sum + (r.detectionFailures ?? 0), 0);
  const coverageScores = results.filter((r) => r.coverageScore != null).map((r) => r.coverageScore!);
  const avgCoverage = coverageScores.length > 0
    ? Math.round(coverageScores.reduce((a, b) => a + b, 0) / coverageScores.length)
    : null;

  return (
    <Card className="mt-8">
      <CardHeader className="flex flex-row items-center justify-between">
        <div>
          <CardTitle className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5" />
            Detection Lab Results
          </CardTitle>
          <CardDescription>Summary of tests run in this session</CardDescription>
        </div>
        <Button variant="ghost" size="sm" onClick={() => lab?.clearResults()}>
          <Trash2 className="h-4 w-4 mr-1" />
          Clear
        </Button>
      </CardHeader>
      <CardContent>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
          <div className="rounded-lg border p-4">
            <p className="text-sm text-muted-foreground">Datasets Tested</p>
            <p className="text-2xl font-bold">{datasetsTested}</p>
          </div>
          <div className="rounded-lg border p-4">
            <p className="text-sm text-muted-foreground">Rules Evaluated</p>
            <p className="text-2xl font-bold">{totalRulesEvaluated}</p>
          </div>
          <div className="rounded-lg border p-4">
            <p className="text-sm text-muted-foreground">Detections Triggered</p>
            <p className="text-2xl font-bold text-green-600">{totalDetectionsTriggered}</p>
          </div>
          <div className="rounded-lg border p-4">
            <p className="text-sm text-muted-foreground">Detection Failures</p>
            <p className="text-2xl font-bold text-amber-600">{totalFailures}</p>
          </div>
          <div className="rounded-lg border p-4">
            <p className="text-sm text-muted-foreground">Coverage Score</p>
            <p className="text-2xl font-bold">{avgCoverage != null ? `${avgCoverage}%` : "—"}</p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
