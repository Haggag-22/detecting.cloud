import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { detections } from "@/data/detections";
import { computeCoverage, computeCoverageScore } from "@/lib/detection-lab/coverageMapping";
import { useDetectionLab } from "../DetectionLabContext";
import { BarChart3, CheckCircle, AlertCircle, XCircle } from "lucide-react";

export function DetectionCoverageMapping() {
  const [usePlatformRules, setUsePlatformRules] = useState(true);
  const coverage = computeCoverage(usePlatformRules ? detections.map((d) => d.id) : []);
  const score = computeCoverageScore(usePlatformRules ? detections.map((d) => d.id) : []);
  const lab = useDetectionLab();

  const handleUsePlatformRules = () => {
    setUsePlatformRules(true);
    lab?.addResult({
      type: "coverage",
      coverageScore: score,
      rulesEvaluated: detections.length,
      details: { coverageScore: score },
    });
  };

  const covered = coverage.filter((c) => c.coverage === "covered");
  const partial = coverage.filter((c) => c.coverage === "partial");
  const notCovered = coverage.filter((c) => c.coverage === "not_covered");

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Detection Coverage Mapping</CardTitle>
          <CardDescription>
            See what attacks your detection rules cover and where gaps exist. Upload rules or use platform rules to map coverage.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Button onClick={handleUsePlatformRules} variant={usePlatformRules ? "default" : "outline"}>
            Use Platform Detection Rules
          </Button>
          <p className="text-sm text-muted-foreground">
            Platform rules are mapped to techniques via event patterns (CreateAccessKey, PutBucketAcl, CreateAccessEntry, etc.).
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <BarChart3 className="h-5 w-5" />
            Cloud Attack Detection Coverage
          </CardTitle>
          <CardDescription>Technique coverage based on event pattern mapping</CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div className="rounded-lg border bg-muted/30 p-6 text-center">
            <p className="text-sm text-muted-foreground mb-1">Detection Coverage Score</p>
            <p className="text-4xl font-bold text-primary">{score}%</p>
          </div>

          <div className="space-y-4">
            <div>
              <p className="text-sm font-medium mb-2 flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-green-500" />
                Covered ({covered.length})
              </p>
              <div className="space-y-2">
                {covered.map((c) => (
                  <div key={c.techniqueId} className="flex items-center justify-between rounded-lg border p-3">
                    <span>{c.techniqueName}</span>
                    <Badge variant="secondary">{c.detectionIds.length} rules</Badge>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <p className="text-sm font-medium mb-2 flex items-center gap-2">
                <AlertCircle className="h-4 w-4 text-amber-500" />
                Partial ({partial.length})
              </p>
              <div className="space-y-2">
                {partial.map((c) => (
                  <div key={c.techniqueId} className="flex items-center justify-between rounded-lg border p-3">
                    <span>{c.techniqueName}</span>
                    <Badge variant="outline">{c.detectionIds.length} rule</Badge>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <p className="text-sm font-medium mb-2 flex items-center gap-2">
                <XCircle className="h-4 w-4 text-muted-foreground" />
                Not Covered ({notCovered.length})
              </p>
              <div className="space-y-2">
                {notCovered.slice(0, 10).map((c) => (
                  <div key={c.techniqueId} className="flex items-center justify-between rounded-lg border border-dashed p-3 text-muted-foreground">
                    <span>{c.techniqueName}</span>
                  </div>
                ))}
                {notCovered.length > 10 && (
                  <p className="text-sm text-muted-foreground">+ {notCovered.length - 10} more</p>
                )}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
