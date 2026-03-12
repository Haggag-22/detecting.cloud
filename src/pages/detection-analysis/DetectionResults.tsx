import { useDetectionAnalysis } from "@/context/DetectionAnalysisContext";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Link } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { CheckCircle, AlertTriangle, XCircle } from "lucide-react";

export function DetectionResults() {
  const { result } = useDetectionAnalysis();

  if (!result) return null;

  return (
    <div className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Valid Detections</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-green-500" />
              <span className="text-2xl font-bold">{result.validDetections}</span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Possible False Positives</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-5 w-5 text-amber-500" />
              <span className="text-2xl font-bold">{result.possibleFalsePositives}</span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Misconfigured Rules</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-center gap-2">
              <XCircle className="h-5 w-5 text-red-500" />
              <span className="text-2xl font-bold">{result.misconfiguredRules}</span>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Total Events</CardTitle>
          </CardHeader>
          <CardContent>
            <span className="text-2xl font-bold">{result.totalEvents}</span>
          </CardContent>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium text-muted-foreground">Rules Evaluated</CardTitle>
          </CardHeader>
          <CardContent>
            <span className="text-2xl font-bold">{result.rulesEvaluated}</span>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Deduplicated Detections by Technique</CardTitle>
          <CardDescription>Multiple rules detecting the same technique are grouped together</CardDescription>
        </CardHeader>
        <CardContent>
          {result.deduplicated.length === 0 ? (
            <p className="text-muted-foreground">No detections to display.</p>
          ) : (
            <div className="space-y-3">
              {result.deduplicated.map((d) => (
                <div
                  key={d.techniqueKey}
                  className="flex items-center justify-between rounded-lg border p-4"
                >
                  <div>
                    <p className="font-medium">{d.techniqueName}</p>
                    <p className="text-sm text-muted-foreground">
                      {d.detectionIds.length} rule{d.detectionIds.length !== 1 ? "s" : ""} triggered
                    </p>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="secondary">{d.severity}</Badge>
                    <Badge variant="outline">Score: {d.combinedConfidenceScore}%</Badge>
                    <Button variant="ghost" size="sm" asChild>
                      <Link to="/detection-analysis/explanation">Explain</Link>
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
