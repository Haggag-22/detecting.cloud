import { useDetectionAnalysis } from "@/context/DetectionAnalysisContext";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { AlertTriangle, XCircle } from "lucide-react";

export function FalsePositiveAnalysis() {
  const { result } = useDetectionAnalysis();

  if (!result) return null;

  const fpFindings = result.matches.flatMap((m) => (m.fpFinding ? [m.fpFinding] : []));
  const possibleFP = fpFindings.filter((f) => f.result === "possible_false_positive");
  const misconfigured = fpFindings.filter((f) => f.result === "rule_misconfigured");

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>False Positive Report</CardTitle>
          <CardDescription>
            Detections flagged as possible false positives or rule misconfigurations
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          {possibleFP.length > 0 && (
            <div>
              <h4 className="font-medium mb-2 flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-500" />
                Possible False Positives ({possibleFP.length})
              </h4>
              <div className="space-y-2">
                {possibleFP.map((f, i) => (
                  <div key={i} className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
                    <p className="font-medium">{f.detectionTitle}</p>
                    <p className="text-sm text-muted-foreground mt-1">{f.reason}</p>
                    {f.expectedValue && (
                      <p className="text-sm mt-1">
                        Expected: <code className="bg-muted px-1 rounded">{f.expectedValue}</code>
                        {f.actualValue && (
                          <> • Actual: <code className="bg-muted px-1 rounded">{String(f.actualValue)}</code></>
                        )}
                      </p>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {misconfigured.length > 0 && (
            <div>
              <h4 className="font-medium mb-2 flex items-center gap-2">
                <XCircle className="h-4 w-4 text-red-500" />
                Misconfigured Rules ({misconfigured.length})
              </h4>
              <div className="space-y-2">
                {misconfigured.map((f, i) => (
                  <div key={i} className="rounded-lg border border-red-500/30 bg-red-500/5 p-4">
                    <p className="font-medium">{f.detectionTitle}</p>
                    <p className="text-sm text-muted-foreground mt-1">{f.reason}</p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {fpFindings.length === 0 && (
            <p className="text-muted-foreground">No false positives or misconfigured rules detected.</p>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
