import { useDetectionAnalysis } from "@/context/DetectionAnalysisContext";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";

export function ConfidenceScores() {
  const { result } = useDetectionAnalysis();

  if (!result) return null;

  const validMatches = result.matches.filter(
    (m) => m.matchedEvents.length > 0 && !m.fpFinding
  );

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Detection Confidence Scores</CardTitle>
          <CardDescription>
            Confidence is calculated from field matches. Strong = 80%+, Medium = 60%+, Low = 40%+, Possible FP = &lt;40%
          </CardDescription>
        </CardHeader>
        <CardContent>
          {validMatches.length === 0 ? (
            <p className="text-muted-foreground">No valid detections with confidence scores.</p>
          ) : (
            <div className="space-y-4">
              {validMatches.map((m) => (
                <div key={m.detection.id} className="rounded-lg border p-4">
                  <div className="flex items-center justify-between mb-2">
                    <p className="font-medium">{m.detection.title}</p>
                    <div className="flex items-center gap-2">
                      <Badge
                        variant={
                          m.confidenceLabel === "strong"
                            ? "default"
                            : m.confidenceLabel === "medium"
                              ? "secondary"
                              : "outline"
                        }
                      >
                        {m.confidenceLabel}
                      </Badge>
                      <span className="text-sm font-mono">{m.confidenceScore}%</span>
                    </div>
                  </div>
                  <Progress value={m.confidenceScore} className="h-2" />
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
