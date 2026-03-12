import { useState } from "react";
import { useDetectionAnalysis } from "@/context/DetectionAnalysisContext";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { CheckCircle, XCircle } from "lucide-react";

export function DetectionExplanation() {
  const { result } = useDetectionAnalysis();
  const [selectedMatchId, setSelectedMatchId] = useState<string>("");

  if (!result) return null;

  const validMatches = result.matches.filter((m) => m.matchedEvents.length > 0);
  const selectedMatch = validMatches.find((m) => m.detection.id === selectedMatchId) ?? validMatches[0];

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Explain Detection</CardTitle>
          <CardDescription>
            See which fields and values triggered each detection rule
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {validMatches.length === 0 ? (
            <p className="text-muted-foreground">No detections to explain.</p>
          ) : (
            <>
              <div className="space-y-2">
                <Label>Select Detection</Label>
                <Select
                  value={selectedMatchId || selectedMatch?.detection.id}
                  onValueChange={setSelectedMatchId}
                >
                  <SelectTrigger>
                    <SelectValue placeholder="Choose a detection..." />
                  </SelectTrigger>
                  <SelectContent>
                    {validMatches.map((m) => (
                      <SelectItem key={m.detection.id} value={m.detection.id}>
                        {m.detection.title}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {selectedMatch && (
                <div className="rounded-lg border p-4 space-y-4">
                  <div>
                    <h4 className="font-medium">{selectedMatch.explanation.detectionTitle}</h4>
                    <p className="text-sm text-muted-foreground mt-1">{selectedMatch.explanation.summary}</p>
                  </div>
                  <div>
                    <h5 className="text-sm font-medium mb-2">Field Matches</h5>
                    <div className="space-y-2">
                      {selectedMatch.explanation.fieldMatches.map((fm, i) => (
                        <div
                          key={i}
                          className="flex items-center justify-between rounded-md bg-muted/50 px-3 py-2"
                        >
                          <div className="flex items-center gap-2">
                            {fm.matched ? (
                              <CheckCircle className="h-4 w-4 text-green-500" />
                            ) : (
                              <XCircle className="h-4 w-4 text-muted-foreground" />
                            )}
                            <span className="font-mono text-sm">{fm.field}</span>
                            <span className="text-muted-foreground text-sm">
                              {fm.operator} {fm.expectedValues.join(", ")}
                            </span>
                          </div>
                          <span className="font-mono text-sm">
                            Actual: {JSON.stringify(fm.actualValue)}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </>
          )}
        </CardContent>
      </Card>
    </div>
  );
}
