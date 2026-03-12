import { useState } from "react";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { useDetectionAnalysis } from "@/context/DetectionAnalysisContext";
import { Button } from "@/components/ui/button";
import { CheckCircle, XCircle, Lightbulb } from "lucide-react";

export function ExplainDetectionDialog() {
  const { result } = useDetectionAnalysis();
  const [selectedMatchId, setSelectedMatchId] = useState<string>("");

  if (!result) return null;

  const validMatches = result.matches.filter((m) => m.matchedEvents.length > 0);
  if (validMatches.length === 0) return null;

  const selectedMatch = validMatches.find((m) => m.detection.id === selectedMatchId) ?? validMatches[0];

  return (
    <Dialog>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm">
          <Lightbulb className="h-4 w-4 mr-2" />
          Explain Detection
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Explain Detection</DialogTitle>
          <DialogDescription>
            See which fields and values triggered each detection rule
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4 pt-2">
          <div className="space-y-2">
            <Label>Detection</Label>
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
                          <CheckCircle className="h-4 w-4 text-green-500 shrink-0" />
                        ) : (
                          <XCircle className="h-4 w-4 text-muted-foreground shrink-0" />
                        )}
                        <span className="font-mono text-sm">{fm.field}</span>
                        <span className="text-muted-foreground text-sm">
                          {fm.operator} {fm.expectedValues.join(", ")}
                        </span>
                      </div>
                      <span className="font-mono text-sm truncate max-w-[120px]">
                        {JSON.stringify(fm.actualValue)}
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
