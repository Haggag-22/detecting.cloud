import { useState, useRef } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { attackSequences, getAttackSequenceById } from "@/data/detection-lab/attackSequences";
import { detections } from "@/data/detections";
import { normalizeEvent } from "@/lib/detection-lab/normalize";
import { evaluateRules } from "@/lib/detection-lab/ruleEvaluator";
import { useDetectionLab } from "../DetectionLabContext";
import { Play, RotateCcw, CheckCircle, AlertCircle } from "lucide-react";

export function AttackReplayEngine() {
  const [selectedSequenceId, setSelectedSequenceId] = useState("");
  const [replaying, setReplaying] = useState(false);
  const [result, setResult] = useState<{
    scenario: string;
    eventsReplayed: number;
    detectionTriggered: boolean;
    triggeredAtStep: number | null;
    detectionDelay: number;
    matchedDetections: string[];
  } | null>(null);
  const startTimeRef = useRef<number>(0);
  const lab = useDetectionLab();

  const handleReplay = async () => {
    const sequence = getAttackSequenceById(selectedSequenceId);
    if (!sequence) return;

    setReplaying(true);
    setResult(null);
    startTimeRef.current = Date.now();

    let triggeredAtStep: number | null = null;
    const matchedDetections: string[] = [];

    for (let i = 0; i < sequence.steps.length; i++) {
      await new Promise((r) => setTimeout(r, 800));
      const event = normalizeEvent(sequence.steps[i]);
      const evalResults = evaluateRules(detections, [event]);
      const matched = evalResults.filter((r) => r.matched);

      if (matched.length > 0 && triggeredAtStep === null) {
        triggeredAtStep = i + 1;
        matched.forEach((m) => matchedDetections.push(m.detectionTitle));
      }
    }

    const detectionDelay = Math.round((Date.now() - startTimeRef.current) / 1000);

    setResult({
      scenario: sequence.name,
      eventsReplayed: sequence.steps.length,
      detectionTriggered: triggeredAtStep !== null,
      triggeredAtStep,
      detectionDelay,
      matchedDetections,
    });

    lab?.addResult({
      type: "replay",
      detectionsTriggered: triggeredAtStep !== null ? 1 : 0,
      detectionFailures: triggeredAtStep === null ? 1 : 0,
      details: {
        scenario: sequence.name,
        eventsReplayed: sequence.steps.length,
        triggeredAtStep,
        detectionDelay,
      },
    });

    setReplaying(false);
  };

  const sequence = getAttackSequenceById(selectedSequenceId);

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Attack Replay Engine</CardTitle>
          <CardDescription>
            Replay real attack telemetry sequences to evaluate detection logic. Events stream sequentially and detection rules are evaluated at each step.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <Label>Select Attack Scenario</Label>
            <Select value={selectedSequenceId} onValueChange={setSelectedSequenceId}>
              <SelectTrigger>
                <SelectValue placeholder="Choose a scenario..." />
              </SelectTrigger>
              <SelectContent>
                {attackSequences.map((s) => (
                  <SelectItem key={s.id} value={s.id}>
                    {s.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {sequence && (
              <p className="text-sm text-muted-foreground">{sequence.description}</p>
            )}
          </div>

          <Button onClick={handleReplay} disabled={!selectedSequenceId || replaying}>
            {replaying ? (
              <>
                <span className="animate-pulse">Replaying...</span>
              </>
            ) : (
              <>
                <Play className="h-4 w-4 mr-2" />
                Start Replay
              </>
            )}
          </Button>
        </CardContent>
      </Card>

      {result && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {result.detectionTriggered ? (
                <CheckCircle className="h-5 w-5 text-green-500" />
              ) : (
                <AlertCircle className="h-5 w-5 text-amber-500" />
              )}
              Attack Replay Result
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <p className="text-sm text-muted-foreground">Scenario</p>
                <p className="font-medium">{result.scenario}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Events Replayed</p>
                <p className="font-medium">{result.eventsReplayed}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Detection Triggered</p>
                <p className={`font-medium ${result.detectionTriggered ? "text-green-600" : "text-amber-600"}`}>
                  {result.detectionTriggered ? "YES" : "NO"}
                </p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Triggered At Step</p>
                <p className="font-medium">{result.triggeredAtStep ?? "—"}</p>
              </div>
            </div>
            <div>
              <p className="text-sm text-muted-foreground">Detection Delay</p>
              <p className="font-medium">{result.detectionDelay} seconds</p>
            </div>
            {result.matchedDetections.length > 0 && (
              <div>
                <p className="text-sm font-medium mb-2">Matched Detections</p>
                <ul className="list-disc list-inside text-sm text-muted-foreground">
                  {result.matchedDetections.map((d) => (
                    <li key={d}>{d}</li>
                  ))}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
