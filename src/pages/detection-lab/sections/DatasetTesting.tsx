import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { datasets, getDatasetById } from "@/data/detection-lab/datasets";
import { detections } from "@/data/detections";
import { normalizeEvents } from "@/lib/detection-lab/normalize";
import { evaluateRules } from "@/lib/detection-lab/ruleEvaluator";
import { useDetectionLab } from "../DetectionLabContext";
import { Play, CheckCircle, XCircle, Upload } from "lucide-react";

export function DatasetTesting() {
  const [selectedDatasetId, setSelectedDatasetId] = useState<string>("");
  const [uploadedRule, setUploadedRule] = useState("");
  const [result, setResult] = useState<{
    technique: string;
    eventsAnalyzed: number;
    matchesFound: number;
    passed: boolean;
    matchedDetections: { id: string; title: string; severity: string }[];
  } | null>(null);
  const lab = useDetectionLab();

  const handleRunTest = () => {
    const dataset = getDatasetById(selectedDatasetId);
    if (!dataset) {
      setResult(null);
      return;
    }

    const events = normalizeEvents(dataset.events);

    let rulesToEval = detections;
    if (uploadedRule.trim()) {
      try {
        const parsed = JSON.parse(uploadedRule) as { id?: string; title?: string; rules?: { eventbridge?: string }; severity?: string }[];
        if (Array.isArray(parsed)) {
          rulesToEval = parsed.map((r, i) => ({
            id: r.id ?? `uploaded-${i}`,
            title: r.title ?? "Uploaded Rule",
            description: "",
            awsService: "Custom",
            relatedServices: [],
            severity: (r.severity as "Critical" | "High" | "Medium" | "Low") ?? "Medium",
            tags: [],
            logSources: ["AWS CloudTrail"],
            falsePositives: [],
            rules: { eventbridge: r.rules?.eventbridge ? JSON.stringify(r.rules.eventbridge) : undefined },
            relatedAttackSlugs: [],
          }));
        }
      } catch {
        rulesToEval = detections;
      }
    }

    const evalResults = evaluateRules(rulesToEval, events);
    const matched = evalResults.filter((r) => r.matched);
    const expectedIds = dataset.metadata.expectedDetections;
    const expectedMatched = expectedIds.some((id) => matched.some((m) => m.detectionId === id));
    const passed = expectedMatched || matched.length > 0;

    setResult({
      technique: dataset.metadata.technique,
      eventsAnalyzed: events.length,
      matchesFound: matched.length,
      passed,
      matchedDetections: matched.map((m) => ({
        id: m.detectionId,
        title: m.detectionTitle,
        severity: m.severity,
      })),
    });

    lab?.addResult({
      type: "dataset",
      datasetsTested: 1,
      rulesEvaluated: rulesToEval.length,
      detectionsTriggered: matched.length,
      detectionFailures: passed ? 0 : 1,
      details: { datasetId: selectedDatasetId, technique: dataset.metadata.technique },
    });
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>Dataset Testing</CardTitle>
          <CardDescription>
            Test detection rules against curated datasets. Select a dataset, optionally upload a custom rule, and run the test.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-4 md:grid-cols-2">
            <div className="space-y-2">
              <Label>Select Dataset</Label>
              <Select value={selectedDatasetId} onValueChange={setSelectedDatasetId}>
                <SelectTrigger>
                  <SelectValue placeholder="Choose a dataset..." />
                </SelectTrigger>
                <SelectContent>
                  {datasets.map((d) => (
                    <SelectItem key={d.id} value={d.id}>
                      {d.metadata.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="space-y-2">
            <Label>Upload Detection Rule (optional JSON)</Label>
            <Textarea
              placeholder='Paste EventBridge pattern or rule JSON. Leave empty to use platform rules.'
              value={uploadedRule}
              onChange={(e) => setUploadedRule(e.target.value)}
              rows={4}
              className="font-mono text-sm"
            />
          </div>

          <Button onClick={handleRunTest} disabled={!selectedDatasetId}>
            <Play className="h-4 w-4 mr-2" />
            Run Test
          </Button>
        </CardContent>
      </Card>

      {result && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              {result.passed ? (
                <CheckCircle className="h-5 w-5 text-green-500" />
              ) : (
                <XCircle className="h-5 w-5 text-amber-500" />
              )}
              Dataset Test Result
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <p className="text-sm text-muted-foreground">Technique</p>
                <p className="font-medium">{result.technique}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Events Analyzed</p>
                <p className="font-medium">{result.eventsAnalyzed}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Matches Found</p>
                <p className="font-medium">{result.matchesFound}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Detection Result</p>
                <p className={`font-medium ${result.passed ? "text-green-600" : "text-amber-600"}`}>
                  {result.passed ? "PASS" : "NO MATCH"}
                </p>
              </div>
            </div>
            {result.matchedDetections.length > 0 && (
              <div>
                <p className="text-sm font-medium mb-2">Matched Rules</p>
                <ul className="list-disc list-inside space-y-1 text-sm text-muted-foreground">
                  {result.matchedDetections.map((d) => (
                    <li key={d.id}>
                      {d.title} ({d.severity})
                    </li>
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
