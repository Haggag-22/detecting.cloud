import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { detections } from "@/data/detections";
import { normalizeEvents } from "@/lib/detection-lab/normalize";
import { evaluateRules } from "@/lib/detection-lab/ruleEvaluator";
import { useDetectionLab } from "../DetectionLabContext";
import { Play, FileJson, Clipboard, Upload } from "lucide-react";

export function UserLogTesting() {
  const [inputMode, setInputMode] = useState<"paste" | "upload">("paste");
  const [pastedLog, setPastedLog] = useState("");
  const [result, setResult] = useState<{
    matchingRules: { id: string; title: string; severity: string; confidence: string }[];
    matchedEvents: number;
    totalEvents: number;
  } | null>(null);
  const lab = useDetectionLab();

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      setPastedLog(String(ev.target?.result ?? ""));
    };
    reader.readAsText(file);
  };

  const handleRunTest = () => {
    if (!pastedLog.trim()) {
      setResult(null);
      return;
    }

    let raw: unknown;
    try {
      raw = JSON.parse(pastedLog);
    } catch {
      raw = pastedLog;
    }

    const events = normalizeEvents(raw);
    const evalResults = evaluateRules(detections, events);
    const matched = evalResults.filter((r) => r.matched);

    setResult({
      matchingRules: matched.map((m) => ({
        id: m.detectionId,
        title: m.detectionTitle,
        severity: m.severity,
        confidence: m.confidence,
      })),
      matchedEvents: matched.reduce((sum, m) => sum + m.matchedEvents.length, 0),
      totalEvents: events.length,
    });

    lab?.addResult({
      type: "user-log",
      rulesEvaluated: detections.length,
      detectionsTriggered: matched.length,
      details: { totalEvents: events.length, matchedEvents: matched.reduce((s, m) => s + m.matchedEvents.length, 0) },
    });
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle>User Log Testing</CardTitle>
          <CardDescription>
            Test detection rules against your own telemetry. Paste CloudTrail JSON or upload a log file.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <Tabs value={inputMode} onValueChange={(v) => setInputMode(v as "paste" | "upload")}>
            <TabsList>
              <TabsTrigger value="paste">
                <Clipboard className="h-4 w-4 mr-2" />
                Paste Log Event
              </TabsTrigger>
              <TabsTrigger value="upload">
                <Upload className="h-4 w-4 mr-2" />
                Upload JSON / Log File
              </TabsTrigger>
            </TabsList>
            <TabsContent value="paste" className="mt-4">
              <Label>Paste CloudTrail or JSON log</Label>
              <Textarea
                placeholder='{"eventSource":"eks.amazonaws.com","eventName":"CreateAccessEntry",...}'
                value={pastedLog}
                onChange={(e) => setPastedLog(e.target.value)}
                rows={10}
                className="font-mono text-sm mt-2"
              />
            </TabsContent>
            <TabsContent value="upload" className="mt-4">
              <Label>Upload JSON or log file</Label>
              <input
                type="file"
                accept=".json,.log,.txt"
                onChange={handleFileUpload}
                className="mt-2 block w-full text-sm text-muted-foreground file:mr-4 file:py-2 file:px-4 file:rounded-md file:border-0 file:bg-primary file:text-primary-foreground"
              />
              {pastedLog && (
                <Textarea
                  value={pastedLog}
                  onChange={(e) => setPastedLog(e.target.value)}
                  rows={8}
                  className="font-mono text-sm mt-2"
                />
              )}
            </TabsContent>
          </Tabs>

          <Button onClick={handleRunTest} disabled={!pastedLog.trim()}>
            <Play className="h-4 w-4 mr-2" />
            Run Analysis
          </Button>
        </CardContent>
      </Card>

      {result && (
        <Card>
          <CardHeader>
            <CardTitle>Log Analysis Result</CardTitle>
            <CardDescription>Matching detection rules and confidence levels</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-3">
              <div>
                <p className="text-sm text-muted-foreground">Matched Rules</p>
                <p className="text-2xl font-bold">{result.matchingRules.length}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Matched Events</p>
                <p className="text-2xl font-bold">{result.matchedEvents}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Total Events</p>
                <p className="text-2xl font-bold">{result.totalEvents}</p>
              </div>
            </div>
            {result.matchingRules.length > 0 ? (
              <div>
                <p className="text-sm font-medium mb-2">Matching Rules</p>
                <ul className="space-y-2">
                  {result.matchingRules.map((r) => (
                    <li key={r.id} className="flex items-center justify-between rounded-lg border p-3">
                      <div>
                        <p className="font-medium">{r.title}</p>
                        <p className="text-sm text-muted-foreground">
                          {r.severity} • Confidence: {r.confidence}
                        </p>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            ) : (
              <p className="text-muted-foreground">No detection rules matched the provided logs.</p>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
