import React, { useState, useCallback } from "react";
import { Layout } from "@/components/Layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  FileJson,
  Upload,
  Database,
  ClipboardPaste,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  ChevronDown,
  ChevronRight,
} from "lucide-react";
import {
  handlePasteInput,
  handleFileUpload,
  handleDatasetUpload,
  type IngestionResult,
  type NormalizedCloudTrailEvent,
} from "@/features/cloudtrail-analyzer";
import { useToast } from "@/hooks/use-toast";

export default function CloudTrailAnalyzer() {
  const [pasteValue, setPasteValue] = useState("");
  const [result, setResult] = useState<IngestionResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);
  const { toast } = useToast();

  const processPaste = useCallback(() => {
    setIsLoading(true);
    try {
      const r = handlePasteInput(pasteValue);
      setResult(r);
      if (r.valid_count > 0) {
        toast.success(`Parsed ${r.valid_count} event(s)`);
      } else if (r.errors.length > 0) {
        toast.error(r.errors[0].message);
      }
    } finally {
      setIsLoading(false);
    }
  }, [pasteValue, toast]);

  const processFile = useCallback(
    async (file: File) => {
      setIsLoading(true);
      try {
        const r = await handleFileUpload(file);
        setResult(r);
        if (r.valid_count > 0) {
          toast.success(`Parsed ${r.valid_count} event(s) from ${file.name}`);
        } else if (r.errors.length > 0) {
          toast.error(r.errors[0].message);
        }
      } finally {
        setIsLoading(false);
      }
    },
    [toast]
  );

  const processDataset = useCallback(
    async (file: File) => {
      setIsLoading(true);
      try {
        const r = await handleDatasetUpload(file);
        setResult(r);
        if (r.valid_count > 0) {
          toast.success(`Parsed ${r.valid_count} event(s) from dataset`);
        } else if (r.errors.length > 0) {
          toast.error(r.errors[0].message);
        }
      } finally {
        setIsLoading(false);
      }
    },
    [toast]
  );

  return (
    <Layout>
      <div className="container py-10">
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2 flex items-center gap-3">
            <FileJson className="h-8 w-8 text-primary" />
            CloudTrail Analyzer
          </h1>
          <p className="text-muted-foreground">
            Ingest and parse AWS CloudTrail logs into a normalized format for detection testing, attack mapping, and timeline analysis.
          </p>
        </div>

        <Tabs defaultValue="paste" className="space-y-6">
          <TabsList className="grid w-full max-w-md grid-cols-3">
            <TabsTrigger value="paste" className="gap-2">
              <ClipboardPaste className="h-4 w-4" />
              Paste Event
            </TabsTrigger>
            <TabsTrigger value="file" className="gap-2">
              <Upload className="h-4 w-4" />
              File Upload
            </TabsTrigger>
            <TabsTrigger value="dataset" className="gap-2">
              <Database className="h-4 w-4" />
              Dataset
            </TabsTrigger>
          </TabsList>

          <TabsContent value="paste" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Single Event Paste</CardTitle>
                <p className="text-sm text-muted-foreground">
                  Paste a CloudTrail JSON event. Supports single object, array, or {"{ Records: [...] }"}.
                </p>
              </CardHeader>
              <CardContent className="space-y-4">
                <Textarea
                  placeholder='Paste CloudTrail JSON here... e.g. {"eventVersion":"1.08","eventTime":"2024-01-15T12:00:00Z",...}'
                  value={pasteValue}
                  onChange={(e) => setPasteValue(e.target.value)}
                  className="min-h-[200px] font-mono text-sm"
                />
                <Button onClick={processPaste} disabled={isLoading || !pasteValue.trim()}>
                  {isLoading ? "Parsing..." : "Parse Events"}
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="file" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">File Upload</CardTitle>
                <p className="text-sm text-muted-foreground">
                  Upload CloudTrail log files. Supports single event, multiple events, JSON arrays, or Records bundles.
                </p>
              </CardHeader>
              <CardContent>
                <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed rounded-lg cursor-pointer border-muted-foreground/25 hover:border-muted-foreground/50 transition-colors">
                  <Upload className="h-8 w-8 text-muted-foreground mb-2" />
                  <span className="text-sm text-muted-foreground">Click or drag .json file</span>
                  <input
                    type="file"
                    accept=".json,application/json"
                    className="hidden"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) processFile(f);
                      e.target.value = "";
                    }}
                    disabled={isLoading}
                  />
                </label>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="dataset" className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Dataset Upload</CardTitle>
                <p className="text-sm text-muted-foreground">
                  Upload large CloudTrail datasets. Events are processed sequentially. Max 50MB.
                </p>
              </CardHeader>
              <CardContent>
                <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed rounded-lg cursor-pointer border-muted-foreground/25 hover:border-muted-foreground/50 transition-colors">
                  <Database className="h-8 w-8 text-muted-foreground mb-2" />
                  <span className="text-sm text-muted-foreground">Click or drag dataset file</span>
                  <input
                    type="file"
                    accept=".json,application/json,.jsonl,.ndjson"
                    className="hidden"
                    onChange={(e) => {
                      const f = e.target.files?.[0];
                      if (f) processDataset(f);
                      e.target.value = "";
                    }}
                    disabled={isLoading}
                  />
                </label>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>

        {result && (
          <Card className="mt-8">
            <CardHeader>
              <div className="flex flex-wrap items-center gap-4">
                <CardTitle className="text-lg">Ingestion Results</CardTitle>
                <div className="flex gap-2">
                  <Badge variant="secondary" className="gap-1">
                    <CheckCircle2 className="h-3 w-3" />
                    Valid: {result.valid_count}
                  </Badge>
                  {result.malformed_count > 0 && (
                    <Badge variant="destructive" className="gap-1">
                      <XCircle className="h-3 w-3" />
                      Malformed: {result.malformed_count}
                    </Badge>
                  )}
                  <Badge variant="outline">Total: {result.total_count}</Badge>
                </div>
              </div>
              {result.errors.length > 0 && (
                <div className="space-y-1 mt-2">
                  {result.errors.slice(0, 5).map((err, i) => (
                    <p key={i} className="text-sm text-destructive flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4 shrink-0" />
                      {err.index != null ? `Event #${err.index}: ` : ""}{err.message}
                    </p>
                  ))}
                  {result.errors.length > 5 && (
                    <p className="text-sm text-muted-foreground">+{result.errors.length - 5} more errors</p>
                  )}
                </div>
              )}
            </CardHeader>
            <CardContent>
              {result.parsed_events.length > 0 ? (
                <EventsTable
                  events={result.parsed_events}
                  expandedId={expandedEventId}
                  onToggleExpand={setExpandedEventId}
                />
              ) : (
                <p className="text-muted-foreground text-center py-8">No valid events to display.</p>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </Layout>
  );
}

function EventsTable({
  events,
  expandedId,
  onToggleExpand,
}: {
  events: NormalizedCloudTrailEvent[];
  expandedId: string | null;
  onToggleExpand: (id: string | null) => void;
}) {
  return (
    <ScrollArea className="w-full rounded-md border">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-8" />
            <TableHead>Time</TableHead>
            <TableHead>Source</TableHead>
            <TableHead>Event</TableHead>
            <TableHead>Region</TableHead>
            <TableHead>Principal</TableHead>
            <TableHead>IP</TableHead>
            <TableHead className="w-20">Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {events.map((ev) => (
            <React.Fragment key={ev.event_id}>
              <TableRow
                key={ev.event_id}
                className="cursor-pointer"
                onClick={() => onToggleExpand(expandedId === ev.event_id ? null : ev.event_id)}
              >
                <TableCell className="w-8">
                  {expandedId === ev.event_id ? (
                    <ChevronDown className="h-4 w-4" />
                  ) : (
                    <ChevronRight className="h-4 w-4" />
                  )}
                </TableCell>
                <TableCell className="font-mono text-xs whitespace-nowrap">{ev.event_time}</TableCell>
                <TableCell className="font-mono text-xs">{ev.event_source}</TableCell>
                <TableCell className="font-mono text-xs">{ev.event_name}</TableCell>
                <TableCell className="text-xs">{ev.aws_region}</TableCell>
                <TableCell className="font-mono text-xs max-w-[120px] truncate" title={ev.principal_arn}>
                  {ev.principal_arn || ev.principal_type || "-"}
                </TableCell>
                <TableCell className="font-mono text-xs">{ev.source_ip || "-"}</TableCell>
                <TableCell>
                  {ev.is_fully_structured ? (
                    <Badge variant="secondary" className="text-xs">Valid</Badge>
                  ) : (
                    <Badge variant="outline" className="text-xs text-amber-600">Partial</Badge>
                  )}
                </TableCell>
              </TableRow>
              {expandedId === ev.event_id && (
                <TableRow>
                  <TableCell colSpan={8} className="bg-muted/30 p-4">
                    <pre className="text-xs overflow-auto max-h-64 font-mono whitespace-pre-wrap break-words">
                      {JSON.stringify(
                        {
                          event_id: ev.event_id,
                          event_time: ev.event_time,
                          event_source: ev.event_source,
                          event_name: ev.event_name,
                          aws_region: ev.aws_region,
                          source_ip: ev.source_ip,
                          principal_type: ev.principal_type,
                          principal_arn: ev.principal_arn,
                          request_parameters: ev.request_parameters,
                          response_elements: ev.response_elements,
                          resources: ev.resources,
                        },
                        null,
                        2
                      )}
                    </pre>
                  </TableCell>
                </TableRow>
              )}
            </React.Fragment>
          ))}
        </TableBody>
      </Table>
      <ScrollBar orientation="horizontal" />
    </ScrollArea>
  );
}
