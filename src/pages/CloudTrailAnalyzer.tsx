import React, { useState, useCallback, useMemo, useEffect } from "react";
import { Layout } from "@/components/Layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Popover,
  PopoverContent,
  PopoverTrigger,
} from "@/components/ui/popover";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { ScrollArea, ScrollBar } from "@/components/ui/scroll-area";
import {
  FileJson,
  Upload,
  ClipboardPaste,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  ChevronDown,
  ChevronRight,
  Search,
  Filter,
  ArrowUpDown,
  X,
  Download,
  Table2,
  List,
  Maximize2,
  Minimize2,
} from "lucide-react";
import {
  handlePasteInput,
  handleFileUpload,
  type IngestionResult,
  type NormalizedCloudTrailEvent,
} from "@/features/cloudtrail-analyzer";
import { runCorrelationEngine } from "@/features/detection-engine";
import type { DetectionResult } from "@/features/detection-engine";
import { getTechniquesForDetections, getAttackPathsForDetections } from "@/features/cloudtrail-analyzer";
import { useToast } from "@/hooks/use-toast";
import { cn } from "@/lib/utils";
import { Link } from "react-router-dom";

type SortField = "event_time" | "event_name" | "event_source" | "aws_region" | "principal_arn" | "source_ip";
type SortOrder = "asc" | "desc";
type ViewMode = "table" | "timeline";

function downloadFile(content: string, filename: string, mimeType: string = "text/plain;charset=utf-8") {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function exportEventsAsJson(events: NormalizedCloudTrailEvent[]): string {
  const exportData = events.map((e) => {
    const { _raw, ...rest } = e;
    return rest;
  });
  return JSON.stringify(exportData, null, 2);
}

function exportEventsAsCsv(events: NormalizedCloudTrailEvent[]): string {
  const headers = ["event_id", "event_time", "event_source", "event_name", "aws_region", "source_ip", "principal_type", "principal_arn"];
  const rows = events.map((e) =>
    headers.map((h) => {
      const v = (e as unknown as Record<string, unknown>)[h];
      const s = String(v ?? "");
      return s.includes(",") || s.includes('"') ? `"${s.replace(/"/g, '""')}"` : s;
    }).join(",")
  );
  return [headers.join(","), ...rows].join("\n");
}

export default function CloudTrailAnalyzer() {
  const [pasteValue, setPasteValue] = useState("");
  const [result, setResult] = useState<IngestionResult | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [expandedEventId, setExpandedEventId] = useState<string | null>(null);
  const [isFullscreen, setIsFullscreen] = useState(false);

  useEffect(() => {
    const handleEsc = (e: KeyboardEvent) => {
      if (e.key === "Escape") setIsFullscreen(false);
    };
    if (isFullscreen) {
      document.addEventListener("keydown", handleEsc);
      document.body.style.overflow = "hidden";
    }
    return () => {
      document.removeEventListener("keydown", handleEsc);
      document.body.style.overflow = "";
    };
  }, [isFullscreen]);
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedEventNames, setSelectedEventNames] = useState<Set<string>>(new Set());
  const [selectedEventSources, setSelectedEventSources] = useState<Set<string>>(new Set());
  const [selectedRegions, setSelectedRegions] = useState<Set<string>>(new Set());
  const [sortField, setSortField] = useState<SortField>("event_time");
  const [sortOrder, setSortOrder] = useState<SortOrder>("desc");
  const [viewMode, setViewMode] = useState<ViewMode>("table");
  const { toast } = useToast();

  const processPaste = useCallback(() => {
    setIsLoading(true);
    try {
      const r = handlePasteInput(pasteValue);
      setResult(r);
      if (r.valid_count > 0) {
        toast({ title: `Parsed ${r.valid_count} event(s)` });
      } else if (r.errors.length > 0) {
        toast({ title: r.errors[0].message, variant: "destructive" });
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
          toast({ title: `Parsed ${r.valid_count} event(s) from ${file.name}` });
        } else if (r.errors.length > 0) {
          toast({ title: r.errors[0].message, variant: "destructive" });
        }
      } finally {
        setIsLoading(false);
      }
    },
    [toast]
  );

  const { filteredEvents, uniqueEventNames, uniqueEventSources, uniqueRegions } = useMemo(() => {
    const events = result?.parsed_events ?? [];
    const eventNames = [...new Set(events.map((e) => e.event_name).filter(Boolean))].sort();
    const eventSources = [...new Set(events.map((e) => e.event_source).filter(Boolean))].sort();
    const regions = [...new Set(events.map((e) => e.aws_region).filter(Boolean))].sort();

    const q = searchQuery.toLowerCase().trim();
    const filtered = events.filter((ev) => {
      if (selectedEventNames.size > 0 && !selectedEventNames.has(ev.event_name)) return false;
      if (selectedEventSources.size > 0 && !selectedEventSources.has(ev.event_source)) return false;
      if (selectedRegions.size > 0 && !selectedRegions.has(ev.aws_region)) return false;
      if (q) {
        const searchable =
          [ev.event_name, ev.event_source, ev.principal_arn, ev.source_ip, ev.aws_region, ev.principal_type]
            .filter(Boolean)
            .join(" ")
            .toLowerCase();
        if (!searchable.includes(q)) return false;
      }
      return true;
    });

    const sorted = [...filtered].sort((a, b) => {
      const aVal = a[sortField] ?? "";
      const bVal = b[sortField] ?? "";
      const cmp = String(aVal).localeCompare(String(bVal), undefined, { numeric: true });
      return sortOrder === "asc" ? cmp : -cmp;
    });

    return {
      filteredEvents: sorted,
      uniqueEventNames: eventNames,
      uniqueEventSources: eventSources,
      uniqueRegions: regions,
    };
  }, [
    result?.parsed_events,
    searchQuery,
    selectedEventNames,
    selectedEventSources,
    selectedRegions,
    sortField,
    sortOrder,
  ]);

  const toggleEventName = (name: string) => {
    setSelectedEventNames((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const toggleEventSource = (src: string) => {
    setSelectedEventSources((prev) => {
      const next = new Set(prev);
      if (next.has(src)) next.delete(src);
      else next.add(src);
      return next;
    });
  };

  const toggleRegion = (r: string) => {
    setSelectedRegions((prev) => {
      const next = new Set(prev);
      if (next.has(r)) next.delete(r);
      else next.add(r);
      return next;
    });
  };

  const clearFilters = () => {
    setSearchQuery("");
    setSelectedEventNames(new Set());
    setSelectedEventSources(new Set());
    setSelectedRegions(new Set());
  };

  const hasActiveFilters =
    searchQuery.trim() ||
    selectedEventNames.size > 0 ||
    selectedEventSources.size > 0 ||
    selectedRegions.size > 0;

  const detectionMatches = useMemo(() => {
    return runCorrelationEngine(filteredEvents);
  }, [filteredEvents]);

  const detectionSummary = useMemo(() => {
    let matchedCount = 0;
    for (const [, results] of detectionMatches) {
      if (results.length > 0) matchedCount++;
    }
    return { matchedCount, total: filteredEvents.length };
  }, [detectionMatches, filteredEvents.length]);

  return (
    <Layout>
      <div className="container max-w-[1800px] py-10">
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
          <TabsList className="grid w-full max-w-sm grid-cols-2">
            <TabsTrigger value="paste" className="gap-2">
              <ClipboardPaste className="h-4 w-4" />
              Paste Event
            </TabsTrigger>
            <TabsTrigger value="file" className="gap-2">
              <Upload className="h-4 w-4" />
              File Upload
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
                  Upload CloudTrail log files or larger datasets. Supports single events, JSON arrays, `Records` bundles,
                  `.jsonl`, `.ndjson`, and `.csv` up to 50MB.
                </p>
              </CardHeader>
              <CardContent>
                <label className="flex flex-col items-center justify-center w-full h-32 border-2 border-dashed rounded-lg cursor-pointer border-muted-foreground/25 hover:border-muted-foreground/50 transition-colors">
                  <Upload className="h-8 w-8 text-muted-foreground mb-2" />
                  <span className="text-sm text-muted-foreground">Click or drag `.json`, `.jsonl`, `.ndjson`, or `.csv` file</span>
                  <input
                    type="file"
                    accept=".json,application/json,.jsonl,.ndjson,.csv,text/csv"
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
        </Tabs>

        {result && (
          <Card className="mt-8">
            <CardHeader>
              <div className="flex flex-wrap items-center gap-4">
                <CardTitle className="text-lg font-semibold tracking-tight">Ingestion Results</CardTitle>
                <div className="flex gap-2">
                  <Badge variant="secondary" className="gap-1.5 text-sm font-medium">
                    <CheckCircle2 className="h-3.5 w-3.5" />
                    Valid: {result.valid_count}
                  </Badge>
                  {result.malformed_count > 0 && (
                    <Badge variant="destructive" className="gap-1.5 text-sm font-medium">
                      <XCircle className="h-3.5 w-3.5" />
                      Malformed: {result.malformed_count}
                    </Badge>
                  )}
                  <Badge variant="outline" className="text-sm font-medium">Total: {result.total_count}</Badge>
                  {filteredEvents.length > 0 && (
                    <Badge variant="outline" className="text-sm font-medium">
                      Matched: {detectionSummary.matchedCount}/{detectionSummary.total}
                    </Badge>
                  )}
                </div>
              </div>
              {result.errors.length > 0 && (
                <div className="space-y-1 mt-2">
                  {result.errors.slice(0, 5).map((err, i) => (
                    <p key={i} className="text-sm font-medium text-destructive flex items-center gap-2">
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
            <CardContent className="space-y-4">
              {result.parsed_events.length > 0 ? (
                <>
                  <EventFilters
                    searchQuery={searchQuery}
                    onSearchChange={setSearchQuery}
                    uniqueEventNames={uniqueEventNames}
                    uniqueEventSources={uniqueEventSources}
                    uniqueRegions={uniqueRegions}
                    selectedEventNames={selectedEventNames}
                    selectedEventSources={selectedEventSources}
                    selectedRegions={selectedRegions}
                    onToggleEventName={toggleEventName}
                    onToggleEventSource={toggleEventSource}
                    onToggleRegion={toggleRegion}
                    sortField={sortField}
                    sortOrder={sortOrder}
                    onSortFieldChange={setSortField}
                    onSortOrderChange={setSortOrder}
                    hasActiveFilters={!!hasActiveFilters}
                    onClearFilters={clearFilters}
                    filteredCount={filteredEvents.length}
                    totalCount={result.parsed_events.length}
                    viewMode={viewMode}
                    onViewModeChange={setViewMode}
                    isFullscreen={isFullscreen}
                    onFullscreenChange={setIsFullscreen}
                    onExportJson={() => {
                      const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
                      downloadFile(exportEventsAsJson(filteredEvents), `cloudtrail-events-${ts}.json`, "application/json");
                      toast({ title: "Exported as JSON" });
                    }}
                    onExportCsv={() => {
                      const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
                      downloadFile(exportEventsAsCsv(filteredEvents), `cloudtrail-events-${ts}.csv`, "text/csv");
                      toast({ title: "Exported as CSV" });
                    }}
                    canExport={filteredEvents.length > 0}
                  />
                  {filteredEvents.length > 0 ? (
                    viewMode === "table" ? (
                      <EventsTable
                        events={filteredEvents}
                        expandedId={expandedEventId}
                        onToggleExpand={setExpandedEventId}
                        detectionMatches={detectionMatches}
                      />
                    ) : (
                      <EventsTimeline
                        events={filteredEvents}
                        expandedId={expandedEventId}
                        onToggleExpand={setExpandedEventId}
                        detectionMatches={detectionMatches}
                      />
                    )
                  ) : (
                    <p className="text-muted-foreground text-center py-8">
                      No events match your filters. Try adjusting or clearing filters.
                    </p>
                  )}

                  {isFullscreen && filteredEvents.length > 0 && (
                    <div className="fixed inset-0 z-50 flex flex-col bg-background">
                      <div className="flex items-center justify-between gap-4 border-b px-4 py-3 shrink-0">
                        <h3 className="font-semibold">Events — Full Screen</h3>
                        <Button
                          variant="ghost"
                          size="icon"
                          onClick={() => setIsFullscreen(false)}
                          className="shrink-0"
                          aria-label="Exit full screen"
                        >
                          <Minimize2 className="h-4 w-4" />
                        </Button>
                      </div>
                      <div className="flex-1 min-h-0 flex flex-col p-4 overflow-hidden">
                        <div className="shrink-0 mb-4">
                          <EventFilters
                            searchQuery={searchQuery}
                            onSearchChange={setSearchQuery}
                            uniqueEventNames={uniqueEventNames}
                            uniqueEventSources={uniqueEventSources}
                            uniqueRegions={uniqueRegions}
                            selectedEventNames={selectedEventNames}
                            selectedEventSources={selectedEventSources}
                            selectedRegions={selectedRegions}
                            onToggleEventName={toggleEventName}
                            onToggleEventSource={toggleEventSource}
                            onToggleRegion={toggleRegion}
                            sortField={sortField}
                            sortOrder={sortOrder}
                            onSortFieldChange={setSortField}
                            onSortOrderChange={setSortOrder}
                            hasActiveFilters={!!hasActiveFilters}
                            onClearFilters={clearFilters}
                            filteredCount={filteredEvents.length}
                            totalCount={result.parsed_events.length}
                            viewMode={viewMode}
                            onViewModeChange={setViewMode}
                            isFullscreen={isFullscreen}
                            onFullscreenChange={setIsFullscreen}
                            onExportJson={() => {
                              const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
                              downloadFile(exportEventsAsJson(filteredEvents), `cloudtrail-events-${ts}.json`, "application/json");
                              toast({ title: "Exported as JSON" });
                            }}
                            onExportCsv={() => {
                              const ts = new Date().toISOString().replace(/[:.]/g, "-").slice(0, 19);
                              downloadFile(exportEventsAsCsv(filteredEvents), `cloudtrail-events-${ts}.csv`, "text/csv");
                              toast({ title: "Exported as CSV" });
                            }}
                            canExport={filteredEvents.length > 0}
                          />
                        </div>
                        <div className="flex-1 min-h-0 rounded-lg border overflow-hidden">
                          {viewMode === "table" ? (
                            <EventsTable
                              events={filteredEvents}
                              expandedId={expandedEventId}
                              onToggleExpand={setExpandedEventId}
                              detectionMatches={detectionMatches}
                              className="h-full"
                            />
                          ) : (
                            <EventsTimeline
                              events={filteredEvents}
                              expandedId={expandedEventId}
                              onToggleExpand={setExpandedEventId}
                              detectionMatches={detectionMatches}
                              className="h-full"
                            />
                          )}
                        </div>
                      </div>
                    </div>
                  )}
                </>
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

function EventFilters({
  searchQuery,
  onSearchChange,
  uniqueEventNames,
  uniqueEventSources,
  uniqueRegions,
  selectedEventNames,
  selectedEventSources,
  selectedRegions,
  onToggleEventName,
  onToggleEventSource,
  onToggleRegion,
  sortField,
  sortOrder,
  onSortFieldChange,
  onSortOrderChange,
  hasActiveFilters,
  onClearFilters,
  filteredCount,
  totalCount,
  viewMode = "table",
  onViewModeChange,
  onExportJson,
  onExportCsv,
  canExport = false,
  isFullscreen = false,
  onFullscreenChange,
}: {
  searchQuery: string;
  onSearchChange: (v: string) => void;
  uniqueEventNames: string[];
  uniqueEventSources: string[];
  uniqueRegions: string[];
  selectedEventNames: Set<string>;
  selectedEventSources: Set<string>;
  selectedRegions: Set<string>;
  onToggleEventName: (name: string) => void;
  onToggleEventSource: (src: string) => void;
  onToggleRegion: (r: string) => void;
  sortField: SortField;
  sortOrder: SortOrder;
  onSortFieldChange: (v: SortField) => void;
  onSortOrderChange: (v: SortOrder) => void;
  hasActiveFilters: boolean;
  onClearFilters: () => void;
  filteredCount: number;
  totalCount: number;
  viewMode?: ViewMode;
  onViewModeChange?: (mode: ViewMode) => void;
  onExportJson?: () => void;
  onExportCsv?: () => void;
  canExport?: boolean;
  isFullscreen?: boolean;
  onFullscreenChange?: (value: boolean) => void;
}) {
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <div className="relative flex-1 min-w-[180px] max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search events..."
            value={searchQuery}
            onChange={(e) => onSearchChange(e.target.value)}
            className="pl-9"
          />
        </div>

        <Popover>
          <PopoverTrigger asChild>
            <Button variant="outline" size="sm" className="gap-1.5">
              <Filter className="h-3.5 w-3.5" />
              Event Names
              {selectedEventNames.size > 0 && (
                <Badge variant="secondary" className="ml-1 h-5 px-1.5 text-xs">
                  {selectedEventNames.size}
                </Badge>
              )}
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-64 p-2" align="start">
            <div className="max-h-56 overflow-y-auto space-y-2">
              {uniqueEventNames.length === 0 ? (
                <p className="text-sm text-muted-foreground py-2">No event names</p>
              ) : (
                uniqueEventNames.map((name) => (
                  <label
                    key={name}
                    className="flex items-center gap-2 cursor-pointer hover:bg-muted/50 rounded px-2 py-1.5 text-sm"
                  >
                    <Checkbox
                      checked={selectedEventNames.has(name)}
                      onCheckedChange={() => onToggleEventName(name)}
                    />
                    <span className="font-mono truncate">{name}</span>
                  </label>
                ))
              )}
            </div>
            <p className="text-xs text-muted-foreground mt-2 px-2">
              {selectedEventNames.size === 0 ? "All events" : `${selectedEventNames.size} selected`}
            </p>
          </PopoverContent>
        </Popover>

        <Popover>
          <PopoverTrigger asChild>
            <Button variant="outline" size="sm" className="gap-1.5">
              <Filter className="h-3.5 w-3.5" />
              Sources
              {selectedEventSources.size > 0 && (
                <Badge variant="secondary" className="ml-1 h-5 px-1.5 text-xs">
                  {selectedEventSources.size}
                </Badge>
              )}
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-64 p-2" align="start">
            <div className="max-h-56 overflow-y-auto space-y-2">
              {uniqueEventSources.length === 0 ? (
                <p className="text-sm text-muted-foreground py-2">No sources</p>
              ) : (
                uniqueEventSources.map((src) => (
                  <label
                    key={src}
                    className="flex items-center gap-2 cursor-pointer hover:bg-muted/50 rounded px-2 py-1.5 text-sm"
                  >
                    <Checkbox
                      checked={selectedEventSources.has(src)}
                      onCheckedChange={() => onToggleEventSource(src)}
                    />
                    <span className="font-mono text-xs truncate">{src}</span>
                  </label>
                ))
              )}
            </div>
          </PopoverContent>
        </Popover>

        <Popover>
          <PopoverTrigger asChild>
            <Button variant="outline" size="sm" className="gap-1.5">
              <Filter className="h-3.5 w-3.5" />
              Regions
              {selectedRegions.size > 0 && (
                <Badge variant="secondary" className="ml-1 h-5 px-1.5 text-xs">
                  {selectedRegions.size}
                </Badge>
              )}
            </Button>
          </PopoverTrigger>
          <PopoverContent className="w-48 p-2" align="start">
            <div className="max-h-56 overflow-y-auto space-y-2">
              {uniqueRegions.length === 0 ? (
                <p className="text-sm text-muted-foreground py-2">No regions</p>
              ) : (
                uniqueRegions.map((r) => (
                  <label
                    key={r}
                    className="flex items-center gap-2 cursor-pointer hover:bg-muted/50 rounded px-2 py-1.5 text-sm"
                  >
                    <Checkbox checked={selectedRegions.has(r)} onCheckedChange={() => onToggleRegion(r)} />
                    <span>{r}</span>
                  </label>
                ))
              )}
            </div>
          </PopoverContent>
        </Popover>

        <Select value={sortField} onValueChange={(v) => onSortFieldChange(v as SortField)}>
          <SelectTrigger className="w-[140px]">
            <ArrowUpDown className="h-3.5 w-3.5 mr-1.5" />
            <SelectValue placeholder="Sort by" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="event_time">Time</SelectItem>
            <SelectItem value="event_name">Event Name</SelectItem>
            <SelectItem value="event_source">Source</SelectItem>
            <SelectItem value="aws_region">Region</SelectItem>
            <SelectItem value="principal_arn">Principal</SelectItem>
            <SelectItem value="source_ip">IP Address</SelectItem>
          </SelectContent>
        </Select>

        <Select value={sortOrder} onValueChange={(v) => onSortOrderChange(v as SortOrder)}>
          <SelectTrigger className="w-[120px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="asc">Ascending</SelectItem>
            <SelectItem value="desc">Descending</SelectItem>
          </SelectContent>
        </Select>

        {hasActiveFilters && (
          <Button variant="ghost" size="sm" onClick={onClearFilters} className="gap-1 text-muted-foreground">
            <X className="h-3.5 w-3.5" />
            Clear filters
          </Button>
        )}

        {onViewModeChange && (
          <div className="flex border rounded-md">
            <Button
              variant={viewMode === "table" ? "secondary" : "ghost"}
              size="sm"
              onClick={() => onViewModeChange("table")}
              className="rounded-r-none"
            >
              <Table2 className="h-3.5 w-3.5" />
            </Button>
            <Button
              variant={viewMode === "timeline" ? "secondary" : "ghost"}
              size="sm"
              onClick={() => onViewModeChange("timeline")}
              className="rounded-l-none"
            >
              <List className="h-3.5 w-3.5" />
            </Button>
          </div>
        )}

        {canExport && onExportJson && onExportCsv && (
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <Button variant="outline" size="sm" className="gap-1.5">
                <Download className="h-3.5 w-3.5" />
                Export
              </Button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="end">
              <DropdownMenuItem onClick={onExportJson}>Export as JSON</DropdownMenuItem>
              <DropdownMenuItem onClick={onExportCsv}>Export as CSV</DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
        )}

        {onFullscreenChange && (
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                variant="outline"
                size="sm"
                onClick={() => onFullscreenChange(!isFullscreen)}
                aria-label={isFullscreen ? "Exit full screen" : "Full screen"}
              >
                {isFullscreen ? (
                  <Minimize2 className="h-3.5 w-3.5" />
                ) : (
                  <Maximize2 className="h-3.5 w-3.5" />
                )}
              </Button>
            </TooltipTrigger>
            <TooltipContent>
              {isFullscreen ? "Exit full screen (Esc)" : "Full screen"}
            </TooltipContent>
          </Tooltip>
        )}
      </div>
      {(hasActiveFilters || filteredCount !== totalCount) && (
        <p className="text-sm text-muted-foreground">
          Showing {filteredCount} of {totalCount} events
        </p>
      )}
    </div>
  );
}

const severityColors: Record<string, string> = {
  Critical: "bg-red-500/20 text-red-400 border-red-500/30",
  High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  Medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  Low: "bg-muted text-muted-foreground",
};

function DetectionBadges({ results }: { results: DetectionResult[] }) {
  if (results.length === 0) return <span className="text-sm text-muted-foreground">No matches</span>;
  return (
    <div className="flex flex-wrap gap-2 min-w-0">
      {results.map((r) => (
        <Badge
          key={r.ruleId}
          variant="outline"
          title={r.reason}
          className={`text-xs px-2.5 py-1 min-w-0 max-w-full shrink cursor-default overflow-hidden ${severityColors[r.severity] ?? ""}`}
        >
          <span className="block truncate min-w-0">
            {r.ruleName}
          </span>
        </Badge>
      ))}
    </div>
  );
}

function EventsTimeline({
  events,
  expandedId,
  onToggleExpand,
  detectionMatches = new Map(),
  className,
}: {
  events: NormalizedCloudTrailEvent[];
  expandedId: string | null;
  onToggleExpand: (id: string | null) => void;
  detectionMatches?: Map<string, DetectionResult[]>;
  className?: string;
}) {
  return (
    <ScrollArea className={cn("w-full rounded-md border", className)}>
      <div className="p-5">
        {events.map((ev) => (
          <React.Fragment key={ev.event_id}>
            <div
              className="flex gap-6 py-4 px-3 border-b last:border-b-0 cursor-pointer hover:bg-muted/30 transition-colors rounded-sm"
              onClick={() => onToggleExpand(expandedId === ev.event_id ? null : ev.event_id)}
            >
              <div className="shrink-0 w-40 font-mono text-sm text-muted-foreground whitespace-nowrap pt-0.5">
                {ev.event_time}
              </div>
              <div className="flex-1 min-w-0 space-y-2">
                <div className="flex items-center gap-3 flex-wrap">
                  <span className="font-mono text-sm font-semibold">{ev.event_name}</span>
                  <span className="text-muted-foreground">·</span>
                  <span className="font-mono text-sm text-muted-foreground">{ev.event_source}</span>
                  <span className="text-muted-foreground">·</span>
                  <span className="text-sm">{ev.aws_region}</span>
                </div>
                <div className="text-sm text-muted-foreground break-all">
                  {ev.principal_arn || ev.principal_type || ev.source_ip || "-"}
                </div>
                <div className="pt-1">
                  <DetectionBadges results={detectionMatches.get(ev.event_id) ?? []} />
                </div>
              </div>
              <div className="shrink-0 self-center">
                {expandedId === ev.event_id ? (
                  <ChevronDown className="h-4 w-4" />
                ) : (
                  <ChevronRight className="h-4 w-4" />
                )}
              </div>
            </div>
            {expandedId === ev.event_id && (
              <div className="ml-40 mr-3 mb-4 px-4 py-4 bg-muted/30 rounded-md space-y-4">
                <EventExpandedDetail event={ev} results={detectionMatches.get(ev.event_id) ?? []} />
              </div>
            )}
          </React.Fragment>
        ))}
      </div>
      <ScrollBar orientation="horizontal" />
    </ScrollArea>
  );
}

function EventExpandedDetail({ event: ev, results }: { event: NormalizedCloudTrailEvent; results: DetectionResult[] }) {
  const platformIds = results.filter((r) => r.ruleId.startsWith("det-")).map((r) => r.ruleId);
  const techniques = getTechniquesForDetections(platformIds);
  const attackPaths = getAttackPathsForDetections(platformIds);

  return (
    <>
      {results.length > 0 && (
        <div className="space-y-3">
          <p className="text-xs font-semibold text-muted-foreground">Detection results</p>
          {results.map((r) => (
            <div key={r.ruleId} className="rounded border border-border/50 p-3 space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[10px] uppercase tracking-wider text-muted-foreground/80 px-1.5 py-0.5 rounded border border-border/50 shrink-0">
                  {r.ruleType === "correlation" ? "Correlation" : "Single"}
                </span>
                <Badge variant="outline" className={`text-xs ${severityColors[r.severity] ?? ""}`}>
                  {r.ruleName}
                </Badge>
                {r.resource && (
                  <span className="text-xs text-muted-foreground">Resource: {r.resource}</span>
                )}
              </div>
              {r.matchedEvents && r.matchedEvents.length > 1 && (
                <div className="text-xs">
                  <span className="font-medium text-muted-foreground">Matched events: </span>
                  {r.matchedEvents.map((me, i) => (
                    <span key={me.event_id}>
                      {i > 0 && " → "}
                      <span className="font-mono">{me.event_name}</span>
                      {me.resource && ` (${me.resource})`}
                    </span>
                  ))}
                </div>
              )}
              {r.timeWindow && (
                <div className="text-xs text-muted-foreground">
                  Window: {r.timeWindow.start} to {r.timeWindow.end}
                </div>
              )}
              <p className="text-xs text-muted-foreground">{r.reason}</p>
            </div>
          ))}
          {techniques.length > 0 && (
            <>
              <p className="text-xs font-semibold text-muted-foreground mt-2">Techniques</p>
              <div className="flex flex-wrap gap-1">
                {techniques.map((t) => (
                  <Link key={t.techniqueId} to={`/attack-paths/technique/${t.techniqueId}`}>
                    <Badge variant="secondary" className="text-xs cursor-pointer">{t.name}</Badge>
                  </Link>
                ))}
              </div>
            </>
          )}
          {attackPaths.length > 0 && (
            <>
              <p className="text-xs font-semibold text-muted-foreground mt-2">Attack paths</p>
              <div className="flex flex-wrap gap-1">
                {attackPaths.map((p) => (
                  <Link key={p.slug} to={`/attack-paths?technique=${p.slug}`}>
                    <Badge variant="secondary" className="text-xs cursor-pointer">{p.title}</Badge>
                  </Link>
                ))}
              </div>
            </>
          )}
        </div>
      )}
      <pre className="text-sm font-mono antialiased overflow-auto max-h-64 whitespace-pre-wrap break-words leading-relaxed">
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
    </>
  );
}

function EventsTable({
  events,
  expandedId,
  onToggleExpand,
  detectionMatches = new Map(),
  className,
}: {
  events: NormalizedCloudTrailEvent[];
  expandedId: string | null;
  onToggleExpand: (id: string | null) => void;
  detectionMatches?: Map<string, DetectionResult[]>;
  className?: string;
}) {
  return (
    <ScrollArea className={cn("w-full rounded-lg border", className)}>
      <Table className="w-full min-w-[1200px] table-fixed">
        <colgroup>
          <col style={{ width: "3%" }} />
          <col style={{ width: "11%" }} />
          <col style={{ width: "14%" }} />
          <col style={{ width: "15%" }} />
          <col style={{ width: "8%" }} />
          <col style={{ width: "22%" }} />
          <col style={{ width: "10%" }} />
          <col style={{ width: "7%" }} />
          <col style={{ width: "10%" }} />
        </colgroup>
        <TableHeader>
          <TableRow className="hover:bg-transparent">
            <TableHead className="w-10 px-5 py-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground" />
            <TableHead className="px-5 py-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Time</TableHead>
            <TableHead className="px-5 py-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Source</TableHead>
            <TableHead className="px-5 py-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Event</TableHead>
            <TableHead className="px-5 py-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Region</TableHead>
            <TableHead className="px-5 py-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Principal</TableHead>
            <TableHead className="px-5 py-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">IP</TableHead>
            <TableHead className="px-5 py-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Status</TableHead>
            <TableHead className="px-5 py-4 text-xs font-semibold uppercase tracking-wider text-muted-foreground">Detections</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {events.map((ev) => (
            <React.Fragment key={ev.event_id}>
              <TableRow
                key={ev.event_id}
                className="cursor-pointer transition-colors"
                onClick={() => onToggleExpand(expandedId === ev.event_id ? null : ev.event_id)}
              >
                <TableCell className="w-10 px-5 py-5 align-middle overflow-hidden">
                  {expandedId === ev.event_id ? (
                    <ChevronDown className="h-4 w-4 text-muted-foreground shrink-0" />
                  ) : (
                    <ChevronRight className="h-4 w-4 text-muted-foreground shrink-0" />
                  )}
                </TableCell>
                <TableCell className="px-5 py-5 align-middle overflow-hidden min-w-0">
                  <span className="block font-mono text-sm whitespace-nowrap truncate">
                    {ev.event_time}
                  </span>
                </TableCell>
                <TableCell className="px-5 py-5 align-middle overflow-hidden min-w-0">
                  <div className="min-w-0 overflow-hidden">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="block font-mono text-sm truncate cursor-default">
                          {ev.event_source}
                        </span>
                      </TooltipTrigger>
                      <TooltipContent side="top" className="max-w-md break-all font-mono text-xs">
                        {ev.event_source}
                      </TooltipContent>
                    </Tooltip>
                  </div>
                </TableCell>
                <TableCell className="px-5 py-5 align-middle overflow-hidden min-w-0">
                  <div className="min-w-0 overflow-hidden">
                    <Tooltip>
                      <TooltipTrigger asChild>
                        <span className="block font-mono text-sm font-medium truncate cursor-default">
                          {ev.event_name}
                        </span>
                      </TooltipTrigger>
                      <TooltipContent side="top" className="max-w-md break-all font-mono text-xs">
                        {ev.event_name}
                      </TooltipContent>
                    </Tooltip>
                  </div>
                </TableCell>
                <TableCell className="px-5 py-5 text-sm whitespace-nowrap align-middle overflow-hidden">
                  {ev.aws_region}
                </TableCell>
                <TableCell className="px-5 py-5 align-middle overflow-hidden min-w-0">
                  <div className="min-w-0 overflow-hidden">
                    {(ev.principal_arn || ev.principal_type) ? (
                      <Tooltip>
                        <TooltipTrigger asChild>
                          <span className="block font-mono text-sm truncate cursor-default">
                            {ev.principal_arn || ev.principal_type}
                          </span>
                        </TooltipTrigger>
                        <TooltipContent side="top" className="max-w-md break-all font-mono text-xs">
                          {ev.principal_arn || ev.principal_type}
                        </TooltipContent>
                      </Tooltip>
                    ) : (
                      <span className="text-muted-foreground">—</span>
                    )}
                  </div>
                </TableCell>
                <TableCell className="px-5 py-5 font-mono text-sm whitespace-nowrap align-middle overflow-hidden">
                  {ev.source_ip || <span className="text-muted-foreground">—</span>}
                </TableCell>
                <TableCell className="px-5 py-5 align-middle overflow-hidden">
                  {ev.is_fully_structured ? (
                    <Badge variant="secondary" className="text-xs font-medium">Valid</Badge>
                  ) : (
                    <Badge variant="outline" className="text-xs font-medium text-amber-600">Partial</Badge>
                  )}
                </TableCell>
                <TableCell className="px-5 py-5 align-middle overflow-hidden min-w-0">
                  <div className="min-w-0 overflow-hidden">
                    <DetectionBadges results={detectionMatches.get(ev.event_id) ?? []} />
                  </div>
                </TableCell>
              </TableRow>
              {expandedId === ev.event_id && (
                <TableRow>
                  <TableCell colSpan={9} className="bg-muted/30 p-4">
                    <EventExpandedDetail event={ev} results={detectionMatches.get(ev.event_id) ?? []} />
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
