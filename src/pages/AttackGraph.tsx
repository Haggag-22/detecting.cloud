import { useMemo, useState, useCallback } from "react";
import { Layout } from "@/components/Layout";
import {
  ReactFlow,
  Node,
  Edge,
  Background,
  Controls,
  MiniMap,
  useNodesState,
  useEdgesState,
  BackgroundVariant,
  Panel,
  NodeProps,
  Handle,
  Position,
} from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { attackPaths } from "@/data/attackPaths";
import { detections } from "@/data/detections";
import { Badge } from "@/components/ui/badge";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Shield, Crosshair, Eye, Cloud, FileText, Search } from "lucide-react";
import { Input } from "@/components/ui/input";

type GraphNodeType = "attack" | "detection" | "service" | "logSource";

interface GraphNodeData {
  label: string;
  nodeType: GraphNodeType;
  category?: string;
  severity?: string;
  link?: string;
  tags?: string[];
  [key: string]: unknown;
}

// Build a focused graph around a single attack technique
function buildTechniqueGraph(slug: string) {
  const ap = attackPaths.find((a) => a.slug === slug);
  if (!ap) return { nodes: [], edges: [] };

  const nodes: Node<GraphNodeData>[] = [];
  const edges: Edge[] = [];

  // Center: the attack technique
  nodes.push({
    id: `attack-${ap.slug}`,
    type: "graphNode",
    position: { x: 500, y: 300 },
    data: {
      label: ap.title,
      nodeType: "attack",
      category: ap.category,
      severity: ap.severity,
      link: `/attack-paths?technique=${ap.slug}`,
      tags: ap.tags,
    },
  });

  // Left: AWS services used
  const services = ap.tags.filter((t) =>
    ["IAM", "Lambda", "S3", "EC2", "CloudTrail", "STS", "Glue", "VPC", "KMS", "EBS", "DynamoDB", "EKS"].includes(t)
  );
  services.forEach((svc, i) => {
    nodes.push({
      id: `service-${svc}`,
      type: "graphNode",
      position: { x: 100, y: 150 + i * 130 },
      data: { label: svc, nodeType: "service" },
    });
    edges.push({
      id: `e-svc-${svc}-attack`,
      source: `service-${svc}`,
      target: `attack-${ap.slug}`,
      style: { stroke: "hsl(210 79% 46% / 0.5)", strokeWidth: 1.5 },
      label: "targets",
      labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
      labelBgStyle: { fill: "hsl(215 40% 6%)", fillOpacity: 0.9 },
    });
  });

  // Right: detection rules
  const relatedDets = detections.filter((d) => ap.relatedDetectionIds.includes(d.id));
  relatedDets.forEach((det, i) => {
    nodes.push({
      id: `detection-${det.id}`,
      type: "graphNode",
      position: { x: 900, y: 100 + i * 160 },
      data: {
        label: det.title,
        nodeType: "detection",
        link: `/detection-engineering?rule=${det.id}`,
      },
    });
    edges.push({
      id: `e-attack-det-${det.id}`,
      source: `attack-${ap.slug}`,
      target: `detection-${det.id}`,
      animated: true,
      style: { stroke: "hsl(43 96% 56% / 0.5)", strokeWidth: 2 },
      label: "detected by",
      labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
      labelBgStyle: { fill: "hsl(215 40% 6%)", fillOpacity: 0.9 },
    });

    // Far right: log sources for each detection
    det.logSources.forEach((ls, j) => {
      const logId = `log-${det.id}-${ls.replace(/\s/g, "_")}`;
      if (!nodes.find((n) => n.id === logId)) {
        nodes.push({
          id: logId,
          type: "graphNode",
          position: { x: 1300, y: 80 + i * 160 + j * 80 },
          data: { label: ls, nodeType: "logSource" },
        });
      }
      edges.push({
        id: `e-det-${det.id}-log-${ls.replace(/\s/g, "_")}`,
        source: `detection-${det.id}`,
        target: logId,
        style: { stroke: "hsl(142 71% 45% / 0.4)", strokeWidth: 1.5 },
        label: "analyzes",
        labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
        labelBgStyle: { fill: "hsl(215 40% 6%)", fillOpacity: 0.9 },
      });
    });
  });

  return { nodes, edges };
}

// Build a focused graph around a single detection rule
function buildDetectionGraph(detId: string) {
  const det = detections.find((d) => d.id === detId);
  if (!det) return { nodes: [], edges: [] };

  const nodes: Node<GraphNodeData>[] = [];
  const edges: Edge[] = [];

  // Center: the detection rule
  nodes.push({
    id: `detection-${det.id}`,
    type: "graphNode",
    position: { x: 500, y: 300 },
    data: {
      label: det.title,
      nodeType: "detection",
      link: `/detection-engineering?rule=${det.id}`,
    },
  });

  // Left: attack techniques that this rule detects
  const relatedAttacks = attackPaths.filter((ap) => ap.relatedDetectionIds.includes(det.id));
  relatedAttacks.forEach((ap, i) => {
    nodes.push({
      id: `attack-${ap.slug}`,
      type: "graphNode",
      position: { x: 100, y: 150 + i * 140 },
      data: {
        label: ap.title,
        nodeType: "attack",
        severity: ap.severity,
        link: `/attack-paths?technique=${ap.slug}`,
      },
    });
    edges.push({
      id: `e-attack-${ap.slug}-det`,
      source: `attack-${ap.slug}`,
      target: `detection-${det.id}`,
      animated: true,
      style: { stroke: "hsl(43 96% 56% / 0.5)", strokeWidth: 2 },
      label: "detected by",
      labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
      labelBgStyle: { fill: "hsl(215 40% 6%)", fillOpacity: 0.9 },
    });
  });

  // Right: log sources
  det.logSources.forEach((ls, i) => {
    const logId = `log-${ls.replace(/\s/g, "_")}`;
    nodes.push({
      id: logId,
      type: "graphNode",
      position: { x: 900, y: 200 + i * 120 },
      data: { label: ls, nodeType: "logSource" },
    });
    edges.push({
      id: `e-det-log-${ls.replace(/\s/g, "_")}`,
      source: `detection-${det.id}`,
      target: logId,
      style: { stroke: "hsl(142 71% 45% / 0.4)", strokeWidth: 1.5 },
      label: "analyzes",
      labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
      labelBgStyle: { fill: "hsl(215 40% 6%)", fillOpacity: 0.9 },
    });
  });

  // Top: AWS service
  nodes.push({
    id: `service-${det.awsService}`,
    type: "graphNode",
    position: { x: 500, y: 80 },
    data: { label: det.awsService, nodeType: "service" },
  });
  edges.push({
    id: `e-svc-det`,
    source: `service-${det.awsService}`,
    target: `detection-${det.id}`,
    style: { stroke: "hsl(210 79% 46% / 0.5)", strokeWidth: 1.5 },
    label: "monitors",
    labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
    labelBgStyle: { fill: "hsl(215 40% 6%)", fillOpacity: 0.9 },
  });

  return { nodes, edges };
}

const nodeColors: Record<GraphNodeType, { bg: string; border: string; text: string; icon: typeof Shield }> = {
  attack: { bg: "bg-destructive/10", border: "border-destructive/40", text: "text-destructive", icon: Crosshair },
  detection: { bg: "bg-primary/10", border: "border-primary/40", text: "text-primary", icon: Eye },
  service: { bg: "bg-accent/10", border: "border-accent/40", text: "text-accent", icon: Cloud },
  logSource: { bg: "bg-green-500/10", border: "border-green-500/40", text: "text-green-400", icon: FileText },
};

function GraphNodeComponent({ data }: NodeProps<Node<GraphNodeData>>) {
  const navigate = useNavigate();
  const config = nodeColors[data.nodeType];
  const Icon = config.icon;

  return (
    <div
      className={`px-3 py-2 rounded-lg border ${config.bg} ${config.border} cursor-pointer hover:scale-105 transition-transform min-w-[120px] max-w-[220px]`}
      onClick={() => data.link && navigate(data.link)}
    >
      <Handle type="target" position={Position.Left} className="!bg-muted-foreground !w-2 !h-2" />
      <Handle type="source" position={Position.Right} className="!bg-muted-foreground !w-2 !h-2" />
      <div className="flex items-center gap-2">
        <Icon className={`h-3.5 w-3.5 shrink-0 ${config.text}`} />
        <span className="text-xs font-medium text-foreground truncate">{data.label}</span>
      </div>
      {data.severity && (
        <Badge className={`text-[10px] mt-1 border-0 ${
          data.severity === "Critical" ? "bg-destructive/20 text-destructive" :
          data.severity === "High" ? "bg-primary/20 text-primary" : "bg-accent/20 text-accent"
        }`}>
          {data.severity}
        </Badge>
      )}
    </div>
  );
}

const nodeTypes = { graphNode: GraphNodeComponent };

// Combine all searchable items
const allItems = [
  ...attackPaths.map((ap) => ({ id: ap.slug, label: ap.title, type: "technique" as const })),
  ...detections.map((d) => ({ id: d.id, label: d.title, type: "detection" as const })),
];

const AttackGraphPage = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedTechnique = searchParams.get("technique");
  const selectedDetection = searchParams.get("rule");

  const [search, setSearch] = useState("");

  const hasSelection = !!selectedTechnique || !!selectedDetection;

  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    if (selectedTechnique) return buildTechniqueGraph(selectedTechnique);
    if (selectedDetection) return buildDetectionGraph(selectedDetection);
    return { nodes: [], edges: [] };
  }, [selectedTechnique, selectedDetection]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Sync when selection changes
  useMemo(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  const handleSelect = useCallback((item: typeof allItems[0]) => {
    setSearch("");
    if (item.type === "technique") {
      setSearchParams({ technique: item.id });
    } else {
      setSearchParams({ rule: item.id });
    }
  }, [setSearchParams]);

  const filteredItems = search.trim()
    ? allItems.filter((item) => item.label.toLowerCase().includes(search.toLowerCase())).slice(0, 10)
    : [];

  return (
    <Layout>
      <div className="container py-8">
        <div className="mb-6">
          <h1 className="font-display text-3xl font-bold mb-2">Attack & Detection Graph</h1>
          <p className="text-muted-foreground text-sm">
            Search for an attack technique or detection rule to visualize its relationships with AWS services, detections, and log sources.
          </p>
        </div>

        {/* Search bar */}
        <div className="relative mb-6 max-w-lg">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search a technique or detection rule..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-10 bg-card border-border/50"
          />
          {filteredItems.length > 0 && (
            <div className="absolute top-full left-0 right-0 mt-1 bg-card border border-border/50 rounded-lg shadow-xl z-50 max-h-64 overflow-y-auto">
              {filteredItems.map((item) => (
                <button
                  key={`${item.type}-${item.id}`}
                  onClick={() => handleSelect(item)}
                  className="w-full text-left px-4 py-2.5 text-sm hover:bg-muted/50 flex items-center gap-3 transition-colors"
                >
                  {item.type === "technique" ? (
                    <Crosshair className="h-3.5 w-3.5 text-destructive shrink-0" />
                  ) : (
                    <Eye className="h-3.5 w-3.5 text-primary shrink-0" />
                  )}
                  <span className="truncate text-foreground">{item.label}</span>
                  <span className="text-xs text-muted-foreground ml-auto shrink-0 capitalize">{item.type}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Quick picks when nothing selected */}
        {!hasSelection && (
          <div className="space-y-4">
            <h2 className="text-sm font-medium text-muted-foreground uppercase tracking-wider">Select a technique to visualize</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
              {attackPaths.map((ap) => (
                <button
                  key={ap.slug}
                  onClick={() => setSearchParams({ technique: ap.slug })}
                  className="text-left p-4 rounded-lg border border-border/50 bg-card hover:border-primary/30 hover:bg-primary/5 transition-colors group"
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Crosshair className="h-3.5 w-3.5 text-destructive" />
                    <span className="text-sm font-medium text-foreground group-hover:text-primary transition-colors">{ap.title}</span>
                  </div>
                  <p className="text-xs text-muted-foreground line-clamp-2">{ap.overview}</p>
                  <Badge className={`text-[10px] mt-2 border-0 ${
                    ap.severity === "Critical" ? "bg-destructive/20 text-destructive" :
                    ap.severity === "High" ? "bg-primary/20 text-primary" : "bg-accent/20 text-accent"
                  }`}>
                    {ap.severity}
                  </Badge>
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Graph - only when something is selected */}
        {hasSelection && (
          <div className="rounded-lg border border-border/50 bg-card overflow-hidden" style={{ height: "70vh" }}>
            <ReactFlow
              nodes={nodes}
              edges={edges}
              onNodesChange={onNodesChange}
              onEdgesChange={onEdgesChange}
              nodeTypes={nodeTypes}
              fitView
              minZoom={0.3}
              maxZoom={2}
              defaultEdgeOptions={{ type: "smoothstep" }}
              proOptions={{ hideAttribution: true }}
            >
              <Background variant={BackgroundVariant.Dots} gap={30} size={1} color="hsl(213 20% 16% / 0.5)" />
              <Controls
                className="!bg-card !border-border/50 !rounded-lg [&>button]:!bg-card [&>button]:!border-border/50 [&>button]:!text-muted-foreground [&>button:hover]:!bg-muted"
              />
              <MiniMap
                className="!bg-card !border-border/50 !rounded-lg"
                nodeColor={(node) => {
                  const nt = (node.data as GraphNodeData).nodeType;
                  if (nt === "attack") return "hsl(0 84% 60%)";
                  if (nt === "detection") return "hsl(43 96% 56%)";
                  if (nt === "service") return "hsl(210 79% 46%)";
                  return "hsl(142 71% 45%)";
                }}
                maskColor="hsl(215 40% 6% / 0.7)"
              />
              <Panel position="top-left">
                <div className="flex flex-wrap gap-3 bg-card/90 backdrop-blur-sm border border-border/50 rounded-lg px-3 py-2">
                  {Object.entries(nodeColors).map(([type, config]) => {
                    const Icon = config.icon;
                    return (
                      <div key={type} className="flex items-center gap-1.5 text-xs text-muted-foreground">
                        <div className={`w-3 h-3 rounded-sm ${config.bg} ${config.border} border`} />
                        <Icon className={`h-3 w-3 ${config.text}`} />
                        <span className="capitalize">{type === "logSource" ? "Log Source" : type}</span>
                      </div>
                    );
                  })}
                </div>
              </Panel>
            </ReactFlow>
          </div>
        )}
      </div>
    </Layout>
  );
};

export default AttackGraphPage;
