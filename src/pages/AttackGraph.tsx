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
import { attackPaths, attackPathCategories } from "@/data/attackPaths";
import { detections } from "@/data/detections";
import { Badge } from "@/components/ui/badge";
import { useNavigate } from "react-router-dom";
import { Shield, Crosshair, Eye, Cloud, FileText, Filter, X } from "lucide-react";
import { Button } from "@/components/ui/button";

// --- Node types ---
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

// Extract unique AWS services and log sources from data
function extractServices(): string[] {
  const services = new Set<string>();
  attackPaths.forEach((ap) => {
    ap.tags.forEach((t) => {
      if (["IAM", "Lambda", "S3", "EC2", "CloudTrail", "STS", "Glue", "VPC"].includes(t)) {
        services.add(t);
      }
    });
  });
  return Array.from(services);
}

function extractLogSources(): string[] {
  const sources = new Set<string>();
  detections.forEach((d) => {
    d.logSources.forEach((ls) => sources.add(ls));
  });
  return Array.from(sources);
}

// Build graph data
function buildGraph(filter: string) {
  const services = extractServices();
  const logSources = extractLogSources();

  const nodes: Node<GraphNodeData>[] = [];
  const edges: Edge[] = [];

  // Filter attack paths
  let filteredAttacks = attackPaths;
  if (filter && filter !== "all") {
    if (filter in attackPathCategories) {
      filteredAttacks = attackPaths.filter((ap) => ap.category === filter);
    } else if (["AWS", "Azure", "GCP"].includes(filter)) {
      filteredAttacks = attackPaths.filter((ap) => ap.provider === filter);
    }
  }

  const relatedDetectionIds = new Set<string>();
  const relatedServices = new Set<string>();
  const relatedLogSources = new Set<string>();

  // Attack nodes - arrange in a circle on the left
  const attackCount = filteredAttacks.length;
  filteredAttacks.forEach((ap, i) => {
    const angle = (i / Math.max(attackCount, 1)) * Math.PI * 1.4 - Math.PI * 0.7;
    const radius = 350;
    nodes.push({
      id: `attack-${ap.slug}`,
      type: "graphNode",
      position: { x: 400 + Math.cos(angle) * radius, y: 400 + Math.sin(angle) * radius },
      data: {
        label: ap.title,
        nodeType: "attack",
        category: ap.category,
        severity: ap.severity,
        link: `/attack-paths?technique=${ap.slug}`,
        tags: ap.tags,
      },
    });

    // Connect to services
    ap.tags.forEach((t) => {
      if (services.includes(t)) {
        relatedServices.add(t);
        edges.push({
          id: `e-attack-${ap.slug}-svc-${t}`,
          source: `attack-${ap.slug}`,
          target: `service-${t}`,
          animated: false,
          style: { stroke: "hsl(210 79% 46% / 0.4)", strokeWidth: 1.5 },
          label: "uses",
          labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
          labelBgStyle: { fill: "hsl(213 35% 7%)", fillOpacity: 0.8 },
        });
      }
    });

    // Connect to detections
    ap.relatedDetectionIds.forEach((detId) => {
      relatedDetectionIds.add(detId);
      edges.push({
        id: `e-attack-${ap.slug}-det-${detId}`,
        source: `attack-${ap.slug}`,
        target: `detection-${detId}`,
        animated: true,
        style: { stroke: "hsl(43 96% 56% / 0.5)", strokeWidth: 2 },
        label: "detected by",
        labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
        labelBgStyle: { fill: "hsl(213 35% 7%)", fillOpacity: 0.8 },
      });
    });
  });

  // Service nodes - center column
  const filteredServices = filter === "all" || !filter ? services : Array.from(relatedServices);
  filteredServices.forEach((svc, i) => {
    nodes.push({
      id: `service-${svc}`,
      type: "graphNode",
      position: { x: 850, y: 80 + i * 120 },
      data: { label: svc, nodeType: "service" },
    });
  });

  // Detection nodes - right side
  const filteredDetections = filter === "all" || !filter
    ? detections
    : detections.filter((d) => relatedDetectionIds.has(d.id));
  filteredDetections.forEach((det, i) => {
    const angle = (i / Math.max(filteredDetections.length, 1)) * Math.PI * 1.4 - Math.PI * 0.7;
    const radius = 300;
    nodes.push({
      id: `detection-${det.id}`,
      type: "graphNode",
      position: { x: 1300 + Math.cos(angle) * radius, y: 400 + Math.sin(angle) * radius },
      data: {
        label: det.title,
        nodeType: "detection",
        link: `/detection-engineering?rule=${det.id}`,
        tags: det.tags,
      },
    });

    // Connect detections to log sources
    det.logSources.forEach((ls) => {
      relatedLogSources.add(ls);
      edges.push({
        id: `e-det-${det.id}-log-${ls.replace(/\s/g, "_")}`,
        source: `detection-${det.id}`,
        target: `log-${ls.replace(/\s/g, "_")}`,
        style: { stroke: "hsl(142 71% 45% / 0.4)", strokeWidth: 1.5 },
        label: "analyzes",
        labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
        labelBgStyle: { fill: "hsl(213 35% 7%)", fillOpacity: 0.8 },
      });
    });
  });

  // Log source nodes - far right
  const filteredLogSources = filter === "all" || !filter ? logSources : Array.from(relatedLogSources);
  filteredLogSources.forEach((ls, i) => {
    nodes.push({
      id: `log-${ls.replace(/\s/g, "_")}`,
      type: "graphNode",
      position: { x: 1750, y: 120 + i * 130 },
      data: { label: ls, nodeType: "logSource" },
    });
  });

  return { nodes, edges };
}

// Custom node colors
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
      className={`px-3 py-2 rounded-lg border ${config.bg} ${config.border} cursor-pointer hover:scale-105 transition-transform min-w-[120px] max-w-[200px]`}
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

const filterOptions = [
  { value: "all", label: "All" },
  { value: "iam-abuse", label: "IAM Abuse" },
  { value: "privilege-escalation", label: "Privilege Escalation" },
  { value: "persistence", label: "Persistence" },
  { value: "lateral-movement", label: "Lateral Movement" },
  { value: "data-exfiltration", label: "Data Exfiltration" },
];

const AttackGraphPage = () => {
  const [filter, setFilter] = useState("all");

  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => buildGraph(filter), [filter]);
  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  // Reset nodes/edges when filter changes
  const handleFilterChange = useCallback((value: string) => {
    setFilter(value);
    const { nodes: n, edges: e } = buildGraph(value);
    setNodes(n);
    setEdges(e);
  }, [setNodes, setEdges]);

  return (
    <Layout>
      <div className="container py-8">
        <div className="mb-6">
          <h1 className="font-display text-3xl font-bold mb-2">Attack & Detection Graph</h1>
          <p className="text-muted-foreground text-sm">
            Interactive map of cloud attack techniques, AWS services, detection rules, and log sources.
            Click any node to navigate to its detail page.
          </p>
        </div>

        {/* Legend */}
        <div className="flex flex-wrap gap-4 mb-4">
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
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground ml-4">
            <div className="w-6 h-0.5 bg-primary/50" />
            <span>detected by</span>
          </div>
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <div className="w-6 h-0.5 bg-accent/50" />
            <span>uses service</span>
          </div>
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
            <div className="w-6 h-0.5 bg-green-500/50" />
            <span>analyzes logs</span>
          </div>
        </div>

        {/* Graph */}
        <div className="rounded-lg border border-border/50 bg-card overflow-hidden" style={{ height: "70vh" }}>
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            nodeTypes={nodeTypes}
            fitView
            minZoom={0.2}
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
              maskColor="hsl(213 35% 7% / 0.7)"
            />

            <Panel position="top-left" className="flex flex-wrap gap-1.5">
              <div className="flex items-center gap-1.5 bg-card/90 backdrop-blur-sm border border-border/50 rounded-lg px-2 py-1.5">
                <Filter className="h-3.5 w-3.5 text-muted-foreground" />
                {filterOptions.map((opt) => (
                  <Button
                    key={opt.value}
                    variant={filter === opt.value ? "default" : "ghost"}
                    size="sm"
                    className="h-6 text-xs px-2"
                    onClick={() => handleFilterChange(opt.value)}
                  >
                    {opt.label}
                  </Button>
                ))}
              </div>
            </Panel>
          </ReactFlow>
        </div>
      </div>
    </Layout>
  );
};

export default AttackGraphPage;
