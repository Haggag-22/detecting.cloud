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
import { techniques, getTechniqueById } from "@/data/techniques";
import { detections } from "@/data/detections";
import { Badge } from "@/components/ui/badge";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Shield, Crosshair, Eye, Cloud, FileText, Search, Route } from "lucide-react";
import { Input } from "@/components/ui/input";

type GraphNodeType = "attack" | "technique" | "detection" | "service" | "logSource";

interface GraphNodeData {
  label: string;
  nodeType: GraphNodeType;
  category?: string;
  severity?: string;
  link?: string;
  tags?: string[];
  [key: string]: unknown;
}

// Build a graph around an attack path (chain)
function buildAttackPathGraph(slug: string) {
  const ap = attackPaths.find((a) => a.slug === slug);
  if (!ap) return { nodes: [], edges: [] };

  const nodes: Node<GraphNodeData>[] = [];
  const edges: Edge[] = [];
  const addedServices = new Set<string>();
  const addedDetections = new Set<string>();

  // Center: the attack path
  nodes.push({
    id: `path-${ap.slug}`,
    type: "graphNode",
    position: { x: 500, y: 50 },
    data: {
      label: ap.title,
      nodeType: "attack",
      severity: ap.severity,
      link: `/attack-paths?technique=${ap.slug}`,
    },
  });

  // Steps: technique nodes in a vertical chain
  ap.steps.forEach((step, i) => {
    const tech = getTechniqueById(step.techniqueId);
    if (!tech) return;

    const nodeId = `tech-${tech.id}`;
    nodes.push({
      id: nodeId,
      type: "graphNode",
      position: { x: 500, y: 180 + i * 140 },
      data: {
        label: tech.name,
        nodeType: "technique",
        category: tech.category,
        link: `/attack-paths?technique=${tech.id}`,
      },
    });

    // Connect path → first step, or step → next step
    const sourceId = i === 0 ? `path-${ap.slug}` : `tech-${ap.steps[i - 1].techniqueId}`;
    edges.push({
      id: `e-chain-${i}`,
      source: sourceId,
      target: nodeId,
      style: { stroke: "hsl(43 96% 56% / 0.6)", strokeWidth: 2 },
      animated: true,
      label: i === 0 ? "step 1" : `step ${i + 1}`,
      labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
      labelBgStyle: { fill: "hsl(215 40% 6%)", fillOpacity: 0.9 },
    });

    // Services branching left
    tech.services.forEach((svc) => {
      const svcId = `service-${svc}`;
      if (!addedServices.has(svc)) {
        addedServices.add(svc);
        nodes.push({
          id: svcId,
          type: "graphNode",
          position: { x: 100, y: 180 + i * 140 },
          data: { label: svc, nodeType: "service" },
        });
      }
      edges.push({
        id: `e-svc-${tech.id}-${svc}`,
        source: svcId,
        target: nodeId,
        style: { stroke: "hsl(210 79% 46% / 0.4)", strokeWidth: 1.5 },
      });
    });

    // Detections branching right
    tech.detectionIds.forEach((detId) => {
      const det = detections.find((d) => d.id === detId);
      if (!det) return;
      const detNodeId = `detection-${det.id}`;
      if (!addedDetections.has(det.id)) {
        addedDetections.add(det.id);
        nodes.push({
          id: detNodeId,
          type: "graphNode",
          position: { x: 900, y: 180 + i * 140 },
          data: {
            label: det.title,
            nodeType: "detection",
            link: `/detection-engineering?rule=${det.id}`,
          },
        });
      }
      edges.push({
        id: `e-det-${tech.id}-${det.id}`,
        source: nodeId,
        target: detNodeId,
        style: { stroke: "hsl(0 84% 60% / 0.4)", strokeWidth: 1.5, strokeDasharray: "5 3" },
        label: "detected by",
        labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
        labelBgStyle: { fill: "hsl(215 40% 6%)", fillOpacity: 0.9 },
      });
    });
  });

  return { nodes, edges };
}

// Build a graph around a single technique
function buildTechniqueGraph(techId: string) {
  const tech = getTechniqueById(techId);
  if (!tech) return { nodes: [], edges: [] };

  const nodes: Node<GraphNodeData>[] = [];
  const edges: Edge[] = [];

  // Center: the technique
  nodes.push({
    id: `tech-${tech.id}`,
    type: "graphNode",
    position: { x: 500, y: 300 },
    data: {
      label: tech.name,
      nodeType: "technique",
      category: tech.category,
      link: `/attack-paths?technique=${tech.id}`,
    },
  });

  // Left: services
  tech.services.forEach((svc, i) => {
    nodes.push({
      id: `service-${svc}`,
      type: "graphNode",
      position: { x: 100, y: 200 + i * 120 },
      data: { label: svc, nodeType: "service" },
    });
    edges.push({
      id: `e-svc-${svc}`,
      source: `service-${svc}`,
      target: `tech-${tech.id}`,
      style: { stroke: "hsl(210 79% 46% / 0.5)", strokeWidth: 1.5 },
    });
  });

  // Right: detection rules
  const relatedDets = detections.filter((d) => tech.detectionIds.includes(d.id));
  relatedDets.forEach((det, i) => {
    nodes.push({
      id: `detection-${det.id}`,
      type: "graphNode",
      position: { x: 900, y: 150 + i * 150 },
      data: {
        label: det.title,
        nodeType: "detection",
        link: `/detection-engineering?rule=${det.id}`,
      },
    });
    edges.push({
      id: `e-det-${det.id}`,
      source: `tech-${tech.id}`,
      target: `detection-${det.id}`,
      animated: true,
      style: { stroke: "hsl(43 96% 56% / 0.5)", strokeWidth: 2 },
      label: "detected by",
      labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
      labelBgStyle: { fill: "hsl(215 40% 6%)", fillOpacity: 0.9 },
    });
  });

  // Top/Bottom: attack paths that use this technique
  const relatedPaths = attackPaths.filter((ap) => ap.steps.some((s) => s.techniqueId === tech.id));
  relatedPaths.forEach((ap, i) => {
    nodes.push({
      id: `path-${ap.slug}`,
      type: "graphNode",
      position: { x: 300 + i * 200, y: 50 },
      data: {
        label: ap.title,
        nodeType: "attack",
        severity: ap.severity,
        link: `/attack-paths?technique=${ap.slug}`,
      },
    });
    edges.push({
      id: `e-path-${ap.slug}`,
      source: `path-${ap.slug}`,
      target: `tech-${tech.id}`,
      style: { stroke: "hsl(0 84% 60% / 0.4)", strokeWidth: 1.5 },
      label: "uses",
      labelStyle: { fontSize: 9, fill: "hsl(215 20% 55%)" },
      labelBgStyle: { fill: "hsl(215 40% 6%)", fillOpacity: 0.9 },
    });
  });

  return { nodes, edges };
}

// Build a graph around a detection rule
function buildDetectionGraph(detId: string) {
  const det = detections.find((d) => d.id === detId);
  if (!det) return { nodes: [], edges: [] };

  const nodes: Node<GraphNodeData>[] = [];
  const edges: Edge[] = [];

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

  // Left: techniques that this rule detects
  const relatedTechs = techniques.filter((t) => t.detectionIds.includes(det.id));
  relatedTechs.forEach((tech, i) => {
    nodes.push({
      id: `tech-${tech.id}`,
      type: "graphNode",
      position: { x: 100, y: 150 + i * 140 },
      data: {
        label: tech.name,
        nodeType: "technique",
        link: `/attack-paths?technique=${tech.id}`,
      },
    });
    edges.push({
      id: `e-tech-${tech.id}`,
      source: `tech-${tech.id}`,
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
      id: `e-log-${ls.replace(/\s/g, "_")}`,
      source: `detection-${det.id}`,
      target: logId,
      style: { stroke: "hsl(142 71% 45% / 0.4)", strokeWidth: 1.5 },
    });
  });

  // Top: AWS services
  nodes.push({
    id: `service-${det.awsService}`,
    type: "graphNode",
    position: { x: 500, y: 80 },
    data: { label: det.awsService, nodeType: "service" },
  });
  edges.push({
    id: `e-svc-primary`,
    source: `service-${det.awsService}`,
    target: `detection-${det.id}`,
    style: { stroke: "hsl(210 79% 46% / 0.5)", strokeWidth: 1.5 },
  });

  return { nodes, edges };
}

const nodeColors: Record<GraphNodeType, { bg: string; border: string; text: string; icon: typeof Shield }> = {
  attack: { bg: "bg-destructive/10", border: "border-destructive/40", text: "text-destructive", icon: Crosshair },
  technique: { bg: "bg-amber-500/10", border: "border-amber-500/40", text: "text-amber-400", icon: Route },
  detection: { bg: "bg-purple-500/10", border: "border-purple-500/40", text: "text-purple-400", icon: Eye },
  service: { bg: "bg-sky-500/15", border: "border-sky-500/40", text: "text-sky-400", icon: Cloud },
  logSource: { bg: "bg-emerald-500/10", border: "border-emerald-500/40", text: "text-emerald-400", icon: FileText },
};

function GraphNodeComponent({ data }: NodeProps<Node<GraphNodeData>>) {
  const navigate = useNavigate();
  const config = nodeColors[data.nodeType];
  const Icon = config.icon;

  return (
    <div
      className={`px-3 py-2 rounded-lg border ${config.bg} ${config.border} cursor-pointer hover:scale-105 transition-transform min-w-[120px] max-w-[220px]`}
      onClick={() => data.link && navigate(data.link)}
      style={{
        fontFamily: "Inter, system-ui, -apple-system, sans-serif",
        WebkitFontSmoothing: "antialiased",
        MozOsxFontSmoothing: "grayscale",
      }}
    >
      <Handle type="target" position={Position.Left} className="!bg-muted-foreground !w-2 !h-2" />
      <Handle type="source" position={Position.Right} className="!bg-muted-foreground !w-2 !h-2" />
      <div className="flex items-center gap-2">
        <Icon className={`h-3.5 w-3.5 shrink-0 ${config.text}`} />
        <span
          className="text-xs font-medium truncate"
          style={{
            color: "hsl(var(--foreground))",
            fontFamily: "inherit",
          }}
        >
          {data.label}
        </span>
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
  ...attackPaths.map((ap) => ({ id: ap.slug, label: ap.title, type: "path" as const })),
  ...techniques.map((t) => ({ id: t.id, label: t.name, type: "technique" as const })),
  ...detections.map((d) => ({ id: d.id, label: d.title, type: "detection" as const })),
];

const AttackGraphPage = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const selectedTechnique = searchParams.get("technique");
  const selectedDetection = searchParams.get("rule");

  const [search, setSearch] = useState("");

  const hasSelection = !!selectedTechnique || !!selectedDetection;

  const { nodes: initialNodes, edges: initialEdges } = useMemo(() => {
    if (selectedTechnique) {
      // Check if it's a technique ID or attack path slug
      if (selectedTechnique.startsWith("tech-")) {
        return buildTechniqueGraph(selectedTechnique);
      }
      return buildAttackPathGraph(selectedTechnique);
    }
    if (selectedDetection) return buildDetectionGraph(selectedDetection);
    return { nodes: [], edges: [] };
  }, [selectedTechnique, selectedDetection]);

  const [nodes, setNodes, onNodesChange] = useNodesState(initialNodes);
  const [edges, setEdges, onEdgesChange] = useEdgesState(initialEdges);

  useMemo(() => {
    setNodes(initialNodes);
    setEdges(initialEdges);
  }, [initialNodes, initialEdges, setNodes, setEdges]);

  const handleSelect = useCallback((item: typeof allItems[0]) => {
    setSearch("");
    if (item.type === "detection") {
      setSearchParams({ rule: item.id });
    } else {
      setSearchParams({ technique: item.id });
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
            Explore the knowledge graph of attack techniques, chains, detection rules, and AWS services.
          </p>
        </div>

        {/* Search bar */}
        <div className="relative mb-6 max-w-lg">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder="Search a technique, attack path, or detection rule..."
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
                  {item.type === "path" ? (
                    <Crosshair className="h-3.5 w-3.5 text-destructive shrink-0" />
                  ) : item.type === "technique" ? (
                    <Route className="h-3.5 w-3.5 text-primary shrink-0" />
                  ) : (
                    <Eye className="h-3.5 w-3.5 text-accent shrink-0" />
                  )}
                  <span className="truncate text-foreground">{item.label}</span>
                  <span className="text-xs text-muted-foreground ml-auto shrink-0 capitalize">{item.type}</span>
                </button>
              ))}
            </div>
          )}
        </div>

        {/* Quick picks */}
        {!hasSelection && (
          <div className="space-y-6">
            <div>
              <h2 className="text-sm font-medium text-muted-foreground uppercase tracking-wider mb-3">Attack Chains</h2>
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
                    <p className="text-xs text-muted-foreground line-clamp-2">{ap.description}</p>
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

            <div>
              <h2 className="text-sm font-medium text-muted-foreground uppercase tracking-wider mb-3">Techniques</h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                {techniques.slice(0, 6).map((tech) => (
                  <button
                    key={tech.id}
                    onClick={() => setSearchParams({ technique: tech.id })}
                    className="text-left p-4 rounded-lg border border-border/50 bg-card hover:border-primary/30 hover:bg-primary/5 transition-colors group"
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Route className="h-3.5 w-3.5 text-primary" />
                      <span className="text-sm font-medium text-foreground group-hover:text-primary transition-colors">{tech.name}</span>
                    </div>
                    <p className="text-xs text-muted-foreground line-clamp-2">{tech.description}</p>
                  </button>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* Graph */}
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
                style={{ background: "hsl(215, 38%, 8%)" }}
                nodeColor={(node) => {
                  const nt = (node.data as GraphNodeData).nodeType;
                  if (nt === "attack") return "hsl(0 84% 60%)";
                  if (nt === "technique") return "hsl(43 96% 56%)";
                  if (nt === "detection") return "hsl(270 70% 65%)";
                  if (nt === "service") return "hsl(199 89% 48%)";
                  return "hsl(160 84% 39%)";
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
                        <span className="capitalize">{type === "logSource" ? "Log Source" : type === "attack" ? "Attack Path" : type}</span>
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
