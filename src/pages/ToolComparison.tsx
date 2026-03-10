import { useState } from "react";
import { Layout } from "@/components/Layout";
import { Badge } from "@/components/ui/badge";
import { CheckCircle, XCircle, Minus } from "lucide-react";

type Support = "full" | "partial" | "none";

interface Tool {
  name: string;
  category: string;
  pricing: string;
  features: Record<string, Support>;
}

const featureCategories = [
  { group: "Detection & Response", features: ["CloudTrail Analysis", "Real-time Alerting", "Custom Detection Rules", "Automated Response", "Threat Intelligence"] },
  { group: "Posture Management", features: ["Misconfiguration Detection", "Compliance Frameworks", "IAM Analysis", "Network Exposure", "Drift Detection"] },
  { group: "Data & Integration", features: ["Multi-Cloud Support", "API Access", "SIEM Integration", "CI/CD Integration", "Custom Dashboards"] },
];

const allFeatures = featureCategories.flatMap((c) => c.features);

const tools: Tool[] = [
  {
    name: "AWS GuardDuty",
    category: "AWS Native",
    pricing: "Pay-per-use",
    features: {
      "CloudTrail Analysis": "full", "Real-time Alerting": "full", "Custom Detection Rules": "none",
      "Automated Response": "partial", "Threat Intelligence": "full", "Misconfiguration Detection": "none",
      "Compliance Frameworks": "none", "IAM Analysis": "partial", "Network Exposure": "full",
      "Drift Detection": "none", "Multi-Cloud Support": "none", "API Access": "full",
      "SIEM Integration": "full", "CI/CD Integration": "partial", "Custom Dashboards": "partial",
    },
  },
  {
    name: "AWS Security Hub",
    category: "AWS Native",
    pricing: "Pay-per-use",
    features: {
      "CloudTrail Analysis": "partial", "Real-time Alerting": "full", "Custom Detection Rules": "partial",
      "Automated Response": "full", "Threat Intelligence": "partial", "Misconfiguration Detection": "full",
      "Compliance Frameworks": "full", "IAM Analysis": "full", "Network Exposure": "partial",
      "Drift Detection": "partial", "Multi-Cloud Support": "none", "API Access": "full",
      "SIEM Integration": "full", "CI/CD Integration": "full", "Custom Dashboards": "full",
    },
  },
  {
    name: "Prowler",
    category: "Open Source",
    pricing: "Free / Enterprise",
    features: {
      "CloudTrail Analysis": "partial", "Real-time Alerting": "none", "Custom Detection Rules": "full",
      "Automated Response": "none", "Threat Intelligence": "none", "Misconfiguration Detection": "full",
      "Compliance Frameworks": "full", "IAM Analysis": "full", "Network Exposure": "full",
      "Drift Detection": "none", "Multi-Cloud Support": "full", "API Access": "full",
      "SIEM Integration": "partial", "CI/CD Integration": "full", "Custom Dashboards": "none",
    },
  },
  {
    name: "Wiz",
    category: "Commercial",
    pricing: "Enterprise",
    features: {
      "CloudTrail Analysis": "full", "Real-time Alerting": "full", "Custom Detection Rules": "full",
      "Automated Response": "full", "Threat Intelligence": "full", "Misconfiguration Detection": "full",
      "Compliance Frameworks": "full", "IAM Analysis": "full", "Network Exposure": "full",
      "Drift Detection": "full", "Multi-Cloud Support": "full", "API Access": "full",
      "SIEM Integration": "full", "CI/CD Integration": "full", "Custom Dashboards": "full",
    },
  },
  {
    name: "Prisma Cloud",
    category: "Commercial",
    pricing: "Enterprise",
    features: {
      "CloudTrail Analysis": "full", "Real-time Alerting": "full", "Custom Detection Rules": "full",
      "Automated Response": "full", "Threat Intelligence": "full", "Misconfiguration Detection": "full",
      "Compliance Frameworks": "full", "IAM Analysis": "full", "Network Exposure": "full",
      "Drift Detection": "full", "Multi-Cloud Support": "full", "API Access": "full",
      "SIEM Integration": "full", "CI/CD Integration": "full", "Custom Dashboards": "full",
    },
  },
  {
    name: "Steampipe",
    category: "Open Source",
    pricing: "Free / Cloud",
    features: {
      "CloudTrail Analysis": "full", "Real-time Alerting": "none", "Custom Detection Rules": "full",
      "Automated Response": "none", "Threat Intelligence": "none", "Misconfiguration Detection": "full",
      "Compliance Frameworks": "full", "IAM Analysis": "full", "Network Exposure": "full",
      "Drift Detection": "partial", "Multi-Cloud Support": "full", "API Access": "full",
      "SIEM Integration": "partial", "CI/CD Integration": "full", "Custom Dashboards": "full",
    },
  },
];

const categoryColors: Record<string, string> = {
  "AWS Native": "bg-orange-500/20 text-orange-400 border-orange-500/30",
  "Open Source": "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  "Commercial": "bg-blue-500/20 text-blue-400 border-blue-500/30",
};

function SupportIcon({ support }: { support: Support }) {
  if (support === "full") return <CheckCircle className="h-4 w-4 text-emerald-400" />;
  if (support === "partial") return <Minus className="h-4 w-4 text-yellow-400" />;
  return <XCircle className="h-4 w-4 text-red-400/50" />;
}

export default function ToolComparison() {
  const [selectedTools, setSelectedTools] = useState<string[]>(tools.map((t) => t.name));

  const toggleTool = (name: string) => {
    setSelectedTools((prev) =>
      prev.includes(name) ? prev.filter((t) => t !== name) : [...prev, name]
    );
  };

  const visibleTools = tools.filter((t) => selectedTools.includes(t.name));

  return (
    <Layout>
      <div className="container py-10">
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">Tool Comparison Matrix</h1>
          <p className="text-muted-foreground">
            Compare cloud security tools across detection, posture management, and integration capabilities.
          </p>
        </div>

        {/* Tool toggles */}
        <div className="flex flex-wrap gap-2 mb-8">
          {tools.map((tool) => (
            <button
              key={tool.name}
              onClick={() => toggleTool(tool.name)}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-all border ${
                selectedTools.includes(tool.name)
                  ? "bg-primary/10 border-primary/30 text-foreground"
                  : "bg-muted/30 border-border/30 text-muted-foreground"
              }`}
            >
              {tool.name}
            </button>
          ))}
        </div>

        {/* Legend */}
        <div className="flex gap-6 mb-6 text-sm text-muted-foreground">
          <span className="flex items-center gap-1.5"><CheckCircle className="h-3.5 w-3.5 text-emerald-400" /> Full Support</span>
          <span className="flex items-center gap-1.5"><Minus className="h-3.5 w-3.5 text-yellow-400" /> Partial</span>
          <span className="flex items-center gap-1.5"><XCircle className="h-3.5 w-3.5 text-red-400/50" /> Not Supported</span>
        </div>

        {/* Comparison table */}
        <div className="overflow-x-auto rounded-lg border border-border/50">
          <table className="w-full text-sm">
            <thead>
              <tr className="bg-muted/30">
                <th className="text-left p-3 font-semibold text-foreground min-w-[200px] sticky left-0 bg-muted/30 z-10">Feature</th>
                {visibleTools.map((tool) => (
                  <th key={tool.name} className="p-3 text-center min-w-[130px]">
                    <div className="font-semibold text-foreground">{tool.name}</div>
                    <Badge variant="outline" className={`text-[10px] mt-1 ${categoryColors[tool.category]}`}>
                      {tool.category}
                    </Badge>
                    <div className="text-[10px] text-muted-foreground mt-0.5">{tool.pricing}</div>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {featureCategories.map((cat) => (
                <>
                  <tr key={cat.group}>
                    <td
                      colSpan={visibleTools.length + 1}
                      className="px-3 py-2 text-xs font-bold uppercase tracking-wider text-primary bg-primary/5"
                    >
                      {cat.group}
                    </td>
                  </tr>
                  {cat.features.map((feature) => (
                    <tr key={feature} className="border-t border-border/30 hover:bg-muted/20 transition-colors">
                      <td className="p-3 text-foreground sticky left-0 bg-background z-10">{feature}</td>
                      {visibleTools.map((tool) => (
                        <td key={tool.name} className="p-3 text-center">
                          <div className="flex justify-center">
                            <SupportIcon support={tool.features[feature]} />
                          </div>
                        </td>
                      ))}
                    </tr>
                  ))}
                </>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </Layout>
  );
}
