import { useLocation, useNavigate } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useDetectionAnalysis } from "@/context/DetectionAnalysisContext";
import { DetectionResults } from "./DetectionResults";
import { FalsePositiveAnalysis } from "./FalsePositiveAnalysis";
import { ConfidenceScores } from "./ConfidenceScores";
import { DetectionExplanation } from "./DetectionExplanation";
import { BarChart3, AlertTriangle, Gauge, Lightbulb } from "lucide-react";

type AnalysisPage = "results" | "false-positives" | "confidence" | "explanation";

const sections: { id: AnalysisPage; path: string; label: string; icon: typeof BarChart3 }[] = [
  { id: "results", path: "results", label: "Detection Results", icon: BarChart3 },
  { id: "false-positives", path: "false-positives", label: "False Positive Analysis", icon: AlertTriangle },
  { id: "confidence", path: "confidence", label: "Confidence Scores", icon: Gauge },
  { id: "explanation", path: "explanation", label: "Detection Explanation", icon: Lightbulb },
];

interface Props {
  page: AnalysisPage;
}

export default function DetectionAnalysisPage({ page }: Props) {
  const location = useLocation();
  const navigate = useNavigate();
  const { result } = useDetectionAnalysis();

  const pathPart = location.pathname.replace("/detection-analysis", "").replace(/^\//, "") || "results";
  const activeSection = sections.find((s) => s.path === pathPart)?.id ?? "results";

  const handleTabChange = (value: string) => {
    const section = sections.find((s) => s.id === value);
    if (section) navigate(`/detection-analysis/${section.path}`);
  };

  return (
    <Layout>
      <div className="container py-10">
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">Detection Analysis</h1>
          <p className="text-muted-foreground max-w-2xl">
            Analyze detection results from log analysis. View valid detections, false positives, confidence scores, and rule explanations.
          </p>
        </div>

        {!result ? (
          <div className="rounded-lg border border-dashed p-12 text-center text-muted-foreground">
            <p className="font-medium mb-2">No analysis results yet</p>
            <p className="text-sm">
              Run a log analysis in Detection Lab (Rule Testing or User Log Testing) to see results here.
            </p>
          </div>
        ) : (
          <Tabs value={activeSection} onValueChange={handleTabChange} className="space-y-6">
            <TabsList className="grid w-full grid-cols-2 lg:grid-cols-4 h-auto flex-wrap gap-2">
              {sections.map((s) => (
                <TabsTrigger key={s.id} value={s.id} className="flex items-center gap-2">
                  <s.icon className="h-4 w-4" />
                  <span className="hidden sm:inline">{s.label}</span>
                </TabsTrigger>
              ))}
            </TabsList>

            <TabsContent value="results" className="mt-0">
              <DetectionResults />
            </TabsContent>
            <TabsContent value="false-positives" className="mt-0">
              <FalsePositiveAnalysis />
            </TabsContent>
            <TabsContent value="confidence" className="mt-0">
              <ConfidenceScores />
            </TabsContent>
            <TabsContent value="explanation" className="mt-0">
              <DetectionExplanation />
            </TabsContent>
          </Tabs>
        )}
      </div>
    </Layout>
  );
}
