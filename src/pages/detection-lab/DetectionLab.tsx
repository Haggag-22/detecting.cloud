import { useLocation, useNavigate } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { FlaskConical, Database, FileText, BarChart3 } from "lucide-react";
import { DatasetTesting } from "./sections/DatasetTesting";
import { UserLogTesting } from "./sections/UserLogTesting";
import { DetectionCoverageMapping } from "./sections/DetectionCoverageMapping";
import { ResultDashboard } from "./ResultDashboard";
import { DetectionLabProvider } from "./DetectionLabContext";

const sections = [
  { id: "dataset", path: "dataset", label: "Rule Testing", icon: Database },
  { id: "user-log", path: "user-log", label: "User Log Testing", icon: FileText },
  { id: "coverage", path: "coverage", label: "Detection Coverage Mapping", icon: BarChart3 },
];

export default function DetectionLab() {
  const location = useLocation();
  const navigate = useNavigate();

  const pathPart = location.pathname.replace("/detection-lab", "").replace(/^\//, "") || "dataset";
  const activeSection = sections.find((s) => s.path === pathPart)?.id ?? "dataset";

  const handleTabChange = (value: string) => {
    const section = sections.find((s) => s.id === value);
    if (section) {
      navigate(`/detection-lab/${section.path}`);
    }
  };

  return (
    <Layout>
      <DetectionLabProvider>
      <div className="container py-10">
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-2">
            <FlaskConical className="h-8 w-8 text-primary" />
            <h1 className="text-3xl font-bold">Detection Lab</h1>
          </div>
          <p className="text-muted-foreground max-w-2xl">
            Test, validate, and measure the effectiveness of your detection rules. Upload logs and run detection rules against your telemetry.
          </p>
        </div>

        <Tabs value={activeSection} onValueChange={handleTabChange} className="space-y-6">
          <TabsList className="grid w-full grid-cols-2 lg:grid-cols-3 h-auto flex-wrap gap-2">
            {sections.map((s) => (
              <TabsTrigger key={s.id} value={s.id} className="flex items-center gap-2">
                <s.icon className="h-4 w-4" />
                <span className="hidden sm:inline">{s.label}</span>
              </TabsTrigger>
            ))}
          </TabsList>

          <TabsContent value="dataset" className="mt-0">
            <DatasetTesting />
          </TabsContent>
          <TabsContent value="user-log" className="mt-0">
            <UserLogTesting />
          </TabsContent>
          <TabsContent value="coverage" className="mt-0">
            <DetectionCoverageMapping />
          </TabsContent>
        </Tabs>

        <ResultDashboard />
      </div>
      </DetectionLabProvider>
    </Layout>
  );
}
