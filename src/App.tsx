import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { Toaster as Sonner } from "@/components/ui/sonner";
import { Toaster } from "@/components/ui/toaster";
import { TooltipProvider } from "@/components/ui/tooltip";
import Index from "./pages/Index";
import Research from "./pages/Research";
import Article from "./pages/Article";
import AttackPaths from "./pages/AttackPaths";
import DetectionEngineering from "./pages/DetectionEngineering";
import About from "./pages/About";
import AttackGraph from "./pages/AttackGraph";
import Coverage from "./pages/Coverage";
import TechniqueDetail from "./pages/TechniqueDetail";
import TechniquesLibrary from "./pages/TechniquesLibrary";
import AttackSimulator from "./pages/AttackSimulator";
import DetectionLab from "./pages/detection-lab/DetectionLab";
import DetectionAnalysis from "./pages/detection-analysis/DetectionAnalysis";
import CommunityRules from "./pages/CommunityRules";
import AdminSubscribers from "./pages/AdminSubscribers";
import NotFound from "./pages/NotFound";
import { AiAssistant } from "./components/AiAssistant";
import { DetectionAnalysisProvider } from "./context/DetectionAnalysisContext";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
    <DetectionAnalysisProvider>
    <TooltipProvider>
      <Toaster />
      <Sonner />
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<Index />} />
          <Route path="/research" element={<Research />} />
          <Route path="/research/:slug" element={<Article />} />
          <Route path="/attack-paths/technique/:id" element={<TechniqueDetail />} />
          <Route path="/attack-paths" element={<AttackPaths />} />
          <Route path="/techniques" element={<TechniquesLibrary />} />
          <Route path="/detection-engineering" element={<DetectionEngineering />} />
          <Route path="/attack-graph" element={<AttackGraph />} />
          <Route path="/coverage" element={<Coverage />} />
          <Route path="/simulator" element={<AttackSimulator />} />
          <Route path="/detection-lab" element={<Navigate to="/detection-lab/dataset" replace />} />
          <Route path="/detection-lab/dataset" element={<DetectionLab />} />
          <Route path="/detection-lab/user-log" element={<DetectionLab />} />
          <Route path="/detection-lab/coverage" element={<DetectionLab />} />
          <Route path="/detection-analysis" element={<Navigate to="/detection-analysis/results" replace />} />
          <Route path="/detection-analysis/results" element={<DetectionAnalysis page="results" />} />
          <Route path="/detection-analysis/false-positives" element={<DetectionAnalysis page="false-positives" />} />
          <Route path="/detection-analysis/confidence" element={<DetectionAnalysis page="confidence" />} />
          <Route path="/detection-analysis/explanation" element={<DetectionAnalysis page="explanation" />} />
          <Route path="/community-rules" element={<CommunityRules />} />
          <Route path="/admin/subscribers" element={<AdminSubscribers />} />
          <Route path="/about" element={<About />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
        <AiAssistant />
      </BrowserRouter>
    </TooltipProvider>
    </DetectionAnalysisProvider>
  </QueryClientProvider>
);

export default App;
