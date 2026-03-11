import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { BrowserRouter, Route, Routes } from "react-router-dom";
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
import CommunityRules from "./pages/CommunityRules";
import AdminSubscribers from "./pages/AdminSubscribers";
import NotFound from "./pages/NotFound";
import { AiAssistant } from "./components/AiAssistant";

const queryClient = new QueryClient();

const App = () => (
  <QueryClientProvider client={queryClient}>
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
          <Route path="/community-rules" element={<CommunityRules />} />
          <Route path="/admin/subscribers" element={<AdminSubscribers />} />
          <Route path="/about" element={<About />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
        <AiAssistant />
      </BrowserRouter>
    </TooltipProvider>
  </QueryClientProvider>
);

export default App;
