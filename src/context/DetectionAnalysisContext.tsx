/**
 * Detection Analysis context - stores pipeline results for the Detection Analysis section.
 */

import { createContext, useContext, useState, useCallback, type ReactNode } from "react";
import type { PipelineResult } from "@/lib/detection-lab/detectionPipeline";

interface DetectionAnalysisState {
  result: PipelineResult | null;
  setResult: (result: PipelineResult | null) => void;
  clearResult: () => void;
}

const DetectionAnalysisContext = createContext<DetectionAnalysisState | null>(null);

export function DetectionAnalysisProvider({ children }: { children: ReactNode }) {
  const [result, setResultState] = useState<PipelineResult | null>(null);

  const setResult = useCallback((r: PipelineResult | null) => setResultState(r), []);
  const clearResult = useCallback(() => setResultState(null), []);

  return (
    <DetectionAnalysisContext.Provider value={{ result, setResult, clearResult }}>
      {children}
    </DetectionAnalysisContext.Provider>
  );
}

export function useDetectionAnalysis() {
  return useContext(DetectionAnalysisContext);
}
