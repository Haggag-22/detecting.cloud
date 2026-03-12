import { createContext, useContext, useState, useCallback, type ReactNode } from "react";

export interface LabTestResult {
  id: string;
  type: "dataset" | "user-log" | "coverage";
  timestamp: Date;
  datasetsTested?: number;
  rulesEvaluated?: number;
  detectionsTriggered?: number;
  detectionFailures?: number;
  coverageScore?: number;
  details?: Record<string, unknown>;
}

interface DetectionLabState {
  results: LabTestResult[];
  addResult: (result: Omit<LabTestResult, "id" | "timestamp">) => void;
  clearResults: () => void;
}

const DetectionLabContext = createContext<DetectionLabState | null>(null);

export function DetectionLabProvider({ children }: { children: ReactNode }) {
  const [results, setResults] = useState<LabTestResult[]>([]);

  const addResult = useCallback((result: Omit<LabTestResult, "id" | "timestamp">) => {
    setResults((prev) => [
      ...prev,
      {
        ...result,
        id: `result-${Date.now()}-${Math.random().toString(36).slice(2)}`,
        timestamp: new Date(),
      },
    ]);
  }, []);

  const clearResults = useCallback(() => setResults([]), []);

  return (
    <DetectionLabContext.Provider value={{ results, addResult, clearResults }}>
      {children}
    </DetectionLabContext.Provider>
  );
}

export function useDetectionLab(): DetectionLabState | null {
  return useContext(DetectionLabContext);
}
