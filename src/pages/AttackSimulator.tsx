import { useState, useEffect } from "react";
import { useSearchParams } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { attackPaths, attackObjectiveLabels } from "@/data/attackPaths";
import { techniques } from "@/data/techniques";
import { detections } from "@/data/detections";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Play, ChevronRight, ChevronLeft, RotateCcw, ShieldCheck, ShieldOff, AlertTriangle, CheckCircle } from "lucide-react";
import { Link } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";

const severityColor: Record<string, string> = {
  Critical: "bg-red-500/20 text-red-400 border-red-500/30",
  High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  Medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
};

export default function AttackSimulator() {
  const [searchParams, setSearchParams] = useSearchParams();
  const pathParam = searchParams.get("path");
  const initialSlug = pathParam && attackPaths.some((p) => p.slug === pathParam) ? pathParam : attackPaths[0].slug;
  const [selectedPath, setSelectedPath] = useState(initialSlug);
  const [currentStep, setCurrentStep] = useState(-1); // -1 = not started
  const [simulationComplete, setSimulationComplete] = useState(false);

  // Sync selected path when path query param changes (e.g. from Attack Paths page link)
  useEffect(() => {
    if (pathParam && attackPaths.some((p) => p.slug === pathParam)) {
      setSelectedPath(pathParam);
      setCurrentStep(-1);
      setSimulationComplete(false);
    }
  }, [pathParam]);

  const path = attackPaths.find((p) => p.slug === selectedPath)!;
  const totalSteps = path.steps.length;

  const handleStart = () => {
    setCurrentStep(0);
    setSimulationComplete(false);
  };

  const handleNext = () => {
    if (currentStep < totalSteps - 1) {
      setCurrentStep((s) => s + 1);
    } else {
      setSimulationComplete(true);
    }
  };

  const handlePrev = () => {
    if (currentStep > 0) setCurrentStep((s) => s - 1);
  };

  const handleReset = () => {
    setCurrentStep(-1);
    setSimulationComplete(false);
  };

  const handlePathChange = (slug: string) => {
    setSelectedPath(slug);
    setCurrentStep(-1);
    setSimulationComplete(false);
    setSearchParams({ path: slug });
  };

  // Build step details
  const stepsWithDetails = path.steps.map((step) => {
    const tech = techniques.find((t) => t.id === step.techniqueId);
    const stepDetections = tech
      ? detections.filter((d) => tech.detectionIds.includes(d.id))
      : [];
    return { ...step, technique: tech, detections: stepDetections };
  });

  const detectedCount = stepsWithDetails.filter((s) => s.detections.length > 0).length;
  const coveragePercent = Math.round((detectedCount / totalSteps) * 100);

  // Coverage breakdown: Full (>1 rule), Partial (1 rule), None (0 rules)
  const fullCoverageCount = stepsWithDetails.filter((s) => s.detections.length > 1).length;
  const partialCoverageCount = stepsWithDetails.filter((s) => s.detections.length === 1).length;
  const noCoverageCount = stepsWithDetails.filter((s) => s.detections.length === 0).length;
  const coverageScore = totalSteps > 0 ? Math.round(((fullCoverageCount + partialCoverageCount) / totalSteps) * 100) : 0;

  return (
    <Layout>
      <div className="container py-10">
        <div className="mb-8">
          <h1 className="text-3xl font-bold mb-2">Attack Path Simulator</h1>
          <p className="text-muted-foreground">
            Walk through real-world AWS attack chains step-by-step. See which techniques are detected and where your gaps are.
          </p>
        </div>

        {/* Path selector */}
        <div className="flex flex-wrap items-center gap-4 mb-8">
          <Select value={selectedPath} onValueChange={handlePathChange}>
            <SelectTrigger className="w-80">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {attackPaths.map((ap) => (
                <SelectItem key={ap.slug} value={ap.slug}>
                  {ap.title}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Badge variant="outline" className={severityColor[path.severity]}>
            {path.severity}
          </Badge>
          <Badge variant="outline" className="text-muted-foreground">
            {attackObjectiveLabels[path.objective]}
          </Badge>
          {currentStep === -1 ? (
            <Button onClick={handleStart} className="gap-2">
              <Play className="h-4 w-4" /> Start Simulation
            </Button>
          ) : (
            <Button variant="outline" onClick={handleReset} className="gap-2">
              <RotateCcw className="h-4 w-4" /> Reset
            </Button>
          )}
        </div>

        {/* Description */}
        <p className="text-sm text-muted-foreground mb-6 max-w-3xl">{path.description}</p>

        {/* Attack Path Detection Summary */}
        <Card className="mb-8 border-border/50">
          <CardHeader className="py-4">
            <CardTitle className="text-base font-medium">Attack Detection Coverage</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-4">
              <div className="rounded-lg border border-border/50 bg-card p-3">
                <p className="text-xl font-bold text-foreground">{totalSteps}</p>
                <p className="text-xs text-muted-foreground">Steps</p>
              </div>
              <div className="rounded-lg border border-emerald-500/30 bg-emerald-500/5 p-3">
                <p className="text-xl font-bold text-emerald-400">{fullCoverageCount}</p>
                <p className="text-xs text-muted-foreground">Full Coverage</p>
              </div>
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-3">
                <p className="text-xl font-bold text-amber-400">{partialCoverageCount}</p>
                <p className="text-xs text-muted-foreground">Partial Coverage</p>
              </div>
              <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3">
                <p className="text-xl font-bold text-red-400">{noCoverageCount}</p>
                <p className="text-xs text-muted-foreground">No Coverage</p>
              </div>
            </div>
            <div>
              <div className="flex justify-between text-sm mb-1">
                <span className="text-muted-foreground">Coverage Score</span>
                <span className="font-semibold text-foreground">{coverageScore}%</span>
              </div>
              <div className="h-2 bg-muted rounded-full overflow-hidden">
                <div
                  className="h-full bg-primary rounded-full transition-all duration-300"
                  style={{ width: `${coverageScore}%` }}
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Progress bar */}
        {currentStep >= 0 && (
          <div className="mb-8">
            <div className="flex items-center gap-2 mb-2">
              {stepsWithDetails.map((_, i) => (
                <div
                  key={i}
                  className={`h-2 flex-1 rounded-full transition-colors duration-300 ${
                    i < currentStep
                      ? "bg-primary"
                      : i === currentStep
                      ? "bg-primary animate-pulse"
                      : "bg-muted"
                  }`}
                />
              ))}
            </div>
            <p className="text-xs text-muted-foreground">
              Step {currentStep + 1} of {totalSteps}
            </p>
          </div>
        )}

        {/* Step chain visualization */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-8">
          {/* Left: step list */}
          <div className="space-y-2">
            {stepsWithDetails.map((step, i) => {
              const isActive = i === currentStep;
              const isPast = i < currentStep;
              const isFuture = i > currentStep;
              const hasDetection = step.detections.length > 0;

              return (
                <button
                  key={i}
                  onClick={() => currentStep >= 0 && setCurrentStep(i)}
                  disabled={currentStep < 0}
                  className={`w-full text-left p-3 rounded-lg border transition-all ${
                    isActive
                      ? "border-primary bg-primary/10"
                      : isPast
                      ? "border-border/50 bg-card/50 opacity-80"
                      : isFuture
                      ? "border-border/30 bg-card/30 opacity-50"
                      : "border-border/30 bg-card/30"
                  }`}
                >
                  <div className="flex items-center gap-3">
                    <div
                      className={`w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold shrink-0 ${
                        isActive
                          ? "bg-primary text-primary-foreground"
                          : isPast
                          ? hasDetection
                            ? "bg-emerald-500/20 text-emerald-400"
                            : "bg-red-500/20 text-red-400"
                          : "bg-muted text-muted-foreground"
                      }`}
                    >
                      {isPast ? (hasDetection ? "✓" : "✗") : i + 1}
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-medium truncate">
                        {step.technique?.name || step.techniqueId}
                      </p>
                      {step.context && (
                        <p className="text-xs text-muted-foreground truncate">{step.context}</p>
                      )}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>

          {/* Right: current step detail */}
          <div className="lg:col-span-2">
            <AnimatePresence mode="wait">
              {currentStep < 0 && !simulationComplete && (
                <motion.div
                  key="intro"
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -10 }}
                >
                  <Card className="border-dashed">
                    <CardContent className="py-16 text-center">
                      <Play className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                      <p className="text-muted-foreground">
                        Click <strong>"Start Simulation"</strong> to walk through this attack path step by step.
                      </p>
                    </CardContent>
                  </Card>
                </motion.div>
              )}

              {currentStep >= 0 && !simulationComplete && (
                <motion.div
                  key={`step-${currentStep}`}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  transition={{ duration: 0.2 }}
                >
                  {(() => {
                    const step = stepsWithDetails[currentStep];
                    const hasDetection = step.detections.length > 0;
                    return (
                      <Card>
                        <CardHeader>
                          <div className="flex items-center gap-3 mb-2">
                            <Badge variant="outline" className="text-xs">
                              Step {currentStep + 1}
                            </Badge>
                            {step.technique?.category && (
                              <Badge variant="secondary" className="text-xs capitalize">
                                {step.technique.category.replace(/-/g, " ")}
                              </Badge>
                            )}
                          </div>
                          <CardTitle className="text-xl">
                            <Link
                              to={`/attack-paths/technique/${step.techniqueId}`}
                              className="hover:text-primary transition-colors"
                            >
                              {step.technique?.name || step.techniqueId}
                            </Link>
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-5">
                          {step.context && (
                            <div className="p-3 rounded-md bg-muted/50 border border-border/50">
                              <p className="text-sm font-medium text-primary mb-1">Attacker Action</p>
                              <p className="text-sm text-foreground">{step.context}</p>
                            </div>
                          )}

                          {step.technique && (
                            <div>
                              <p className="text-sm text-muted-foreground">{step.technique.description}</p>
                              <div className="flex flex-wrap gap-1.5 mt-3">
                                {step.technique.services.map((svc) => (
                                  <Badge key={svc} variant="outline" className="text-xs">
                                    {svc}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Telemetry Sources — aggregated from detection rules (technique → detectionIds → logSources) */}
                          <div className="rounded-lg border border-border/50 bg-card p-4">
                            <p className="text-sm font-medium text-primary mb-2">Telemetry Sources</p>
                            {(() => {
                              const logSources = [...new Set(step.detections.flatMap((d) => d.logSources))];
                              return logSources.length > 0 ? (
                                <div className="flex flex-wrap gap-2">
                                  {logSources.map((src) => (
                                    <Badge key={src} variant="outline" className="text-xs border-border/70">
                                      {src}
                                    </Badge>
                                  ))}
                                </div>
                              ) : (
                                <p className="text-xs text-muted-foreground">
                                  No detection rules linked — telemetry requirements cannot be determined from the data model.
                                </p>
                              );
                            })()}
                          </div>

                          {/* Detection Coverage Indicator */}
                          <div className={`p-4 rounded-lg border ${
                            hasDetection
                              ? step.detections.length > 1
                                ? "border-emerald-500/30 bg-emerald-500/5"
                                : "border-amber-500/30 bg-amber-500/5"
                              : "border-red-500/30 bg-red-500/5"
                          }`}>
                            <div className="flex items-center gap-2 mb-2">
                              {hasDetection ? (
                                step.detections.length > 1 ? (
                                  <ShieldCheck className="h-5 w-5 text-emerald-400" />
                                ) : (
                                  <ShieldCheck className="h-5 w-5 text-amber-400" />
                                )
                              ) : (
                                <ShieldOff className="h-5 w-5 text-red-400" />
                              )}
                              <span className={`font-semibold text-sm ${
                                hasDetection
                                  ? step.detections.length > 1
                                    ? "text-emerald-400"
                                    : "text-amber-400"
                                  : "text-red-400"
                              }`}>
                                Detection Coverage:{" "}
                                {step.detections.length > 1 ? "Full" : step.detections.length === 1 ? "Partial" : "None"}
                              </span>
                            </div>
                            {hasDetection ? (
                              <>
                                <p className="text-xs text-muted-foreground mb-2">Detected Rules:</p>
                                <ul className="space-y-1">
                                  {step.detections.map((d) => (
                                    <li key={d.id} className="text-xs flex items-center gap-2">
                                      <CheckCircle className={`h-3 w-3 shrink-0 ${step.detections.length > 1 ? "text-emerald-400" : "text-amber-400"}`} />
                                      <Link
                                        to={`/detection-engineering?rule=${d.id}`}
                                        className="text-primary hover:underline font-medium"
                                      >
                                        {d.title}
                                      </Link>
                                    </li>
                                  ))}
                                </ul>
                              </>
                            ) : (
                              <>
                                <p className="text-sm font-medium text-red-400 mb-1">Detection Gap</p>
                                <p className="text-xs text-muted-foreground">
                                  No detection rules currently exist for this technique.
                                </p>
                              </>
                            )}
                          </div>

                          {/* Investigation Guidance — from detection rules */}
                          {(() => {
                            const investigationSteps = step.detections.flatMap((d) => d.investigationSteps ?? []);
                            const uniqueSteps = [...new Set(investigationSteps)];
                            if (uniqueSteps.length === 0) return null;
                            return (
                              <div className="rounded-lg border border-border/50 bg-card p-4">
                                <p className="text-sm font-medium text-primary mb-2">Investigation Guidance</p>
                                <ol className="space-y-1 list-decimal list-inside text-sm text-muted-foreground">
                                  {uniqueSteps.slice(0, 6).map((stepText, i) => (
                                    <li key={i}>{stepText}</li>
                                  ))}
                                </ol>
                              </div>
                            );
                          })()}

                          {/* Navigation */}
                          <div className="flex justify-between pt-2">
                            <Button
                              variant="outline"
                              onClick={handlePrev}
                              disabled={currentStep === 0}
                              className="gap-2"
                            >
                              <ChevronLeft className="h-4 w-4" /> Previous
                            </Button>
                            <Button onClick={handleNext} className="gap-2">
                              {currentStep < totalSteps - 1 ? (
                                <>
                                  Next Step <ChevronRight className="h-4 w-4" />
                                </>
                              ) : (
                                "Complete Simulation"
                              )}
                            </Button>
                          </div>
                        </CardContent>
                      </Card>
                    );
                  })()}
                </motion.div>
              )}

              {simulationComplete && (
                <motion.div
                  key="summary"
                  initial={{ opacity: 0, scale: 0.95 }}
                  animate={{ opacity: 1, scale: 1 }}
                >
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <AlertTriangle className="h-5 w-5 text-primary" />
                        Simulation Complete
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      <div className="grid grid-cols-3 gap-4">
                        <div className="text-center p-4 rounded-lg bg-muted/50">
                          <p className="text-2xl font-bold text-foreground">{totalSteps}</p>
                          <p className="text-xs text-muted-foreground">Total Steps</p>
                        </div>
                        <div className="text-center p-4 rounded-lg bg-emerald-500/10">
                          <p className="text-2xl font-bold text-emerald-400">{detectedCount}</p>
                          <p className="text-xs text-muted-foreground">Detected</p>
                        </div>
                        <div className="text-center p-4 rounded-lg bg-red-500/10">
                          <p className="text-2xl font-bold text-red-400">{totalSteps - detectedCount}</p>
                          <p className="text-xs text-muted-foreground">Gaps</p>
                        </div>
                      </div>

                      <div>
                        <div className="flex justify-between text-sm mb-1">
                          <span className="text-muted-foreground">Detection Coverage</span>
                          <span className="font-semibold text-foreground">{coveragePercent}%</span>
                        </div>
                        <div className="h-3 bg-muted rounded-full overflow-hidden">
                          <div
                            className="h-full bg-gradient-primary rounded-full transition-all duration-500"
                            style={{ width: `${coveragePercent}%` }}
                          />
                        </div>
                      </div>

                      {/* Undetected steps */}
                      {stepsWithDetails.filter((s) => s.detections.length === 0).length > 0 && (
                        <div>
                          <p className="text-sm font-semibold text-red-400 mb-2">Undetected Techniques:</p>
                          <ul className="space-y-1">
                            {stepsWithDetails
                              .filter((s) => s.detections.length === 0)
                              .map((s, i) => (
                                <li key={i} className="text-sm text-muted-foreground flex items-center gap-2">
                                  <ShieldOff className="h-3.5 w-3.5 text-red-400 shrink-0" />
                                  <Link
                                    to={`/attack-paths/technique/${s.techniqueId}`}
                                    className="hover:text-foreground transition-colors"
                                  >
                                    {s.technique?.name || s.techniqueId}
                                  </Link>
                                </li>
                              ))}
                          </ul>
                        </div>
                      )}

                      <div className="flex gap-3 pt-2">
                        <Button onClick={handleReset} variant="outline" className="gap-2">
                          <RotateCcw className="h-4 w-4" /> Run Again
                        </Button>
                        <Button asChild>
                          <Link to="/gap-analysis">View Full Gap Analysis</Link>
                        </Button>
                      </div>
                    </CardContent>
                  </Card>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </Layout>
  );
}
