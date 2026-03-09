import { useState } from "react";
import { Layout } from "@/components/Layout";
import { attackPaths } from "@/data/attackPaths";
import { Badge } from "@/components/ui/badge";
import { ChevronRight, AlertTriangle, Shield, Search } from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";

const severityColor = {
  Critical: "bg-destructive/10 text-destructive",
  High: "bg-amber-500/10 text-amber-400",
  Medium: "bg-primary/10 text-primary",
};

const AttackPathsPage = () => {
  const [selected, setSelected] = useState<string | null>(null);
  const active = attackPaths.find((a) => a.slug === selected);

  return (
    <Layout>
      <div className="container py-12">
        <h1 className="font-display text-3xl font-bold mb-2">Attack Paths</h1>
        <p className="text-muted-foreground mb-8">Visual breakdown of cloud attack techniques and their detection opportunities.</p>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* List */}
          <div className="space-y-3">
            {attackPaths.map((ap) => (
              <button
                key={ap.slug}
                onClick={() => setSelected(ap.slug === selected ? null : ap.slug)}
                className={`w-full text-left rounded-lg border p-4 transition-all ${
                  selected === ap.slug
                    ? "border-primary/50 bg-primary/5"
                    : "border-border/50 bg-card hover:border-primary/30"
                }`}
              >
                <div className="flex items-center justify-between mb-2">
                  <Badge className={`text-xs border-0 ${severityColor[ap.severity]}`}>{ap.severity}</Badge>
                  <ChevronRight className={`h-4 w-4 text-muted-foreground transition-transform ${selected === ap.slug ? "rotate-90" : ""}`} />
                </div>
                <h3 className="font-semibold text-sm">{ap.title}</h3>
                <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{ap.overview}</p>
              </button>
            ))}
          </div>

          {/* Detail */}
          <div className="lg:col-span-2">
            <AnimatePresence mode="wait">
              {active ? (
                <motion.div
                  key={active.slug}
                  initial={{ opacity: 0, x: 20 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0, x: -20 }}
                  className="rounded-lg border border-border/50 bg-card p-6"
                >
                  <Badge className={`text-xs border-0 mb-3 ${severityColor[active.severity]}`}>{active.severity}</Badge>
                  <h2 className="font-display text-2xl font-bold mb-3">{active.title}</h2>
                  <p className="text-muted-foreground mb-6">{active.overview}</p>

                  <div className="space-y-6">
                    <div>
                      <h3 className="flex items-center gap-2 font-semibold mb-3"><AlertTriangle className="h-4 w-4 text-amber-400" /> Attack Steps</h3>
                      <ol className="space-y-2">
                        {active.steps.map((step, i) => (
                          <li key={i} className="flex gap-3 text-sm text-muted-foreground">
                            <span className="shrink-0 w-6 h-6 rounded-full bg-muted flex items-center justify-center text-xs font-mono font-bold text-foreground">{i + 1}</span>
                            {step}
                          </li>
                        ))}
                      </ol>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-3">Required Permissions</h3>
                      <div className="flex flex-wrap gap-2">
                        {active.permissions.map((p) => (
                          <code key={p} className="px-2 py-1 rounded bg-muted text-xs font-mono text-primary">{p}</code>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h3 className="flex items-center gap-2 font-semibold mb-3"><Search className="h-4 w-4 text-primary" /> Detection Opportunities</h3>
                      <ul className="space-y-1.5">
                        {active.detectionOpportunities.map((d, i) => (
                          <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="text-primary mt-0.5">•</span> {d}
                          </li>
                        ))}
                      </ul>
                    </div>

                    <div>
                      <h3 className="flex items-center gap-2 font-semibold mb-3"><Shield className="h-4 w-4 text-green-400" /> Mitigations</h3>
                      <ul className="space-y-1.5">
                        {active.mitigations.map((m, i) => (
                          <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                            <span className="text-green-400 mt-0.5">•</span> {m}
                          </li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </motion.div>
              ) : (
                <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="rounded-lg border border-dashed border-border bg-card/50 p-12 text-center">
                  <p className="text-muted-foreground">Select an attack path to view details</p>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default AttackPathsPage;
