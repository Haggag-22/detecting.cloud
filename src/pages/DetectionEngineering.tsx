import { useState } from "react";
import { Layout } from "@/components/Layout";
import { detections } from "@/data/detections";
import { attackPaths } from "@/data/attackPaths";
import { Badge } from "@/components/ui/badge";
import { Search, Link as LinkIcon } from "lucide-react";
import { useSearchParams, Link } from "react-router-dom";

const typeColors: Record<string, string> = {
  Sigma: "bg-accent/10 text-accent",
  CloudTrail: "bg-primary/10 text-primary",
  Splunk: "bg-green-500/10 text-green-400",
  SIEM: "bg-primary/10 text-primary",
};

const DetectionEngineeringPage = () => {
  const [searchParams] = useSearchParams();
  const ruleParam = searchParams.get("rule");
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState<string | null>(null);

  const filtered = detections.filter((d) => {
    const matchesSearch =
      !search ||
      d.title.toLowerCase().includes(search.toLowerCase()) ||
      d.description.toLowerCase().includes(search.toLowerCase());
    const matchesType = !typeFilter || d.type === typeFilter;
    return matchesSearch && matchesType;
  });

  const types = Array.from(new Set(detections.map((d) => d.type)));

  // Highlight specific rule if linked from attack path
  const highlightedRule = ruleParam;

  return (
    <Layout>
      <div className="container py-12">
        <h1 className="font-display text-3xl font-bold mb-2">Detection Engineering</h1>
        <p className="text-muted-foreground mb-8">
          Curated detection rules and queries for cloud security monitoring.
        </p>

        <div className="flex flex-col sm:flex-row gap-3 mb-8">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <input
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Search detections..."
              className="w-full rounded-lg border border-border bg-card pl-10 pr-4 py-2.5 text-sm outline-none focus:border-primary/50 transition-colors"
            />
          </div>
          <div className="flex gap-2 flex-wrap">
            <Badge
              variant={!typeFilter ? "default" : "outline"}
              className={`cursor-pointer ${
                !typeFilter ? "bg-primary text-primary-foreground" : "border-border text-muted-foreground"
              }`}
              onClick={() => setTypeFilter(null)}
            >
              All
            </Badge>
            {types.map((type) => (
              <Badge
                key={type}
                variant={typeFilter === type ? "default" : "outline"}
                className={`cursor-pointer ${
                  typeFilter === type
                    ? "bg-primary text-primary-foreground"
                    : "border-border text-muted-foreground"
                }`}
                onClick={() => setTypeFilter(type)}
              >
                {type}
              </Badge>
            ))}
          </div>
        </div>

        <div className="space-y-4">
          {filtered.map((det) => {
            // Get related attack paths for this detection
            const relatedAttacks = attackPaths.filter((ap) =>
              det.relatedAttackSlugs.includes(ap.slug)
            );

            return (
              <div
                key={det.id}
                id={det.id}
                className={`rounded-lg border bg-card p-6 transition-colors ${
                  highlightedRule === det.id
                    ? "border-primary/50 bg-primary/5"
                    : "border-border/50"
                }`}
              >
                <div className="flex items-center gap-2 mb-3">
                  <Badge className={`text-xs border-0 ${typeColors[det.type]}`}>{det.type}</Badge>
                  <h3 className="font-semibold">{det.title}</h3>
                </div>
                <p className="text-sm text-muted-foreground mb-3">{det.description}</p>

                {/* Tags */}
                <div className="flex flex-wrap gap-1.5 mb-4">
                  {det.tags.map((tag) => (
                    <Badge key={tag} variant="outline" className="text-xs border-border/70 text-muted-foreground">
                      {tag}
                    </Badge>
                  ))}
                </div>

                <div className="rounded-lg border border-border overflow-hidden mb-4">
                  <div className="px-4 py-1.5 bg-muted text-xs text-muted-foreground font-mono border-b border-border">
                    Detection Query
                  </div>
                  <pre className="p-4 overflow-x-auto bg-muted/50 text-sm font-mono leading-relaxed">
                    <code>{det.query}</code>
                  </pre>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-sm">
                  <div>
                    <h4 className="font-medium text-xs text-muted-foreground uppercase tracking-wider mb-2">
                      Log Sources
                    </h4>
                    <div className="flex flex-wrap gap-1.5">
                      {det.logSources.map((ls) => (
                        <Badge key={ls} variant="outline" className="text-xs border-border text-muted-foreground">
                          {ls}
                        </Badge>
                      ))}
                    </div>
                  </div>
                  <div>
                    <h4 className="font-medium text-xs text-muted-foreground uppercase tracking-wider mb-2">
                      False Positives
                    </h4>
                    <ul className="space-y-1">
                      {det.falsePositives.map((fp, i) => (
                        <li key={i} className="text-xs text-muted-foreground">
                          • {fp}
                        </li>
                      ))}
                    </ul>
                  </div>
                </div>

                {/* Related Attack Techniques */}
                {relatedAttacks.length > 0 && (
                  <div className="border-t border-border mt-4 pt-4">
                    <h4 className="flex items-center gap-2 font-medium text-xs text-muted-foreground uppercase tracking-wider mb-3">
                      <LinkIcon className="h-3.5 w-3.5 text-accent" /> Detects Attack Techniques
                    </h4>
                    <div className="flex flex-wrap gap-2">
                      {relatedAttacks.map((ap) => (
                        <Link
                          key={ap.slug}
                          to={`/attack-paths?technique=${ap.slug}`}
                          className="inline-flex items-center gap-1.5 rounded-md border border-border/50 bg-muted/30 px-3 py-1.5 text-xs hover:border-primary/30 transition-colors"
                        >
                          <span className="font-medium">{ap.title}</span>
                          <Badge className={`text-[10px] border-0 ${typeColors[det.type] || "bg-muted text-muted-foreground"}`}>
                            {ap.severity}
                          </Badge>
                        </Link>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </Layout>
  );
};

export default DetectionEngineeringPage;
