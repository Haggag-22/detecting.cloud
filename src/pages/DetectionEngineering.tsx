import { useState } from "react";
import { Layout } from "@/components/Layout";
import { detections, getDetectionsByService } from "@/data/detections";
import { attackPaths } from "@/data/attackPaths";
import { Badge } from "@/components/ui/badge";
import { Search, Link as LinkIcon, ChevronRight } from "lucide-react";
import { useSearchParams, Link } from "react-router-dom";
import { getAwsServiceIcon } from "@/components/AwsIcons";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";

const severityColors: Record<string, string> = {
  Critical: "bg-severity-critical/15 text-severity-critical",
  High: "bg-severity-high/15 text-severity-high",
  Medium: "bg-severity-medium/15 text-severity-medium",
  Low: "bg-muted text-muted-foreground",
};

const formatLabels: Record<string, string> = {
  sigma: "Sigma Rule",
  splunk: "Splunk Query",
  cloudtrail: "CloudTrail Athena",
  cloudwatch: "CloudWatch Insights",
};

const DetectionEngineeringPage = () => {
  const [searchParams, setSearchParams] = useSearchParams();
  const ruleParam = searchParams.get("rule");
  const serviceParam = searchParams.get("service");
  const [search, setSearch] = useState("");

  const detectionsByService = getDetectionsByService();
  const services = Object.keys(detectionsByService);

  // If a specific rule is selected, show detailed view
  const selectedDetection = ruleParam ? detections.find((d) => d.id === ruleParam) : null;

  // Filter detections
  // Primary rules for the selected service
  const primaryRules = serviceParam
    ? detections.filter((d) => d.awsService === serviceParam)
    : detections;

  // Related rules (where service appears in relatedServices but not primary)
  const relatedRules = serviceParam
    ? detections.filter((d) => d.awsService !== serviceParam && d.relatedServices.includes(serviceParam))
    : [];

  const filterBySearch = (list: typeof detections) =>
    list.filter((d) => {
      if (!search) return true;
      const s = search.toLowerCase();
      return (
        d.title.toLowerCase().includes(s) ||
        d.description.toLowerCase().includes(s) ||
        d.tags.some((t) => t.toLowerCase().includes(s))
      );
    });

  const filtered = filterBySearch(primaryRules);
  const filteredRelated = filterBySearch(relatedRules);

  if (selectedDetection) {
    const ServiceIcon = getAwsServiceIcon(selectedDetection.awsService);
    const relatedAttacks = attackPaths.filter((ap) =>
      selectedDetection.relatedAttackSlugs.includes(ap.slug)
    );
    const availableFormats = Object.entries(selectedDetection.rules).filter(([, v]) => !!v);

    return (
      <Layout>
        <div className="container py-12 max-w-4xl">
          {/* Breadcrumb */}
          <div className="flex items-center gap-2 text-sm text-muted-foreground mb-6">
            <Link to="/detection-engineering" className="hover:text-foreground transition-colors">
              Detection Engineering
            </Link>
            <ChevronRight className="h-3.5 w-3.5" />
            <Link
              to={`/detection-engineering?service=${selectedDetection.awsService}`}
              className="hover:text-foreground transition-colors"
            >
              {selectedDetection.awsService}
            </Link>
            <ChevronRight className="h-3.5 w-3.5" />
            <span className="text-foreground">{selectedDetection.title}</span>
          </div>

          {/* Header */}
          <div className="flex items-start gap-4 mb-8">
            {ServiceIcon && <ServiceIcon size={40} />}
            <div>
              <h1 className="font-display text-2xl font-bold mb-2">{selectedDetection.title}</h1>
              <p className="text-muted-foreground">{selectedDetection.description}</p>
            </div>
          </div>

          {/* Metadata */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
            <div className="rounded-lg border border-border/50 bg-card p-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Primary Service</p>
              <div className="flex items-center gap-2">
                {ServiceIcon && <ServiceIcon size={16} />}
                <span className="font-medium text-sm">{selectedDetection.awsService}</span>
              </div>
            </div>
            <div className="rounded-lg border border-border/50 bg-card p-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Severity</p>
              <Badge className={`text-xs border-0 ${severityColors[selectedDetection.severity]}`}>
                {selectedDetection.severity}
              </Badge>
            </div>
            <div className="rounded-lg border border-border/50 bg-card p-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Log Sources</p>
              <p className="text-sm font-medium">{selectedDetection.logSources.join(", ")}</p>
            </div>
            <div className="rounded-lg border border-border/50 bg-card p-4">
              <p className="text-xs text-muted-foreground uppercase tracking-wider mb-1">Rule Formats</p>
              <p className="text-sm font-medium">{availableFormats.length} formats</p>
            </div>
          </div>

          {/* Related AWS Services */}
          {selectedDetection.relatedServices.length > 0 && (
            <div className="mb-8">
              <h2 className="text-sm font-medium text-muted-foreground uppercase tracking-wider mb-3">Related AWS Services</h2>
              <div className="flex flex-wrap gap-2">
                {selectedDetection.relatedServices.map((svc) => {
                  const SvcIcon = getAwsServiceIcon(svc);
                  return (
                    <Link
                      key={svc}
                      to={`/detection-engineering?service=${svc}`}
                      className="flex items-center gap-2 rounded-lg border border-border/50 bg-card px-3 py-2 hover:border-primary/30 transition-colors"
                    >
                      {SvcIcon && <SvcIcon size={16} />}
                      <span className="text-sm font-medium">{svc}</span>
                    </Link>
                  );
                })}
              </div>
            </div>
          )}

          {/* Tags */}
          <div className="flex flex-wrap gap-1.5 mb-8">
            {selectedDetection.tags.map((tag) => (
              <Badge key={tag} variant="outline" className="text-xs border-border/70 text-muted-foreground">
                {tag}
              </Badge>
            ))}
          </div>

          {/* Rule Formats Tabs */}
          <div className="mb-8">
            <h2 className="font-display text-lg font-semibold mb-4">Detection Rules</h2>
            <Tabs defaultValue={availableFormats[0]?.[0] || "sigma"}>
              <TabsList className="bg-muted border border-border/50">
                {availableFormats.map(([key]) => (
                  <TabsTrigger key={key} value={key} className="text-xs">
                    {formatLabels[key] || key}
                  </TabsTrigger>
                ))}
              </TabsList>
              {availableFormats.map(([key, value]) => (
                <TabsContent key={key} value={key}>
                  <div className="rounded-lg border border-border overflow-hidden">
                    <div className="px-4 py-2 bg-muted text-xs text-muted-foreground font-mono border-b border-border flex items-center justify-between">
                      <span>{formatLabels[key]}</span>
                    </div>
                    <pre className="p-4 overflow-x-auto bg-muted/30 text-sm font-mono leading-relaxed">
                      <code>{value}</code>
                    </pre>
                  </div>
                </TabsContent>
              ))}
            </Tabs>
          </div>

          {/* False Positives */}
          <div className="mb-8">
            <h2 className="font-display text-lg font-semibold mb-3">False Positives</h2>
            <ul className="space-y-2">
              {selectedDetection.falsePositives.map((fp, i) => (
                <li key={i} className="text-sm text-muted-foreground flex items-start gap-2">
                  <span className="text-primary mt-0.5">•</span> {fp}
                </li>
              ))}
            </ul>
          </div>

          {/* Related Attack Techniques */}
          {relatedAttacks.length > 0 && (
            <div className="border-t border-border pt-6">
              <h2 className="flex items-center gap-2 font-display text-lg font-semibold mb-4">
                <LinkIcon className="h-4 w-4 text-accent" /> Detects Attack Techniques
              </h2>
              <div className="space-y-3">
                {relatedAttacks.map((ap) => (
                  <Link
                    key={ap.slug}
                    to={`/attack-paths?technique=${ap.slug}`}
                    className="block rounded-lg border border-border/50 bg-card p-4 hover:border-primary/30 transition-colors"
                  >
                    <div className="flex items-center gap-2 mb-1">
                      <Badge className={`text-xs border-0 ${severityColors[ap.severity]}`}>
                        {ap.severity}
                      </Badge>
                      <span className="font-medium text-sm">{ap.title}</span>
                    </div>
                    <p className="text-xs text-muted-foreground">{ap.description.substring(0, 120)}…</p>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <div className="container py-12">
        <h1 className="font-display text-3xl font-bold mb-2">Detection Engineering</h1>
        <p className="text-muted-foreground mb-8">
          Cloud security detection rules organized by AWS service.
        </p>

        {/* Search & Service Filter */}
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
              variant={!serviceParam ? "default" : "outline"}
              className={`cursor-pointer ${
                !serviceParam ? "bg-primary text-primary-foreground" : "border-border text-muted-foreground"
              }`}
              onClick={() => setSearchParams({})}
            >
              All Services
            </Badge>
            {services.map((service) => {
              const Icon = getAwsServiceIcon(service);
              return (
                <Badge
                  key={service}
                  variant={serviceParam === service ? "default" : "outline"}
                  className={`cursor-pointer flex items-center gap-1.5 ${
                    serviceParam === service
                      ? "bg-primary text-primary-foreground"
                      : "border-border text-muted-foreground"
                  }`}
                  onClick={() => setSearchParams({ service })}
                >
                  {Icon && <Icon size={14} />}
                  {service}
                </Badge>
              );
            })}
          </div>
        </div>

        {/* Rules grouped by service */}
        {serviceParam ? (
          <div className="space-y-3">
            {filtered.map((det) => (
              <DetectionCard key={det.id} detection={det} />
            ))}
            {filtered.length === 0 && (
              <p className="text-muted-foreground text-sm py-8 text-center">No detections found.</p>
            )}

            {/* Related rules from other primary services */}
            {filteredRelated.length > 0 && (
              <div className="mt-10 pt-6 border-t border-border">
                <h2 className="text-sm font-medium text-muted-foreground uppercase tracking-wider mb-4">
                  Related Detection Rules
                </h2>
                <p className="text-xs text-muted-foreground mb-4">
                  These rules belong to other services but involve {serviceParam} in the attack chain.
                </p>
                <div className="space-y-3">
                  {filteredRelated.map((det) => (
                    <DetectionCard key={det.id} detection={det} />
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : (
          <div className="space-y-10">
            {services.map((service) => {
              const serviceRules = (detectionsByService[service] || []).filter((d) => {
                if (!search) return true;
                const s = search.toLowerCase();
                return d.title.toLowerCase().includes(s) || d.description.toLowerCase().includes(s);
              });
              if (serviceRules.length === 0) return null;

              const ServiceIcon = getAwsServiceIcon(service);
              return (
                <div key={service}>
                  <div className="flex items-center gap-3 mb-4">
                    {ServiceIcon && <ServiceIcon size={28} />}
                    <h2 className="font-display text-xl font-bold">{service}</h2>
                    <Badge variant="outline" className="text-xs border-border text-muted-foreground">
                      {serviceRules.length} rules
                    </Badge>
                  </div>
                  <div className="space-y-3">
                    {serviceRules.map((det) => (
                      <DetectionCard key={det.id} detection={det} />
                    ))}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </Layout>
  );
};

function DetectionCard({ detection: det }: { detection: typeof detections[0] }) {
  const ServiceIcon = getAwsServiceIcon(det.awsService);
  const formatCount = Object.values(det.rules).filter(Boolean).length;

  return (
    <Link
      to={`/detection-engineering?rule=${det.id}`}
      className="block rounded-lg border border-border/50 bg-card p-5 hover:border-primary/30 transition-colors"
    >
      <div className="flex items-center gap-3 mb-2">
        {ServiceIcon && <ServiceIcon size={20} />}
        <h3 className="font-semibold text-sm">{det.title}</h3>
        <Badge className={`text-xs border-0 ml-auto ${severityColors[det.severity]}`}>
          {det.severity}
        </Badge>
      </div>
      <p className="text-xs text-muted-foreground mb-3">{det.description}</p>
      <div className="flex items-center gap-2 flex-wrap">
        {det.tags.slice(0, 4).map((tag) => (
          <Badge key={tag} variant="outline" className="text-[10px] border-border/70 text-muted-foreground">
            {tag}
          </Badge>
        ))}
        <span className="text-[10px] text-muted-foreground ml-auto">{formatCount} rule formats</span>
      </div>
    </Link>
  );
}

export default DetectionEngineeringPage;
