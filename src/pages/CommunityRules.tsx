import { useState } from "react";
import { Layout } from "@/components/Layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Users, ThumbsUp, Copy, Search, Filter, GitPullRequest } from "lucide-react";
import { toast } from "sonner";
import { communityRules } from "@/data/communityRules";

const formatColors: Record<string, string> = {
  sigma: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  splunk: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  cloudtrail: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  cloudwatch: "bg-purple-500/20 text-purple-400 border-purple-500/30",
};

const severityColors: Record<string, string> = {
  Critical: "bg-red-500/20 text-red-400 border-red-500/30",
  High: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  Medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  Low: "bg-muted text-muted-foreground",
};

export default function CommunityRules() {
  const [searchTerm, setSearchTerm] = useState("");
  const [filterFormat, setFilterFormat] = useState<string>("all");
  const [filterSeverity, setFilterSeverity] = useState<string>("all");

  const filtered = communityRules.filter((r) => {
    const matchSearch =
      r.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
      r.tags.some((t) => t.toLowerCase().includes(searchTerm.toLowerCase()));
    const matchFormat = filterFormat === "all" || r.format === filterFormat;
    const matchSeverity = filterSeverity === "all" || r.severity === filterSeverity;
    return matchSearch && matchFormat && matchSeverity;
  });

  const copyRule = (rule: string) => {
    navigator.clipboard.writeText(rule);
    toast.success("Rule copied to clipboard");
  };

  return (
    <Layout>
      <div className="container py-10">
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4 mb-8">
          <div>
            <h1 className="text-3xl font-bold mb-2 flex items-center gap-3">
              <Users className="h-8 w-8 text-primary" />
              Community Rules
            </h1>
            <p className="text-muted-foreground">
              Community-contributed detection rules for AWS cloud security. Vote, copy, and contribute your own.
            </p>
          </div>
          <Button
            className="gap-2 shrink-0"
            onClick={() => window.open("https://github.com/Haggag-22/detecting.cloud/blob/main/CONTRIBUTING.md", "_blank")}
          >
            <GitPullRequest className="h-4 w-4" /> Contribute via PR
          </Button>
        </div>

        {/* Filters */}
        <div className="flex flex-wrap gap-3 mb-6">
          <div className="relative flex-1 min-w-[200px] max-w-sm">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder="Search rules..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-9"
            />
          </div>
          <Select value={filterFormat} onValueChange={setFilterFormat}>
            <SelectTrigger className="w-36">
              <Filter className="h-3.5 w-3.5 mr-1.5" />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Formats</SelectItem>
              <SelectItem value="sigma">Sigma</SelectItem>
              <SelectItem value="splunk">Splunk</SelectItem>
              <SelectItem value="cloudtrail">CloudTrail</SelectItem>
              <SelectItem value="cloudwatch">CloudWatch</SelectItem>
            </SelectContent>
          </Select>
          <Select value={filterSeverity} onValueChange={setFilterSeverity}>
            <SelectTrigger className="w-36">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Severities</SelectItem>
              <SelectItem value="Critical">Critical</SelectItem>
              <SelectItem value="High">High</SelectItem>
              <SelectItem value="Medium">Medium</SelectItem>
            </SelectContent>
          </Select>
        </div>

        <p className="text-sm text-muted-foreground mb-4">{filtered.length} rules</p>

        {/* Rules grid */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
          {filtered.map((rule) => (
            <Card key={rule.id} className="hover:border-primary/30 transition-colors">
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between gap-2">
                  <CardTitle className="text-base">{rule.title}</CardTitle>
                  <div className="flex items-center gap-1 text-sm text-muted-foreground shrink-0">
                    <ThumbsUp className="h-3.5 w-3.5" />
                    {rule.votes}
                  </div>
                </div>
                <p className="text-xs text-muted-foreground">{rule.description}</p>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex flex-wrap gap-1.5">
                  <Badge variant="outline" className={formatColors[rule.format]}>
                    {rule.format.toUpperCase()}
                  </Badge>
                  <Badge variant="outline" className={severityColors[rule.severity]}>
                    {rule.severity}
                  </Badge>
                  <Badge variant="secondary" className="text-xs">
                    {rule.awsService}
                  </Badge>
                </div>

                <pre className="bg-muted/50 rounded-md p-3 text-xs font-mono overflow-x-auto max-h-32 text-foreground">
                  {rule.rule}
                </pre>

                <div className="flex items-center justify-between">
                  <span className="text-xs text-muted-foreground">
                    by <span className="text-foreground font-medium">{rule.author}</span> · {rule.createdAt}
                  </span>
                  <Button variant="ghost" size="sm" onClick={() => copyRule(rule.rule)} className="gap-1.5 text-xs">
                    <Copy className="h-3 w-3" /> Copy
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </Layout>
  );
}
