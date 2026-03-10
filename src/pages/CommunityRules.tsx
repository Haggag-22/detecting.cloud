import { useState } from "react";
import { Layout } from "@/components/Layout";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Users, ThumbsUp, Copy, Search, Filter, GitPullRequest } from "lucide-react";
import { toast } from "sonner";

interface CommunityRule {
  id: string;
  title: string;
  description: string;
  author: string;
  awsService: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  format: "sigma" | "splunk" | "cloudtrail" | "cloudwatch";
  rule: string;
  votes: number;
  createdAt: string;
  tags: string[];
}

const communityRules: CommunityRule[] = [
  {
    id: "cr-001",
    title: "GuardDuty Finding Suppressed",
    description: "Detects when a GuardDuty finding is archived or suppressed, which could indicate an attacker covering their tracks.",
    author: "SecurityOps_Pro",
    awsService: "GuardDuty",
    severity: "High",
    format: "sigma",
    rule: `title: GuardDuty Finding Suppressed
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventName:
      - ArchiveFindings
      - UpdateFindingsFeedback
  condition: selection
level: high`,
    votes: 47,
    createdAt: "2025-12-15",
    tags: ["GuardDuty", "Defense Evasion"],
  },
  {
    id: "cr-002",
    title: "KMS Key Deletion Scheduled",
    description: "Detects when a KMS key is scheduled for deletion, potentially destroying encryption keys for critical data.",
    author: "CloudDefender42",
    awsService: "KMS",
    severity: "Critical",
    format: "splunk",
    rule: `index=aws sourcetype=aws:cloudtrail eventName=ScheduleKeyDeletion
| table _time, userIdentity.arn, requestParameters.keyId, requestParameters.pendingWindowInDays
| sort -_time`,
    votes: 62,
    createdAt: "2025-11-20",
    tags: ["KMS", "Impact", "Encryption"],
  },
  {
    id: "cr-003",
    title: "SSO Permission Set Modified",
    description: "Detects modifications to AWS SSO permission sets which could grant unauthorized access across accounts.",
    author: "IdentityWatch",
    awsService: "SSO",
    severity: "High",
    format: "cloudwatch",
    rule: `fields @timestamp, userIdentity.arn, eventName
| filter eventName in ["CreatePermissionSet", "UpdatePermissionSet", "AttachManagedPolicyToPermissionSet"]
| sort @timestamp desc`,
    votes: 35,
    createdAt: "2026-01-08",
    tags: ["SSO", "IAM", "Privilege Escalation"],
  },
  {
    id: "cr-004",
    title: "RDS Snapshot Made Public",
    description: "Detects when an RDS snapshot is shared publicly, potentially exposing database contents.",
    author: "DBSec_Team",
    awsService: "RDS",
    severity: "Critical",
    format: "sigma",
    rule: `title: RDS Snapshot Made Public
status: experimental
logsource:
  service: cloudtrail
detection:
  selection:
    eventName: ModifyDBSnapshotAttribute
    requestParameters.attributeName: restore
    requestParameters.valuesToAdd: 'all'
  condition: selection
level: critical`,
    votes: 89,
    createdAt: "2025-10-05",
    tags: ["RDS", "Data Exposure", "Snapshot"],
  },
  {
    id: "cr-005",
    title: "Config Rule Deleted",
    description: "Detects deletion of AWS Config rules which could be used to disable compliance monitoring.",
    author: "ComplianceBot",
    awsService: "Config",
    severity: "Medium",
    format: "splunk",
    rule: `index=aws sourcetype=aws:cloudtrail (eventName=DeleteConfigRule OR eventName=DeleteDeliveryChannel)
| table _time, userIdentity.arn, eventName, requestParameters.configRuleName`,
    votes: 28,
    createdAt: "2026-02-01",
    tags: ["Config", "Defense Evasion", "Compliance"],
  },
  {
    id: "cr-006",
    title: "Secrets Manager Secret Accessed by Unusual Role",
    description: "Detects when secrets are accessed by IAM roles not in the expected list.",
    author: "VaultGuard",
    awsService: "Secrets Manager",
    severity: "High",
    format: "cloudtrail",
    rule: `SELECT eventTime, userIdentity.arn, requestParameters.secretId
FROM cloudtrail_logs
WHERE eventName = 'GetSecretValue'
  AND userIdentity.arn NOT LIKE '%expected-role%'
ORDER BY eventTime DESC`,
    votes: 41,
    createdAt: "2026-01-22",
    tags: ["Secrets Manager", "Credential Access"],
  },
];

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
