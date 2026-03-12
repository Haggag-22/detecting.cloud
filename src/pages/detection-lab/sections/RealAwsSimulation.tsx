import { useState } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { getDatasetById } from "@/data/detection-lab/datasets";
import { detections } from "@/data/detections";
import { normalizeEvents } from "@/lib/detection-lab/normalize";
import { evaluateRules } from "@/lib/detection-lab/ruleEvaluator";
import { useDetectionLab } from "../DetectionLabContext";
import { Server, AlertTriangle, Shield, Key, Play } from "lucide-react";

const simulations = [
  { id: "eks_access_entry", name: "EKS Access Entry Creation" },
  { id: "codebuild_exfil", name: "CodeBuild Credential Exposure" },
  { id: "s3_acl", name: "S3 ACL Persistence" },
  { id: "beanstalk_pivot", name: "Beanstalk Credential Pivot" },
];

export function RealAwsSimulation() {
  const [selectedSim, setSelectedSim] = useState("");
  const [result, setResult] = useState<{
    technique: string;
    eventsGenerated: number;
    detectionTriggered: boolean;
    detectionDelay: number;
    matchedRules: string[];
  } | null>(null);
  const lab = useDetectionLab();

  const handleRunSimulation = () => {
    const datasetId = selectedSim === "eks_access_entry" ? "eks_access_entry_creation"
      : selectedSim === "codebuild_exfil" ? "codebuild_credential_exfiltration"
      : selectedSim === "s3_acl" ? "s3_acl_persistence"
      : "beanstalk_configuration_theft";

    const dataset = getDatasetById(datasetId);
    if (!dataset) return;

    const events = normalizeEvents(dataset.events);
    const evalResults = evaluateRules(detections, events);
    const matched = evalResults.filter((r) => r.matched);

    setResult({
      technique: dataset.metadata.technique,
      eventsGenerated: events.length,
      detectionTriggered: matched.length > 0,
      detectionDelay: 10,
      matchedRules: matched.map((m) => m.detectionTitle),
    });

    lab?.addResult({
      type: "aws-simulation",
      detectionsTriggered: matched.length,
      details: { technique: dataset.metadata.technique, eventsGenerated: events.length },
    });
  };

  return (
    <div className="space-y-6">
      <Alert variant="destructive">
        <AlertTriangle className="h-4 w-4" />
        <AlertTitle>Security Notice: Use Test Accounts Only</AlertTitle>
        <AlertDescription>
          Create a dedicated AWS test account for simulation. Use new access keys or a delegated role with limited permissions.
          <strong> Revoke keys and delete test resources immediately after testing.</strong> Never use production credentials.
        </AlertDescription>
      </Alert>

      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Server className="h-5 w-5" />
            Real AWS Attack Simulation
          </CardTitle>
          <CardDescription>
            Run attack simulations in your AWS account and validate detections against collected CloudTrail telemetry.
            Connect via IAM role assumption.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-6">
          <div>
            <h4 className="font-medium mb-2 flex items-center gap-2">
              <Key className="h-4 w-4" />
              Setup: Create DetectingCloudSimulationRole
            </h4>
            <p className="text-sm text-muted-foreground mb-2">
              Create an IAM role in your test account with trust policy allowing this platform to assume it.
              Grant limited simulation permissions:
            </p>
            <ul className="list-disc list-inside text-sm text-muted-foreground space-y-1">
              <li>cloudtrail:LookupEvents, GetEventSelectors</li>
              <li>logs:FilterLogEvents, DescribeLogGroups</li>
              <li>eks:CreateAccessEntry, AssociateAccessPolicy (for EKS sim)</li>
              <li>iam:CreateAccessKey (for IAM sim)</li>
              <li>s3:PutBucketAcl (for S3 sim)</li>
              <li>codebuild:StartBuild (for CodeBuild sim)</li>
            </ul>
            <p className="text-sm text-amber-600 mt-2">
              Real AWS simulation requires a backend service to assume the role and execute API calls.
              This demo runs a local simulation using curated datasets.
            </p>
          </div>

          <div className="space-y-2">
            <Label>Select Simulation (Demo Mode)</Label>
            <Select value={selectedSim} onValueChange={setSelectedSim}>
              <SelectTrigger>
                <SelectValue placeholder="Choose simulation..." />
              </SelectTrigger>
              <SelectContent>
                {simulations.map((s) => (
                  <SelectItem key={s.id} value={s.id}>
                    {s.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <Button onClick={handleRunSimulation} disabled={!selectedSim}>
            <Play className="h-4 w-4 mr-2" />
            Run Simulation (Demo)
          </Button>
        </CardContent>
      </Card>

      {result && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Simulation Result
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div>
                <p className="text-sm text-muted-foreground">Technique</p>
                <p className="font-medium">{result.technique}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Events Generated</p>
                <p className="font-medium">{result.eventsGenerated}</p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Detection Triggered</p>
                <p className={`font-medium ${result.detectionTriggered ? "text-green-600" : "text-amber-600"}`}>
                  {result.detectionTriggered ? "YES" : "NO"}
                </p>
              </div>
              <div>
                <p className="text-sm text-muted-foreground">Detection Delay</p>
                <p className="font-medium">{result.detectionDelay} seconds</p>
              </div>
            </div>
            {result.matchedRules.length > 0 && (
              <div>
                <p className="text-sm font-medium mb-2">Matched Rules</p>
                <ul className="list-disc list-inside text-sm text-muted-foreground">
                  {result.matchedRules.map((r) => (
                    <li key={r}>{r}</li>
                  ))}
                </ul>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}
