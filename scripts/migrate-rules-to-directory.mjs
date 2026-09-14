#!/usr/bin/env node
/**
 * One-shot migrator:
 * 1) Extract existing detections from src/data/detections.ts into rules/aws/<slug>/
 * 2) Deploy approved old-rules candidates as new rule folders
 *
 * Folder layout:
 *   rules/aws/<slug>/
 *     meta.json
 *     sigma.yml
 *     formats/{splunk,cloudtrail,cloudwatch,eventbridge,lambda,esql,datadog}.*
 *     telemetry.json
 *     investigation.json
 *     testing.json
 *     lifecycle.json
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const RULES_AWS = path.join(ROOT, "rules", "aws");
const OLD_AWS = path.join(ROOT, "old-rules", "aws");
const CANDIDATES = "/tmp/aws-deploy-candidates.json";
const ICONS = "/tmp/aws-deploy-icons.json";

function slugify(title) {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-+/g, "-")
    .slice(0, 80);
}

function ensureUniqueSlug(base, used) {
  let slug = base || "unnamed-rule";
  let i = 2;
  while (used.has(slug)) {
    slug = `${base}-${i++}`;
  }
  used.add(slug);
  return slug;
}

function writeJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n");
}

function writeText(file, text) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, (text ?? "").replace(/\n$/, "") + "\n");
}

function writeDetectionFolder(slug, d) {
  const dir = path.join(RULES_AWS, slug);
  fs.mkdirSync(dir, { recursive: true });

  writeJson(path.join(dir, "meta.json"), {
    id: d.id,
    title: d.title,
    description: d.description,
    awsService: d.awsService,
    relatedServices: d.relatedServices || [],
    cloudProvider: d.cloudProvider || "aws",
    severity: d.severity,
    tags: d.tags || [],
    logSources: d.logSources || [],
    falsePositives: d.falsePositives || [],
    relatedAttackSlugs: d.relatedAttackSlugs || [],
  });

  if (d.rules?.sigma) writeText(path.join(dir, "sigma.yml"), d.rules.sigma);
  const formatsDir = path.join(dir, "formats");
  if (d.rules?.splunk) writeText(path.join(formatsDir, "splunk.txt"), d.rules.splunk);
  if (d.rules?.cloudtrail) writeText(path.join(formatsDir, "cloudtrail.sql"), d.rules.cloudtrail);
  if (d.rules?.cloudwatch) writeText(path.join(formatsDir, "cloudwatch.txt"), d.rules.cloudwatch);
  if (d.rules?.eventbridge) writeText(path.join(formatsDir, "eventbridge.json"), d.rules.eventbridge);
  if (d.rules?.lambda) writeText(path.join(formatsDir, "lambda.py"), d.rules.lambda);
  if (d.rules?.esql) writeText(path.join(formatsDir, "esql.txt"), d.rules.esql);
  if (d.rules?.datadog) writeText(path.join(formatsDir, "datadog.txt"), d.rules.datadog);

  if (d.telemetry) writeJson(path.join(dir, "telemetry.json"), d.telemetry);
  if (d.investigationSteps?.length) writeJson(path.join(dir, "investigation.json"), d.investigationSteps);
  if (d.testingSteps?.length) writeJson(path.join(dir, "testing.json"), d.testingSteps);
  if (d.lifecycle) writeJson(path.join(dir, "lifecycle.json"), d.lifecycle);
}

function loadDetectionsViaTsx() {
  const outFile = path.join(ROOT, ".tmp-detections-export.json");
  const script = `
import { detections } from "./src/data/detections.ts";
import fs from "fs";
fs.writeFileSync(${JSON.stringify(outFile)}, JSON.stringify(detections));
console.log("exported", detections.length);
`;
  const tmpTs = path.join(ROOT, ".tmp-export-detections.ts");
  fs.writeFileSync(tmpTs, script);
  const res = spawnSync("npx", ["--yes", "tsx", tmpTs], {
    cwd: ROOT,
    encoding: "utf8",
    env: process.env,
  });
  fs.unlinkSync(tmpTs);
  if (res.status !== 0) {
    console.error(res.stdout, res.stderr);
    throw new Error("Failed to export detections via tsx");
  }
  const data = JSON.parse(fs.readFileSync(outFile, "utf8"));
  fs.unlinkSync(outFile);
  return data;
}

function getField(text, key) {
  const m = text.match(new RegExp("^" + key + ":\\s*(.+)$", "m"));
  if (!m) return null;
  let v = m[1].trim();
  if (v === "|" || v === ">") {
    const lines = text.split("\n");
    const idx = lines.findIndex((l) => l.startsWith(key + ":"));
    const out = [];
    for (let i = idx + 1; i < lines.length; i++) {
      if (/^[a-zA-Z_]/.test(lines[i]) && !lines[i].startsWith(" ")) break;
      out.push(lines[i].replace(/^ {2,4}/, "").trim());
    }
    return out.filter(Boolean).join(" ");
  }
  return v.replace(/^["']|["']$/g, "");
}

function severityFromLevel(level) {
  const l = (level || "medium").toLowerCase();
  if (l === "critical") return "Critical";
  if (l === "high") return "High";
  if (l === "low") return "Low";
  return "Medium";
}

function nextDetId(existing) {
  const nums = existing
    .map((d) => {
      const m = String(d.id || "").match(/^det-(\d+)$/);
      return m ? Number(m[1]) : 0;
    })
    .filter(Boolean);
  const max = nums.length ? Math.max(...nums) : 200;
  return `det-${String(max + 1).padStart(3, "0")}`;
}

function minimalLifecycle(title, description, awsService) {
  return {
    whyItMatters: description,
    threatContext: {
      attackerBehavior: description,
      whyItMatters: description,
      riskAndImpact: `Abuse related to ${awsService} can weaken detection coverage, enable persistence, or expand attacker access.`,
    },
    telemetryValidation: {
      requiredLogSources: ["AWS CloudTrail"],
      requiredFields: ["eventName", "userIdentity.arn", "eventSource", "eventTime", "sourceIPAddress"],
      loggingRequirements: ["CloudTrail management events enabled for the relevant AWS APIs"],
      limitations: ["May require environment-specific tuning to reduce operational false positives"],
    },
    logicExplanation: {
      humanReadable: description,
      whenToFire: `When CloudTrail shows activity matching this ${title} detection.`,
    },
    quality: {
      signalQuality: 6,
      falsePositiveRate: "Medium until tuned",
      expectedVolume: "Varies by environment",
      productionReadiness: "experimental",
    },
    communityConfidence: { accurate: 0, needsTuning: 0, noisy: 0 },
  };
}

function main() {
  fs.mkdirSync(RULES_AWS, { recursive: true });

  console.log("Exporting existing detections...");
  const existing = loadDetectionsViaTsx();
  console.log(`Existing: ${existing.length}`);

  const usedSlugs = new Set();
  const usedIds = new Set(existing.map((d) => d.id));

  // Clear previous aws rules if re-running
  for (const name of fs.readdirSync(RULES_AWS)) {
    const p = path.join(RULES_AWS, name);
    if (fs.statSync(p).isDirectory()) fs.rmSync(p, { recursive: true, force: true });
  }

  for (const d of existing) {
    const slug = ensureUniqueSlug(slugify(d.title), usedSlugs);
    writeDetectionFolder(slug, d);
  }
  console.log(`Wrote ${existing.length} existing rules`);

  // Deploy candidates
  if (!fs.existsSync(CANDIDATES) || !fs.existsSync(ICONS)) {
    console.warn("Missing /tmp candidate/icon JSON — skipping new rule deploy");
    return;
  }
  const { deploy } = JSON.parse(fs.readFileSync(CANDIDATES, "utf8"));
  const { rows: iconRows } = JSON.parse(fs.readFileSync(ICONS, "utf8"));
  const iconByFile = Object.fromEntries(iconRows.map((r) => [r.f, r]));

  let nextNum =
    Math.max(
      0,
      ...[...usedIds].map((id) => {
        const m = String(id).match(/^det-(\d+)$/);
        return m ? Number(m[1]) : 0;
      })
    ) + 1;

  let added = 0;
  for (const c of deploy) {
    const yamlPath = path.join(OLD_AWS, c.file);
    if (!fs.existsSync(yamlPath)) {
      console.warn("missing old rule", c.file);
      continue;
    }
    const yaml = fs.readFileSync(yamlPath, "utf8");
    const icon = iconByFile[c.file];
    const awsService = icon?.awsService || "CloudTrail";
    const id = `det-${String(nextNum++).padStart(3, "0")}`;
    usedIds.add(id);

    const title = c.deployTitle;
    const description =
      getField(yaml, "description") ||
      `Detects ${title} activity in AWS CloudTrail.`;
    const level = getField(yaml, "level") || c.level || "medium";
    const slug = ensureUniqueSlug(slugify(title), usedSlugs);

    const fpMatch = yaml.match(/falsepositives:\n((?:\s*-\s*.+\n?)+)/i);
    const falsePositives = fpMatch
      ? fpMatch[1]
          .split("\n")
          .map((l) => l.replace(/^\s*-\s*/, "").trim())
          .filter(Boolean)
      : ["Legitimate administration or automation activity"];

    const tags = [awsService, "CloudTrail", "Imported"];
    const d = {
      id,
      title,
      description,
      awsService,
      relatedServices: [],
      cloudProvider: "aws",
      severity: severityFromLevel(level),
      tags,
      logSources: ["AWS CloudTrail"],
      falsePositives,
      relatedAttackSlugs: [],
      rules: { sigma: yaml.trim() },
      investigationSteps: [
        "Identify the IAM principal that performed the action.",
        "Validate whether the action was expected for that identity and account.",
        "Review surrounding CloudTrail activity from the same actor and source IP.",
        "Assess blast radius and revoke or contain if the activity is unauthorized.",
      ],
      testingSteps: [
        "Reproduce the API activity in a non-production account where safe.",
        "Confirm the CloudTrail event is present.",
        "Validate the Sigma rule matches the event.",
      ],
      telemetry: {
        primaryLogSource: "AWS CloudTrail",
        generatingService: `${String(awsService).toLowerCase().replace(/\s+/g, "")}.amazonaws.com`,
        importantFields: ["eventName", "userIdentity.arn", "userIdentity.type", "sourceIPAddress", "eventSource", "eventTime"],
        exampleEvent: JSON.stringify(
          {
            eventVersion: "1.08",
            eventSource: "cloudtrail.amazonaws.com",
            eventName: "ExampleEvent",
            userIdentity: { type: "IAMUser", arn: "arn:aws:iam::123456789012:user/example" },
            sourceIPAddress: "203.0.113.10",
            eventTime: "2026-01-15T12:00:00Z",
          },
          null,
          2
        ),
      },
      lifecycle: minimalLifecycle(title, description, awsService),
    };

    writeDetectionFolder(slug, d);
    added++;
  }

  console.log(`Added ${added} new deploy candidates`);
  console.log(`Total rule folders: ${fs.readdirSync(RULES_AWS).length}`);
}

main();
