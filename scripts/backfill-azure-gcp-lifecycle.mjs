#!/usr/bin/env node
/**
 * Backfill Azure/GCP detection-engineering phases 1–5 from meta.json + sigma.yml.
 * Generated lifecycle is experimental until a detection engineer reviews it.
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PROVIDERS = ["azure", "gcp"];

function writeJson(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n");
}

function logSourceFor(provider, meta) {
  if (meta.logSources?.[0]) return meta.logSources[0];
  return provider === "gcp" ? "GCP Audit Logs" : "Azure Activity Logs";
}

function generatingService(meta) {
  return meta.awsService || "unknown";
}

function buildLifecycle(meta, provider) {
  const title = meta.title;
  const desc = meta.description;
  const service = generatingService(meta);
  return {
    whyItMatters: desc,
    threatContext: {
      attackerBehavior: desc,
      whyItMatters: `${title} is a ${service} control-plane or identity signal that defenders should investigate when it is unexpected.`,
      riskAndImpact: `Unauthorized ${title.toLowerCase()} can enable persistence, privilege escalation, credential theft, or impact depending on the resource.`,
    },
    telemetryValidation: {
      requiredLogSources: [logSourceFor(provider, meta)],
      requiredFields: ["eventTime", "operationName", "caller", "status"],
      loggingRequirements: [
        `${logSourceFor(provider, meta)} must be enabled for the tenant or project.`,
        "Retain raw request properties so the detection can be tuned to approved actors.",
      ],
      limitations: [
        "Generated lifecycle — review threat research, enrichment, and testing before production.",
        "Bare Sigma selections may fire on every matching event until customer inventory is supplied.",
      ],
    },
    enrichment: [
      {
        dimension: "Approved actor",
        description: "Compare the caller to change-management and privileged-identity inventories.",
        examples: ["break-glass admin", "CI/CD service principal"],
        falsePositiveReduction: "Suppress known automation identities after review.",
      },
    ],
    logicExplanation: {
      humanReadable: `Alert when telemetry matches the Sigma selection for ${title}.`,
      conditions: [desc],
      whenToFire: "On each matching successful (or explicitly failed) control-plane event.",
      tuningGuidance: "Add approved-actor allowlists and sensitive-target inventories before production.",
    },
    simulationCommand: `Review the Sigma rule for ${meta.id} and replay a matching ${provider} audit event in a lab tenant.`,
    quality: {
      signalQuality: 5,
      falsePositiveRate: "unknown until tuned",
      expectedVolume: "varies by tenant",
      productionReadiness: "experimental",
    },
    generatedFromTemplate: true,
  };
}

let wrote = 0;
for (const provider of PROVIDERS) {
  const base = path.join(ROOT, "rules", provider);
  if (!fs.existsSync(base)) continue;
  for (const slug of fs.readdirSync(base)) {
    const dir = path.join(base, slug);
    if (!fs.statSync(dir).isDirectory()) continue;
    const metaPath = path.join(dir, "meta.json");
    if (!fs.existsSync(metaPath)) continue;
    const meta = JSON.parse(fs.readFileSync(metaPath, "utf8"));
    const logSource = logSourceFor(provider, meta);

    if (!fs.existsSync(path.join(dir, "lifecycle.json"))) {
      writeJson(path.join(dir, "lifecycle.json"), buildLifecycle(meta, provider));
      wrote++;
    }
    if (!fs.existsSync(path.join(dir, "telemetry.json"))) {
      writeJson(path.join(dir, "telemetry.json"), {
        primaryLogSource: logSource,
        generatingService: generatingService(meta),
        importantFields: ["operationName", "caller", "status", "eventTime"],
        exampleEvent: JSON.stringify(
          {
            eventTime: "2026-01-15T12:00:00Z",
            operationName: meta.title,
            caller: `${provider}-lab-user`,
            status: { value: "Success" },
          },
          null,
          2
        ),
      });
      wrote++;
    }
    if (!fs.existsSync(path.join(dir, "investigation.json"))) {
      writeJson(path.join(dir, "investigation.json"), [
        `Identify the actor and target for ${meta.title}.`,
        "Confirm whether the change was authorized (ticket, PIM, change window).",
        "Check for follow-on privilege, persistence, or data-access activity.",
        "Revert unauthorized changes and rotate credentials if the actor is compromised.",
      ]);
      wrote++;
    }
    if (!fs.existsSync(path.join(dir, "testing.json"))) {
      writeJson(path.join(dir, "testing.json"), [
        `Reproduce ${meta.title} in a lab ${provider} tenant.`,
        "Confirm the matching audit/sign-in event is logged.",
        "Run the Sigma rule against the event and confirm an alert.",
      ]);
      wrote++;
    }
  }
}

console.log(`Wrote ${wrote} missing lifecycle/telemetry/investigation/testing files.`);
