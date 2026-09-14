#!/usr/bin/env node
/**
 * Import old-rules/{azure,gcp} into rules/{azure,gcp}/<slug>/ as Sigma-only rules.
 * Creates meta.json + sigma.yml only (no formats/lifecycle yet).
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function slugify(title) {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-+/g, "-")
    .slice(0, 80);
}

function ensureUnique(base, used) {
  let slug = base || "unnamed-rule";
  let i = 2;
  while (used.has(slug)) slug = `${base}-${i++}`;
  used.add(slug);
  return slug;
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

function getLogsource(text) {
  const product = (text.match(/^\s+product:\s*(.+)$/m) || [])[1]?.trim().replace(/^["']|["']$/g, "");
  const service = (text.match(/^\s+service:\s*(.+)$/m) || [])[1]?.trim().replace(/^["']|["']$/g, "");
  return { product, service };
}

function severityFromLevel(level) {
  const l = (level || "medium").toLowerCase();
  if (l === "critical") return "Critical";
  if (l === "high") return "High";
  if (l === "low") return "Low";
  return "Medium";
}

function parseFalsePositives(text) {
  const fpMatch = text.match(/falsepositives:\n((?:\s*-\s*.+\n?)+)/i);
  if (!fpMatch) return ["Unknown / environment-specific legitimate activity"];
  return fpMatch[1]
    .split("\n")
    .map((l) => l.replace(/^\s*-\s*/, "").trim())
    .filter(Boolean);
}

function parseTags(text) {
  const block = text.match(/^tags:\n((?:\s*-\s*.+\n?)+)/m);
  if (!block) return [];
  return block[1]
    .split("\n")
    .map((l) => l.replace(/^\s*-\s*/, "").trim())
    .filter(Boolean)
    .map((t) => t.replace(/^attack\./, "").replace(/\./g, " "));
}

/** Map Sigma logsource.service → browse UI service label */
const AZURE_SERVICE_MAP = {
  signinlogs: "Entra ID",
  auditlogs: "Entra ID",
  activitylogs: "Azure Activity",
  azureactivity: "Azure Activity",
  riskdetection: "Entra ID Protection",
  identityprotection: "Entra ID Protection",
  pim: "Entra ID PIM",
  "microsoft365": "Microsoft 365",
  office365: "Microsoft 365",
  exchange: "Exchange Online",
  sharepoint: "SharePoint",
  "azure.ad": "Entra ID",
  "azureactivitylogs": "Azure Activity",
};

const GCP_SERVICE_MAP = {
  "gcp.audit": "GCP Audit Logs",
  gcp: "GCP Audit Logs",
  gworkspace: "Google Workspace",
  workspace: "Google Workspace",
  k8s: "GKE",
  kubernetes: "GKE",
};

function mapService(provider, logService, title, filename) {
  const key = (logService || "").toLowerCase();
  const hay = `${filename} ${title}`.toLowerCase();

  if (provider === "azure") {
    if (/pim/i.test(hay)) return "Entra ID PIM";
    if (/identity.?protection|identity_protection|risk/i.test(hay)) return "Entra ID Protection";
    if (/kubernetes|k8s|aks|pod|cronjob/i.test(hay)) return "AKS";
    if (/key.?vault|keyvault/i.test(hay)) return "Key Vault";
    if (/firewall|nsg|network|vpn|vnet|virtual_network|application_security_group/i.test(hay))
      return "Azure Networking";
    if (/app_|application|service.?principal|oauth|consent|credential.?added/i.test(hay))
      return "Entra ID Apps";
    if (AZURE_SERVICE_MAP[key]) return AZURE_SERVICE_MAP[key];
    if (/signin|login|auth|mfa|device.?reg|guest|legacy|aad|entra/i.test(hay)) return "Entra ID";
    return "Azure";
  }

  // gcp — prefer resource-specific labels over generic gcp.audit
  if (/gworkspace|workspace|g.?suite|gmail|drive|out_of_domain/i.test(hay)) return "Google Workspace";
  if (/kubernetes|k8s|gke|pod|cronjob|rolebinding|secrets_modified/i.test(hay)) return "GKE";
  if (/bucket|storage/i.test(hay)) return "Cloud Storage";
  if (/sql|database/i.test(hay)) return "Cloud SQL";
  if (/dns/i.test(hay)) return "Cloud DNS";
  if (/firewall/i.test(hay)) return "VPC Firewall";
  if (/service.?account|access.?policy/i.test(hay)) return "GCP IAM";
  if (/dlp/i.test(hay)) return "Cloud DLP";
  if (/breakglass|container.?workload/i.test(hay)) return "GKE";
  if (GCP_SERVICE_MAP[key]) return GCP_SERVICE_MAP[key];
  return "GCP";
}

function logSourceLabel(provider, logService) {
  if (provider === "azure") {
    if (!logService) return "Azure Logs";
    if (/signin/i.test(logService)) return "Azure Sign-in Logs";
    if (/audit/i.test(logService)) return "Azure Audit Logs";
    if (/activity/i.test(logService)) return "Azure Activity Logs";
    return `Azure ${logService}`;
  }
  if (/gworkspace|workspace/i.test(logService || "")) return "Google Workspace Audit";
  if (/k8s|kubernetes/i.test(logService || "")) return "GKE Audit Logs";
  return "GCP Audit Logs";
}

function importProvider(provider, idPrefix) {
  const srcDir = path.join(ROOT, "old-rules", provider);
  const destRoot = path.join(ROOT, "rules", provider);
  fs.mkdirSync(destRoot, { recursive: true });

  const files = fs.readdirSync(srcDir).filter((f) => f.endsWith(".yml")).sort();
  const usedSlugs = new Set();
  let n = 1;
  let imported = 0;

  for (const file of files) {
    const yaml = fs.readFileSync(path.join(srcDir, file), "utf8");
    const title = getField(yaml, "title") || file.replace(/\.yml$/, "");
    const description =
      getField(yaml, "description") || `Detects ${title} activity in ${provider.toUpperCase()}.`;
    const level = getField(yaml, "level") || "medium";
    const { service: logService } = getLogsource(yaml);
    const awsService = mapService(provider, logService, title, file);
    const slug = ensureUnique(slugify(title) || slugify(file.replace(/\.yml$/, "")), usedSlugs);
    const id = `${idPrefix}-${String(n++).padStart(3, "0")}`;

    const dir = path.join(destRoot, slug);
    fs.mkdirSync(dir, { recursive: true });

    const meta = {
      id,
      title,
      description,
      awsService,
      relatedServices: [],
      cloudProvider: provider,
      severity: severityFromLevel(level),
      tags: [...new Set([provider.toUpperCase(), awsService, ...parseTags(yaml).slice(0, 6)])],
      logSources: [logSourceLabel(provider, logService)],
      falsePositives: parseFalsePositives(yaml),
      relatedAttackSlugs: [],
    };

    fs.writeFileSync(path.join(dir, "meta.json"), JSON.stringify(meta, null, 2) + "\n");
    fs.writeFileSync(path.join(dir, "sigma.yml"), yaml.replace(/\n$/, "") + "\n");
    imported++;
  }

  return { provider, imported, destRoot };
}

const azure = importProvider("azure", "az");
const gcp = importProvider("gcp", "gcp");
console.log(JSON.stringify({ azure, gcp }, null, 2));
console.log(
  "totals",
  {
    azureFolders: fs.readdirSync(path.join(ROOT, "rules", "azure")).length,
    gcpFolders: fs.readdirSync(path.join(ROOT, "rules", "gcp")).length,
  }
);
