#!/usr/bin/env node
/**
 * One-shot: split src/data/techniques.ts + attackPaths.ts into
 *   techniques/{aws,azure,gcp,kubernetes}/<slug>/
 *   attack-paths/{aws,azure,gcp,kubernetes}/<slug>/
 */
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";
import { spawnSync } from "child_process";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const PROVIDERS = ["aws", "azure", "gcp", "kubernetes"];

function writeJson(file, data) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + "\n");
}

function slugify(value) {
  return String(value)
    .toLowerCase()
    .replace(/^tech-/, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .replace(/-+/g, "-")
    .slice(0, 80);
}

function ensureUniqueSlug(base, used) {
  let slug = base || "unnamed";
  let i = 2;
  while (used.has(slug)) slug = `${base}-${i++}`;
  used.add(slug);
  return slug;
}

function resetProviderTree(rootDir) {
  fs.mkdirSync(rootDir, { recursive: true });
  for (const provider of PROVIDERS) {
    const dir = path.join(rootDir, provider);
    if (fs.existsSync(dir)) fs.rmSync(dir, { recursive: true, force: true });
    fs.mkdirSync(dir, { recursive: true });
  }
}

function exportViaTsx() {
  const outFile = path.join(ROOT, ".tmp-catalog-export.json");
  const tmpTs = path.join(ROOT, ".tmp-export-catalog.ts");
  fs.writeFileSync(
    tmpTs,
    `
import { techniques } from "./src/data/techniques.ts";
import { attackPaths } from "./src/data/attackPaths.ts";
import fs from "fs";
fs.writeFileSync(${JSON.stringify(outFile)}, JSON.stringify({ techniques, attackPaths }));
console.log("exported", techniques.length, "techniques,", attackPaths.length, "paths");
`
  );
  const res = spawnSync("npx", ["--yes", "tsx", tmpTs], {
    cwd: ROOT,
    encoding: "utf8",
    env: process.env,
  });
  fs.unlinkSync(tmpTs);
  if (res.status !== 0) {
    console.error(res.stdout, res.stderr);
    throw new Error("Failed to export catalog via tsx");
  }
  const data = JSON.parse(fs.readFileSync(outFile, "utf8"));
  fs.unlinkSync(outFile);
  console.log(res.stdout.trim());
  return data;
}

function writeTechnique(t, used) {
  const provider = t.cloudProvider || "aws";
  const slug = ensureUniqueSlug(slugify(t.id || t.name), used[provider]);
  const dir = path.join(ROOT, "techniques", provider, slug);

  writeJson(path.join(dir, "meta.json"), {
    id: t.id,
    name: t.name,
    shortName: t.shortName,
    description: t.description,
    services: t.services || [],
    permissions: t.permissions || [],
    detectionIds: t.detectionIds || [],
    mitigations: t.mitigations || [],
    category: t.category,
    cloudProvider: provider,
    ...(t.detectionStrategy ? { detectionStrategy: t.detectionStrategy } : {}),
  });

  if (t.commands?.length) writeJson(path.join(dir, "commands.json"), t.commands);
  if (t.references?.length) writeJson(path.join(dir, "references.json"), t.references);
  if (t.cloudtrailSample) {
    const trimmed = String(t.cloudtrailSample).trim();
    try {
      writeJson(path.join(dir, "sample.json"), JSON.parse(trimmed));
    } catch {
      fs.writeFileSync(path.join(dir, "sample.json"), `${trimmed}\n`);
    }
  }
}

function writePath(ap, techById, used) {
  let provider = ap.cloudProvider;
  if (!provider) {
    for (const step of ap.steps || []) {
      const tech = techById.get(step.techniqueId);
      if (tech) {
        provider = tech.cloudProvider || "aws";
        break;
      }
    }
  }
  provider = provider || "aws";
  const slug = ensureUniqueSlug(slugify(ap.slug || ap.title), used[provider]);
  const dir = path.join(ROOT, "attack-paths", provider, slug);

  writeJson(path.join(dir, "meta.json"), {
    slug: ap.slug,
    title: ap.title,
    description: ap.description,
    severity: ap.severity,
    objective: ap.objective,
    tags: ap.tags || [],
    steps: ap.steps || [],
    cloudProvider: provider,
    ...(ap.references?.length ? { references: ap.references } : {}),
  });
}

function main() {
  const { techniques, attackPaths } = exportViaTsx();
  const techById = new Map(techniques.map((t) => [t.id, t]));

  resetProviderTree(path.join(ROOT, "techniques"));
  resetProviderTree(path.join(ROOT, "attack-paths"));

  const usedTech = Object.fromEntries(PROVIDERS.map((p) => [p, new Set()]));
  const usedPath = Object.fromEntries(PROVIDERS.map((p) => [p, new Set()]));

  for (const t of techniques) writeTechnique(t, usedTech);
  for (const ap of attackPaths) writePath(ap, techById, usedPath);

  for (const provider of PROVIDERS) {
    const tCount = fs.readdirSync(path.join(ROOT, "techniques", provider)).length;
    const pCount = fs.readdirSync(path.join(ROOT, "attack-paths", provider)).length;
    if (tCount === 0) fs.writeFileSync(path.join(ROOT, "techniques", provider, ".gitkeep"), "");
    if (pCount === 0) fs.writeFileSync(path.join(ROOT, "attack-paths", provider, ".gitkeep"), "");
    console.log(`${provider}: ${tCount} techniques, ${pCount} attack paths`);
  }
}

main();
