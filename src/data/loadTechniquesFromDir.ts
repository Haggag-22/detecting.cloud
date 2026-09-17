import type { Technique } from "./techniqueTypes";

type TechniqueMeta = Omit<Technique, "commands" | "references" | "cloudtrailSample">;

const metaFiles = import.meta.glob("../../techniques/*/*/meta.json", {
  eager: true,
  import: "default",
}) as Record<string, TechniqueMeta>;

const commandFiles = import.meta.glob("../../techniques/*/*/commands.json", {
  eager: true,
  import: "default",
}) as Record<string, string[]>;

const referenceFiles = import.meta.glob("../../techniques/*/*/references.json", {
  eager: true,
  import: "default",
}) as Record<string, NonNullable<Technique["references"]>>;

const sampleFiles = import.meta.glob("../../techniques/*/*/sample.json", {
  eager: true,
  import: "default",
}) as Record<string, unknown>;

function dirFromMetaPath(metaPath: string): string {
  return metaPath.replace(/\/meta\.json$/, "");
}

function lookup<T>(map: Record<string, T>, dir: string, file: string): T | undefined {
  return map[`${dir}/${file}`];
}

function sampleToString(sample: unknown): string | undefined {
  if (sample == null) return undefined;
  if (typeof sample === "string") return sample;
  return JSON.stringify(sample, null, 2);
}

function providerFromPath(metaPath: string): Technique["cloudProvider"] {
  const match = metaPath.match(/techniques\/([^/]+)\//);
  const provider = match?.[1];
  if (provider === "aws" || provider === "azure" || provider === "gcp" || provider === "kubernetes") {
    return provider;
  }
  return "aws";
}

function loadTechniquesFromDir(): Technique[] {
  const loaded: Technique[] = [];

  for (const [metaPath, meta] of Object.entries(metaFiles)) {
    const dir = dirFromMetaPath(metaPath);
    const sample = lookup(sampleFiles, dir, "sample.json");
    loaded.push({
      ...meta,
      services: meta.services ?? [],
      permissions: meta.permissions ?? [],
      detectionIds: meta.detectionIds ?? [],
      mitigations: meta.mitigations ?? [],
      cloudProvider: meta.cloudProvider ?? providerFromPath(metaPath),
      commands: lookup(commandFiles, dir, "commands.json"),
      references: lookup(referenceFiles, dir, "references.json"),
      cloudtrailSample: sampleToString(sample),
    });
  }

  loaded.sort((a, b) => {
    const providerOrder = { aws: 0, azure: 1, gcp: 2, kubernetes: 3 } as const;
    const pa = providerOrder[a.cloudProvider ?? "aws"] ?? 9;
    const pb = providerOrder[b.cloudProvider ?? "aws"] ?? 9;
    if (pa !== pb) return pa - pb;
    return a.name.localeCompare(b.name);
  });

  return loaded;
}

export const techniquesFromDir: Technique[] = loadTechniquesFromDir();
