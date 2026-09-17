import type { AttackPath } from "./attackPathTypes";

type AttackPathMeta = AttackPath;

const metaFiles = import.meta.glob("../../attack-paths/*/*/meta.json", {
  eager: true,
  import: "default",
}) as Record<string, AttackPathMeta>;

function providerFromPath(metaPath: string): NonNullable<AttackPath["cloudProvider"]> {
  const match = metaPath.match(/attack-paths\/([^/]+)\//);
  const provider = match?.[1];
  if (provider === "aws" || provider === "azure" || provider === "gcp" || provider === "kubernetes") {
    return provider;
  }
  return "aws";
}

function loadAttackPathsFromDir(): AttackPath[] {
  const loaded: AttackPath[] = [];

  for (const [metaPath, meta] of Object.entries(metaFiles)) {
    loaded.push({
      ...meta,
      tags: meta.tags ?? [],
      steps: meta.steps ?? [],
      cloudProvider: meta.cloudProvider ?? providerFromPath(metaPath),
    });
  }

  loaded.sort((a, b) => {
    const providerOrder = { aws: 0, azure: 1, gcp: 2, kubernetes: 3 } as const;
    const pa = providerOrder[a.cloudProvider ?? "aws"] ?? 9;
    const pb = providerOrder[b.cloudProvider ?? "aws"] ?? 9;
    if (pa !== pb) return pa - pb;
    return a.title.localeCompare(b.title);
  });

  return loaded;
}

export const attackPathsFromDir: AttackPath[] = loadAttackPathsFromDir();
