// Runs before `vite dev` and `vite build` (predev/prebuild hooks); writes public/sitemap.xml.
import { writeFileSync, readFileSync } from "fs";
import { resolve } from "path";

const BASE_URL = "https://detecting.cloud";

interface SitemapEntry {
  path: string;
  changefreq?: "always" | "hourly" | "daily" | "weekly" | "monthly" | "yearly" | "never";
  priority?: string;
}

const staticEntries: SitemapEntry[] = [
  { path: "/", changefreq: "weekly", priority: "1.0" },
  { path: "/attack-paths", changefreq: "weekly", priority: "0.9" },
  { path: "/techniques", changefreq: "weekly", priority: "0.9" },
  { path: "/detection-engineering", changefreq: "weekly", priority: "0.9" },
  { path: "/attack-graph", changefreq: "monthly", priority: "0.7" },
  { path: "/coverage", changefreq: "weekly", priority: "0.7" },
  { path: "/threat-matrix", changefreq: "weekly", priority: "0.7" },
  { path: "/simulator", changefreq: "monthly", priority: "0.7" },
  { path: "/cloudtrail-analyzer", changefreq: "monthly", priority: "0.6" },
  { path: "/community-rules", changefreq: "weekly", priority: "0.6" },
  { path: "/about", changefreq: "yearly", priority: "0.5" },
];

// Technique detail routes: ids declared in the techniques data files.
function techniqueEntries(): SitemapEntry[] {
  const ids = new Set<string>();
  for (const file of ["src/data/techniques.ts"]) {
    let source = "";
    try {
      source = readFileSync(resolve(file), "utf8");
    } catch {
      continue;
    }
    for (const match of source.matchAll(/id:\s*"(tech-[a-z0-9-]+)"/g)) ids.add(match[1]);
  }
  return [...ids].map((id) => ({
    path: `/attack-paths/technique/${id}`,
    changefreq: "monthly" as const,
    priority: "0.8",
  }));
}

function generateSitemap(entries: SitemapEntry[]) {
  const urls = entries.map((e) =>
    [
      `  <url>`,
      `    <loc>${BASE_URL}${e.path}</loc>`,
      e.changefreq ? `    <changefreq>${e.changefreq}</changefreq>` : null,
      e.priority ? `    <priority>${e.priority}</priority>` : null,
      `  </url>`,
    ]
      .filter(Boolean)
      .join("\n"),
  );

  return [
    `<?xml version="1.0" encoding="UTF-8"?>`,
    `<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`,
    ...urls,
    `</urlset>`,
  ].join("\n");
}

const entries = [...staticEntries, ...techniqueEntries()];
writeFileSync(resolve("public/sitemap.xml"), generateSitemap(entries));
console.log(`sitemap.xml written (${entries.length} entries)`);
