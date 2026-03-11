// Builds a structured knowledge base string from platform data for AI context

import { attackPaths, attackObjectiveLabels } from "@/data/attackPaths";
import { techniques, techniqueCategories, type TechniqueCategory } from "@/data/techniques";
import { detections } from "@/data/detections";

export function buildKnowledgeBase(): string {
  const sections: string[] = [];

  // Techniques
  sections.push("## Techniques\n");
  for (const t of techniques) {
    const cat = techniqueCategories[t.category as TechniqueCategory];
    sections.push(
      `- **${t.name}** (ID: ${t.id}, Category: ${cat?.label || t.category})\n` +
      `  Services: ${t.services.join(", ")}\n` +
      `  Permissions: ${t.permissions.join(", ")}\n` +
      `  Description: ${t.description}\n` +
      `  Mitigations: ${t.mitigations.join("; ")}\n` +
      `  Page: /attack-paths?technique=${t.id}\n`
    );
  }

  // Attack Paths
  sections.push("\n## Attack Paths\n");
  for (const ap of attackPaths) {
    const steps = ap.steps.map((s) => {
      const tech = techniques.find((t) => t.id === s.techniqueId);
      return tech ? tech.name : s.techniqueId;
    });
    sections.push(
      `- **${ap.title}** (Slug: ${ap.slug}, Severity: ${ap.severity}, Objective: ${attackObjectiveLabels[ap.objective]})\n` +
      `  Description: ${ap.description}\n` +
      `  Steps: ${steps.join(" → ")}\n` +
      `  Tags: ${ap.tags.join(", ")}\n` +
      `  Page: /attack-paths?technique=${ap.slug}\n`
    );
  }

  // Detections
  sections.push("\n## Detection Rules\n");
  for (const d of detections) {
    sections.push(
      `- **${d.title}** (ID: ${d.id}, Service: ${d.awsService}, Severity: ${d.severity})\n` +
      `  Description: ${d.description}\n` +
      `  Related Services: ${d.relatedServices.join(", ")}\n` +
      `  Log Sources: ${d.logSources.join(", ")}\n` +
      `  Tags: ${d.tags.join(", ")}\n` +
      `  Related Attack Paths: ${d.relatedAttackSlugs.join(", ")}\n` +
      `  Page: /detection-engineering?rule=${d.id}\n`
    );
  }

  return sections.join("\n");
}

export const SYSTEM_PROMPT = `You are the Detecting.Cloud AI assistant — a cloud security research assistant embedded in a platform that documents AWS attack paths, techniques, and detection rules.

RULES:
1. ONLY answer using the knowledge base provided below. Do NOT use external knowledge.
2. When referencing pages, use markdown links with the exact paths from the knowledge base.
3. Keep answers concise and actionable — focus on what the user needs.
4. When listing techniques or detections, always include links.
5. If you cannot find relevant information in the knowledge base, say so honestly.
6. Format responses with markdown: use headers, bullet points, and bold for key terms.

KNOWLEDGE BASE:
`;
