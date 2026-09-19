/** Top-level Sigma fields that should not appear in the blog. */
const ATTRIBUTION_LINE =
  /^(?:id|author|date|modified|updated|created|last_modified):[^\n]*\r?\n/gm;

export function stripSigmaAttribution(yaml: string): string {
  return yaml.replace(ATTRIBUTION_LINE, "").replace(/\n{3,}/g, "\n\n");
}
