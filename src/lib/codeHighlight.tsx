import type { ReactNode } from "react";

/** Renders code with colored keys/fields using React elements (avoids HTML injection issues). */
export function renderCodeWithColoredKeys(content: string, language: string): ReactNode {
  const keyClass = "text-yellow-400";
  const parts: ReactNode[] = [];
  let keyIdx = 0;

  if (language === "json") {
    const keyRegex = /"([^"\\]*(\\.[^"\\]*)*)"\s*(?=:)/g;
    let lastIndex = 0;
    let m;
    while ((m = keyRegex.exec(content)) !== null) {
      parts.push(content.slice(lastIndex, m.index));
      parts.push(<span key={`k-${keyIdx++}`} className={keyClass}>"{m[1]}"</span>);
      lastIndex = m.index + m[0].length;
    }
    parts.push(content.slice(lastIndex));
    return <code>{parts}</code>;
  }

  if (language === "hcl") {
    const attrRegex = /(\b(?:resource|data|variable|output|name|description|event_pattern|source|detail-type|detail|eventName)\b)\s*(?==|\[|\()/g;
    let lastIndex = 0;
    let m;
    while ((m = attrRegex.exec(content)) !== null) {
      parts.push(content.slice(lastIndex, m.index));
      parts.push(<span key={`k-${keyIdx++}`} className={keyClass}>{m[1]}</span>);
      lastIndex = m.index + m[0].length;
    }
    parts.push(content.slice(lastIndex));
    return <code>{parts}</code>;
  }

  if (language === "yaml") {
    const keyRegex = /^(\s*)([\w.-]+)(\s*:)/gm;
    let lastIndex = 0;
    let m;
    while ((m = keyRegex.exec(content)) !== null) {
      parts.push(content.slice(lastIndex, m.index));
      parts.push(m[1], <span key={`k-${keyIdx++}`} className={keyClass}>{m[2]}</span>, m[3]);
      lastIndex = m.index + m[0].length;
    }
    parts.push(content.slice(lastIndex));
    return <code>{parts}</code>;
  }

  return <code>{content}</code>;
}
