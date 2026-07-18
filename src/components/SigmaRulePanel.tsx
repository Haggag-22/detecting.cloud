import { useMemo, useState } from "react";
import { AlertTriangle, Check, Copy, Download, Languages } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import type { RuleFormats } from "@/data/detections";
import {
  convertSigma,
  listConvertibleTargets,
  type ConversionResult,
  type SigmaTargetLanguage,
} from "@/lib/sigma";

function highlightCode(code: string, format: string): React.ReactNode {
  if (format === "sigma") {
    return code.split("\n").map((line, i) => {
      const highlighted = line
        .replace(/^(\s*)([\w-]+)(:)/gm, "$1<k>$2</k>$3")
        .replace(/'([^']+)'/g, "<s>'$1'</s>");
      return (
        <span key={i}>
          <span
            dangerouslySetInnerHTML={{
              __html: highlighted
                .replace(/<k>/g, '<span class="text-yellow-400">')
                .replace(/<\/k>/g, "</span>")
                .replace(/<s>/g, '<span class="text-emerald-400">')
                .replace(/<\/s>/g, "</span>"),
            }}
          />
          {"\n"}
        </span>
      );
    });
  }
  if (
    format === "splunk" ||
    format === "elasticsearch" ||
    format === "cortexxdr" ||
    format === "crowdstrike" ||
    format === "sentinelone"
  ) {
    const highlighted = code
      .replace(
        /\b(index|sourcetype|where|table|stats|sort|like|OR|AND|NOT|IN|by|as|fields|filter|FROM|WHERE|KEEP|SORT|SELECT|ORDER BY|DESC|ASC|count|not|dataset|Contains|StartsWith|EndsWith|RegExp)\b/gi,
        '<span class="text-yellow-400">$1</span>'
      )
      .replace(/\|/g, '<span class="text-accent">|</span>');
    return <span dangerouslySetInnerHTML={{ __html: highlighted }} />;
  }
  if (format === "snowflake" || format === "qradar") {
    const highlighted = code.replace(
      /\b(SELECT|FROM|WHERE|AND|OR|ORDER BY|GROUP BY|HAVING|IN|LIKE|ILIKE|NOT|DESC|ASC|COUNT|SUM|LAST|HOURS|UTF8|AS)\b/gi,
      '<span class="text-yellow-400">$1</span>'
    );
    return <span dangerouslySetInnerHTML={{ __html: highlighted }} />;
  }
  if (format === "opensearch") {
    const highlighted = code
      .replace(/\b(AND|OR|NOT)\b/g, '<span class="text-yellow-400">$1</span>')
      .replace(/([\w.]+):/g, '<span class="text-emerald-400">$1</span>:');
    return <span dangerouslySetInnerHTML={{ __html: highlighted }} />;
  }
  if (format === "datadog") {
    const highlighted = code
      .replace(/\b(source|service)\b/g, '<span class="text-yellow-400">$1</span>')
      .replace(/(@[\w.]+)/g, '<span class="text-emerald-400">$1</span>');
    return <span dangerouslySetInnerHTML={{ __html: highlighted }} />;
  }
  return code;
}

function downloadFile(content: string, filename: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

const SOURCE_LABELS: Record<ConversionResult["source"], string> = {
  converted: "Converted from Sigma",
  stored: "Curated stored query",
  hybrid: "Converted from Sigma",
};

export function SigmaRulePanel({
  sigma,
  rules,
  detectionId,
  copiedId,
  setCopiedId,
}: {
  sigma: string;
  rules: RuleFormats;
  detectionId: string;
  copiedId: string | null;
  setCopiedId: (id: string | null) => void;
}) {
  const targets = listConvertibleTargets();
  const [target, setTarget] = useState<SigmaTargetLanguage>("elasticsearch");
  const [converted, setConverted] = useState<ConversionResult | null>(null);

  // Map curated detection rule strings onto converter target ids
  const storedRules = useMemo(
    () => ({
      sigma: rules.sigma,
      splunk: rules.splunk,
      datadog: rules.datadog,
      elasticsearch: rules.esql,
    }),
    [rules]
  );

  const handleConvert = () => {
    const result = convertSigma(sigma, target, { storedRules, preferStored: false });
    setConverted(result);
  };

  const copyKey = converted ? `converted-${converted.language}` : "sigma";

  return (
    <div className="space-y-4">
      <div className="rounded-lg border border-border/60 overflow-hidden bg-card">
        <div className="flex flex-col gap-3 border-b border-border/60 px-4 py-3 sm:flex-row sm:items-center sm:justify-between">
          <div className="min-w-0">
            <p className="text-sm font-medium text-foreground">Sigma rule</p>
            <p className="text-xs text-muted-foreground">YAML</p>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <Select value={target} onValueChange={(v) => setTarget(v as SigmaTargetLanguage)}>
              <SelectTrigger className="h-8 w-[180px] bg-muted/50 border-border/50 text-xs">
                <SelectValue placeholder="Target language" />
              </SelectTrigger>
              <SelectContent>
                {targets.map((t) => (
                  <SelectItem key={t.id} value={t.id} className="text-xs">
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Button
              size="sm"
              className="h-8 gap-1.5 bg-primary text-primary-foreground hover:bg-primary/90"
              onClick={handleConvert}
            >
              <Languages className="h-3.5 w-3.5" />
              Convert
            </Button>
          </div>
        </div>

        <CodePanel
          code={sigma}
          format="sigma"
          copiedId={copiedId}
          setCopiedId={setCopiedId}
          copyKey="sigma-primary"
          onDownload={() => downloadFile(sigma, `${detectionId}.yml`)}
          downloadLabel="Download .yml"
          embedded
        />
      </div>

      {converted && (
        <div className="space-y-2">
          {converted.supported && converted.query ? (
            <div className="rounded-lg border border-border/60 overflow-hidden bg-card">
              <div className="flex items-center justify-between gap-3 border-b border-border/60 px-4 py-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-foreground">{converted.label}</p>
                  <p className="text-xs text-muted-foreground">{SOURCE_LABELS[converted.source]}</p>
                </div>
              </div>
              <CodeToolbar
                code={converted.query}
                format={converted.language}
                copiedId={copiedId}
                setCopiedId={setCopiedId}
                copyKey={copyKey}
                onDownload={() =>
                  downloadFile(converted.query, `${detectionId}.${converted.extension}`)
                }
                downloadLabel={`Download .${converted.extension}`}
                embedded
              />
            </div>
          ) : (
            <div className="rounded-lg border border-border/50 bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
              {converted.warnings[0] || "Conversion not available for this target."}
            </div>
          )}

          {converted.warnings.length > 0 && converted.supported && (
            <div className="rounded-md border border-border/40 bg-muted/15 px-3 py-2 space-y-1">
              {converted.warnings.slice(0, 4).map((w, i) => (
                <p key={i} className="text-xs text-muted-foreground flex items-start gap-1.5">
                  <AlertTriangle className="h-3 w-3 mt-0.5 text-severity-medium shrink-0" />
                  {w}
                </p>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function CodeToolbar({
  code,
  format,
  copiedId,
  setCopiedId,
  copyKey,
  onDownload,
  downloadLabel,
  embedded = false,
}: {
  code: string;
  format: string;
  copiedId: string | null;
  setCopiedId: (id: string | null) => void;
  copyKey: string;
  onDownload?: () => void;
  downloadLabel?: string;
  embedded?: boolean;
}) {
  return (
    <div className={embedded ? "" : "rounded-lg border border-border/60 overflow-hidden bg-card"}>
      <div className="flex items-center justify-end gap-1 border-b border-border/40 bg-muted/40 px-3 py-1.5">
        {onDownload && (
          <Button
            variant="ghost"
            size="sm"
            className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
            onClick={onDownload}
          >
            <Download className="h-3 w-3 mr-1" />
            {downloadLabel ?? "Download"}
          </Button>
        )}
        <Button
          variant="ghost"
          size="sm"
          className="h-7 px-2 text-xs text-muted-foreground hover:text-foreground"
          onClick={() => {
            navigator.clipboard.writeText(code);
            setCopiedId(copyKey);
            setTimeout(() => setCopiedId(null), 2000);
          }}
        >
          {copiedId === copyKey ? (
            <>
              <Check className="h-3 w-3 mr-1" /> Copied
            </>
          ) : (
            <>
              <Copy className="h-3 w-3 mr-1" /> Copy
            </>
          )}
        </Button>
      </div>
      <pre className="max-h-[28rem] overflow-auto bg-muted/20 p-4 text-[13px] font-mono leading-relaxed">
        <code>{highlightCode(code, format)}</code>
      </pre>
    </div>
  );
}
