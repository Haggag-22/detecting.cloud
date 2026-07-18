import { useMemo, useState } from "react";
import { AlertTriangle, Check, Copy, Download, Languages } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
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
import { renderCodeWithColoredKeys } from "@/lib/codeHighlight";

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
  if (format === "splunk" || format === "cloudwatch" || format === "esql") {
    const highlighted = code
      .replace(
        /\b(index|sourcetype|where|table|stats|sort|like|OR|AND|NOT|IN|by|as|fields|filter|FROM|WHERE|KEEP|SORT|SELECT|ORDER BY|DESC|ASC|count|not)\b/gi,
        '<span class="text-yellow-400">$1</span>'
      )
      .replace(/\|/g, '<span class="text-accent">|</span>');
    return <span dangerouslySetInnerHTML={{ __html: highlighted }} />;
  }
  if (format === "cloudtrail") {
    const highlighted = code.replace(
      /\b(SELECT|FROM|WHERE|AND|OR|ORDER BY|GROUP BY|HAVING|IN|LIKE|NOT|DESC|ASC|COUNT|SUM|REGEXP_LIKE)\b/gi,
      '<span class="text-yellow-400">$1</span>'
    );
    return <span dangerouslySetInnerHTML={{ __html: highlighted }} />;
  }
  if (format === "eventbridge") {
    return renderCodeWithColoredKeys(code, "json");
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
  const [target, setTarget] = useState<SigmaTargetLanguage>("esql");
  const [converted, setConverted] = useState<ConversionResult | null>(null);

  const storedRules = useMemo(
    () => ({
      sigma: rules.sigma,
      splunk: rules.splunk,
      cloudtrail: rules.cloudtrail,
      cloudwatch: rules.cloudwatch,
      eventbridge: rules.eventbridge,
      lambda: rules.lambda,
      esql: rules.esql,
      datadog: rules.datadog,
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
      <div className="flex flex-col sm:flex-row sm:items-center gap-3 justify-between">
        <div className="flex items-center gap-2 flex-wrap">
          <Badge className="bg-primary/15 text-primary border-0 text-xs">Canonical</Badge>
          <span className="text-sm font-medium">Sigma rule</span>
          <span className="text-xs text-muted-foreground">Primary detection artifact</span>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <Select value={target} onValueChange={(v) => setTarget(v as SigmaTargetLanguage)}>
            <SelectTrigger className="h-9 w-[200px] bg-muted border-border/50 text-xs">
              <SelectValue placeholder="Target language" />
            </SelectTrigger>
            <SelectContent>
              {targets.map((t) => (
                <SelectItem key={t.id} value={t.id} className="text-xs">
                  {t.label}
                  {!t.convertible ? " (stored only)" : ""}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
          <Button
            size="sm"
            className="h-9 gap-1.5 bg-primary text-primary-foreground hover:bg-primary/90"
            onClick={handleConvert}
          >
            <Languages className="h-3.5 w-3.5" />
            Convert
          </Button>
        </div>
      </div>

      {/* Sigma source */}
      <CodePanel
        title="Sigma Rule"
        subtitle="YAML"
        code={sigma}
        format="sigma"
        copiedId={copiedId}
        setCopiedId={setCopiedId}
        copyKey="sigma-primary"
        onDownload={() => downloadFile(sigma, `${detectionId}.yml`)}
        downloadLabel="Download .yml"
      />

      {/* Conversion output */}
      {converted && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-sm font-medium">{converted.label}</span>
            {converted.supported ? (
              <Badge variant="outline" className="text-[10px] border-border/70 text-muted-foreground">
                {SOURCE_LABELS[converted.source]}
              </Badge>
            ) : (
              <Badge className="text-[10px] border-0 bg-severity-medium/15 text-severity-medium">
                Unsupported
              </Badge>
            )}
          </div>

          {converted.supported && converted.query ? (
            <CodePanel
              title={converted.label}
              subtitle={converted.language}
              code={converted.query}
              format={converted.language}
              copiedId={copiedId}
              setCopiedId={setCopiedId}
              copyKey={copyKey}
              onDownload={() =>
                downloadFile(converted.query, `${detectionId}.${converted.extension}`)
              }
              downloadLabel={`Download .${converted.extension}`}
            />
          ) : (
            <div className="rounded-lg border border-border/50 bg-muted/30 px-4 py-3 text-sm text-muted-foreground">
              {converted.warnings[0] || "Conversion not available for this target."}
            </div>
          )}

          {converted.warnings.length > 0 && converted.supported && (
            <div className="rounded-lg border border-border/50 bg-muted/20 px-3 py-2 space-y-1">
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

function CodePanel({
  title,
  subtitle,
  code,
  format,
  copiedId,
  setCopiedId,
  copyKey,
  onDownload,
  downloadLabel,
}: {
  title: string;
  subtitle: string;
  code: string;
  format: string;
  copiedId: string | null;
  setCopiedId: (id: string | null) => void;
  copyKey: string;
  onDownload?: () => void;
  downloadLabel?: string;
}) {
  return (
    <div className="rounded-lg border border-border overflow-hidden">
      <div className="px-4 py-2 bg-muted text-xs text-muted-foreground font-mono border-b border-border flex items-center justify-between gap-2 flex-wrap">
        <span>
          {title}
          <span className="text-muted-foreground/70 ml-2">{subtitle}</span>
        </span>
        <div className="flex items-center gap-1">
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
      </div>
      <pre className="p-4 overflow-x-auto bg-muted/30 text-sm font-mono leading-relaxed">
        <code>{highlightCode(code, format)}</code>
      </pre>
    </div>
  );
}
