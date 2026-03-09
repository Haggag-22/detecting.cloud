import { useState, useRef, useEffect, useCallback } from "react";
import { Bot, X, Send, Key, Trash2, Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { buildKnowledgeBase, SYSTEM_PROMPT } from "@/lib/knowledgeBase";
import ReactMarkdown from "react-markdown";
import { Link } from "react-router-dom";

type Provider = "openai" | "gemini";
type Msg = { role: "user" | "assistant" | "system"; content: string };

const PROVIDER_CONFIG: Record<Provider, { label: string; url: string; models: string[] }> = {
  openai: {
    label: "OpenAI",
    url: "https://api.openai.com/v1/chat/completions",
    models: ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo"],
  },
  gemini: {
    label: "Google Gemini",
    url: "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    models: ["gemini-2.5-flash", "gemini-2.0-flash", "gemini-1.5-flash"],
  },
};

const STORAGE_KEY = "dc-ai-config";

function loadConfig(): { provider: Provider; apiKey: string; model: string } | null {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

function saveConfig(provider: Provider, apiKey: string, model: string) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify({ provider, apiKey, model }));
}

function clearConfig() {
  localStorage.removeItem(STORAGE_KEY);
}

// Custom link renderer to handle internal links
function InternalLink({ href, children }: { href?: string; children?: React.ReactNode }) {
  if (href && (href.startsWith("/") || href.startsWith("?"))) {
    return (
      <Link to={href} className="text-primary underline underline-offset-2 hover:text-primary/80">
        {children}
      </Link>
    );
  }
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className="text-primary underline underline-offset-2 hover:text-primary/80">
      {children}
    </a>
  );
}

export function AiAssistant() {
  const [open, setOpen] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [provider, setProvider] = useState<Provider>("openai");
  const [apiKey, setApiKey] = useState("");
  const [model, setModel] = useState(PROVIDER_CONFIG.openai.models[0]);
  const [configured, setConfigured] = useState(false);
  const [messages, setMessages] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [loading, setLoading] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const knowledgeRef = useRef<string>("");

  // Load saved config on mount
  useEffect(() => {
    const saved = loadConfig();
    if (saved) {
      setProvider(saved.provider);
      setApiKey(saved.apiKey);
      setModel(saved.model);
      setConfigured(true);
    }
  }, []);

  // Build knowledge base once
  useEffect(() => {
    knowledgeRef.current = buildKnowledgeBase();
  }, []);

  // Auto-scroll
  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [messages, loading]);

  const handleSaveConfig = () => {
    if (!apiKey.trim()) return;
    saveConfig(provider, apiKey.trim(), model);
    setConfigured(true);
    setShowSettings(false);
  };

  const handleClearConfig = () => {
    clearConfig();
    setApiKey("");
    setConfigured(false);
    setMessages([]);
    setShowSettings(false);
  };

  const sendMessage = useCallback(async () => {
    const text = input.trim();
    if (!text || loading || !configured) return;

    const userMsg: Msg = { role: "user", content: text };
    const newMessages = [...messages, userMsg];
    setMessages(newMessages);
    setInput("");
    setLoading(true);

    const systemMsg: Msg = {
      role: "system",
      content: SYSTEM_PROMPT + knowledgeRef.current,
    };

    const config = PROVIDER_CONFIG[provider];

    try {
      const res = await fetch(config.url, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${apiKey}`,
        },
        body: JSON.stringify({
          model,
          messages: [systemMsg, ...newMessages],
          temperature: 0.3,
          max_tokens: 1500,
        }),
      });

      if (!res.ok) {
        const errText = await res.text();
        throw new Error(`API error ${res.status}: ${errText.substring(0, 200)}`);
      }

      const data = await res.json();
      const content = data.choices?.[0]?.message?.content || "No response received.";
      setMessages((prev) => [...prev, { role: "assistant", content }]);
    } catch (err: any) {
      setMessages((prev) => [
        ...prev,
        { role: "assistant", content: `⚠️ Error: ${err.message || "Failed to get response. Check your API key and try again."}` },
      ]);
    } finally {
      setLoading(false);
    }
  }, [input, loading, configured, messages, provider, apiKey, model]);

  if (!open) {
    return (
      <button
        onClick={() => setOpen(true)}
        className="fixed bottom-6 right-6 z-50 flex items-center gap-2 rounded-full bg-primary px-4 py-3 text-primary-foreground shadow-lg hover:bg-primary/90 transition-all hover:scale-105"
        aria-label="Open AI Assistant"
      >
        <Bot className="h-5 w-5" />
        <span className="text-sm font-medium hidden sm:inline">AI Assistant</span>
      </button>
    );
  }

  return (
    <div className="fixed bottom-6 right-6 z-50 flex flex-col w-[400px] max-w-[calc(100vw-2rem)] h-[600px] max-h-[calc(100vh-6rem)] rounded-xl border border-border bg-card shadow-2xl overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-border bg-muted/50">
        <div className="flex items-center gap-2">
          <Bot className="h-4 w-4 text-primary" />
          <span className="font-semibold text-sm">AI Assistant</span>
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-muted-foreground hover:text-foreground"
            onClick={() => setShowSettings(!showSettings)}
          >
            <Key className="h-3.5 w-3.5" />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            className="h-7 w-7 text-muted-foreground hover:text-foreground"
            onClick={() => setOpen(false)}
          >
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>
      </div>

      {/* Settings panel */}
      {showSettings && (
        <div className="p-4 border-b border-border bg-muted/30 space-y-3">
          <div>
            <label className="text-xs text-muted-foreground uppercase tracking-wider block mb-1.5">Provider</label>
            <div className="flex gap-2">
              {(Object.keys(PROVIDER_CONFIG) as Provider[]).map((p) => (
                <button
                  key={p}
                  onClick={() => {
                    setProvider(p);
                    setModel(PROVIDER_CONFIG[p].models[0]);
                  }}
                  className={`flex-1 px-3 py-1.5 rounded-md text-xs font-medium border transition-colors ${
                    provider === p
                      ? "bg-primary/10 border-primary/30 text-primary"
                      : "bg-muted border-border text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {PROVIDER_CONFIG[p].label}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="text-xs text-muted-foreground uppercase tracking-wider block mb-1.5">Model</label>
            <select
              value={model}
              onChange={(e) => setModel(e.target.value)}
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-xs outline-none focus:border-primary/50"
            >
              {PROVIDER_CONFIG[provider].models.map((m) => (
                <option key={m} value={m}>{m}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-muted-foreground uppercase tracking-wider block mb-1.5">API Key</label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              placeholder={`Enter your ${PROVIDER_CONFIG[provider].label} API key`}
              className="w-full rounded-md border border-border bg-background px-3 py-1.5 text-xs outline-none focus:border-primary/50"
            />
          </div>
          <div className="flex gap-2">
            <Button size="sm" className="flex-1 text-xs bg-primary hover:bg-primary/90" onClick={handleSaveConfig} disabled={!apiKey.trim()}>
              Save & Connect
            </Button>
            {configured && (
              <Button size="sm" variant="outline" className="text-xs border-destructive/30 text-destructive hover:bg-destructive/10" onClick={handleClearConfig}>
                <Trash2 className="h-3 w-3 mr-1" /> Clear
              </Button>
            )}
          </div>
          <p className="text-[10px] text-muted-foreground leading-relaxed">
            Your API key is stored locally in your browser and sent directly to the provider. We never see or store your key.
          </p>
        </div>
      )}

      {/* Messages */}
      <div ref={scrollRef} className="flex-1 overflow-y-auto p-4 space-y-4">
        {!configured && !showSettings && (
          <div className="flex flex-col items-center justify-center h-full text-center px-4 gap-3">
            <Bot className="h-10 w-10 text-muted-foreground" />
            <p className="text-sm text-muted-foreground">
              Connect your AI provider to start asking questions about cloud attacks, techniques, and detection rules.
            </p>
            <Button size="sm" className="bg-primary hover:bg-primary/90 text-xs" onClick={() => setShowSettings(true)}>
              <Key className="h-3.5 w-3.5 mr-1.5" /> Configure API Key
            </Button>
          </div>
        )}

        {configured && messages.length === 0 && !showSettings && (
          <div className="flex flex-col items-center justify-center h-full text-center px-4 gap-3">
            <Bot className="h-10 w-10 text-primary/60" />
            <p className="text-sm text-muted-foreground">
              Ask me about AWS attack techniques, detection rules, or attack paths on this platform.
            </p>
            <div className="flex flex-col gap-1.5 w-full">
              {[
                "How can attackers abuse IAM PassRole?",
                "What detections cover S3 exfiltration?",
                "Show me privilege escalation attack paths",
              ].map((q) => (
                <button
                  key={q}
                  onClick={() => { setInput(q); }}
                  className="text-xs text-left px-3 py-2 rounded-md border border-border/50 bg-muted/30 text-muted-foreground hover:border-primary/30 hover:text-foreground transition-colors"
                >
                  {q}
                </button>
              ))}
            </div>
          </div>
        )}

        {messages.map((msg, i) => (
          <div key={i} className={`flex ${msg.role === "user" ? "justify-end" : "justify-start"}`}>
            <div
              className={`max-w-[85%] rounded-lg px-3 py-2 text-sm ${
                msg.role === "user"
                  ? "bg-primary text-primary-foreground"
                  : "bg-muted/50 border border-border/50 text-foreground"
              }`}
            >
              {msg.role === "assistant" ? (
                <div className="prose prose-sm prose-invert max-w-none [&_p]:my-1 [&_ul]:my-1 [&_ol]:my-1 [&_li]:my-0.5 [&_h1]:text-base [&_h2]:text-sm [&_h3]:text-sm [&_h1]:my-2 [&_h2]:my-1.5 [&_h3]:my-1 [&_code]:text-xs [&_code]:bg-muted [&_code]:px-1 [&_code]:rounded">
                  <ReactMarkdown components={{ a: InternalLink as any }}>
                    {msg.content}
                  </ReactMarkdown>
                </div>
              ) : (
                <p>{msg.content}</p>
              )}
            </div>
          </div>
        ))}

        {loading && (
          <div className="flex justify-start">
            <div className="bg-muted/50 border border-border/50 rounded-lg px-3 py-2">
              <Loader2 className="h-4 w-4 animate-spin text-primary" />
            </div>
          </div>
        )}
      </div>

      {/* Input */}
      {configured && (
        <div className="p-3 border-t border-border bg-muted/30">
          <div className="flex gap-2">
            <input
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !e.shiftKey && sendMessage()}
              placeholder="Ask about cloud attacks..."
              disabled={loading}
              className="flex-1 rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:border-primary/50 transition-colors disabled:opacity-50"
            />
            <Button
              size="icon"
              className="bg-primary hover:bg-primary/90 shrink-0"
              onClick={sendMessage}
              disabled={loading || !input.trim()}
            >
              <Send className="h-4 w-4" />
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
