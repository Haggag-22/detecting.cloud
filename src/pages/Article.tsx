import { useParams, Link } from "react-router-dom";
import { Layout } from "@/components/Layout";
import { researchPosts } from "@/data/research";
import { Badge } from "@/components/ui/badge";
import { ArrowLeft, Clock, Calendar, User } from "lucide-react";
import { renderCodeWithColoredKeys } from "@/lib/codeHighlight";

const ArticlePage = () => {
  const { slug } = useParams();
  const post = researchPosts.find((p) => p.slug === slug);

  if (!post) {
    return (
      <Layout>
        <div className="container py-24 text-center">
          <h1 className="text-2xl font-bold mb-4">Article not found</h1>
          <Link to="/research" className="text-primary hover:underline">← Back to Research</Link>
        </div>
      </Layout>
    );
  }

  // Extract headings for TOC
  const headings = post.content.match(/^##\s+(.+)$/gm)?.map((h) => {
    const text = h.replace(/^##\s+/, "");
    const id = text.toLowerCase().replace(/[^a-z0-9]+/g, "-");
    return { text, id };
  }) || [];

  // Render content with code blocks
  const renderContent = (content: string) => {
    const parts = content.split(/(```[\s\S]*?```)/g);
    return parts.map((part, i) => {
      if (part.startsWith("```")) {
        const lines = part.split("\n");
        const lang = lines[0].replace("```", "").trim();
        const code = lines.slice(1, -1).join("\n");
        return (
          <div key={i} className="my-4 rounded-lg border border-border overflow-hidden">
            {lang && (
              <div className="px-4 py-1.5 bg-muted text-xs text-muted-foreground font-mono border-b border-border">
                {lang}
              </div>
            )}
            <pre className="p-4 overflow-x-auto bg-muted/50 text-sm font-mono leading-relaxed">
              {["json", "yaml", "hcl"].includes(lang)
                ? renderCodeWithColoredKeys(code, lang)
                : <code>{code}</code>}
            </pre>
          </div>
        );
      }
      // Render markdown-like text
      const lines = part.split("\n");
      return (
        <div key={i}>
          {lines.map((line, j) => {
            if (line.startsWith("## ")) {
              const text = line.replace("## ", "");
              const id = text.toLowerCase().replace(/[^a-z0-9]+/g, "-");
              return <h2 key={j} id={id} className="text-xl font-bold mt-8 mb-4 scroll-mt-24">{text}</h2>;
            }
            if (line.startsWith("### ")) {
              return <h3 key={j} className="text-lg font-semibold mt-6 mb-3">{line.replace("### ", "")}</h3>;
            }
            if (line.startsWith("1. ") || line.startsWith("2. ") || line.startsWith("3. ") || line.startsWith("4. ") || line.startsWith("5. ")) {
              return <li key={j} className="ml-4 text-muted-foreground list-decimal mb-1">{line.replace(/^\d+\.\s/, "")}</li>;
            }
            if (line.trim() === "") return <div key={j} className="h-2" />;
            // Inline code
            const rendered = line.replace(/`([^`]+)`/g, '<code class="px-1.5 py-0.5 rounded bg-muted text-primary text-sm font-mono">$1</code>');
            return <p key={j} className="text-muted-foreground leading-relaxed mb-2" dangerouslySetInnerHTML={{ __html: rendered }} />;
          })}
        </div>
      );
    });
  };

  return (
    <Layout>
      <div className="container py-12">
        <Link to="/research" className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground mb-8">
          <ArrowLeft className="h-4 w-4" /> Back to Research
        </Link>

        <div className="flex gap-12">
          {/* TOC */}
          {headings.length > 0 && (
            <aside className="hidden xl:block w-56 shrink-0">
              <div className="sticky top-24">
                <h4 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-3">On this page</h4>
                <nav className="space-y-1.5">
                  {headings.map((h) => (
                    <a key={h.id} href={`#${h.id}`} className="block text-sm text-muted-foreground hover:text-foreground transition-colors">
                      {h.text}
                    </a>
                  ))}
                </nav>
              </div>
            </aside>
          )}

          {/* Content */}
          <article className="flex-1 min-w-0 max-w-3xl">
            <Badge className="mb-4 bg-primary/10 text-primary border-0">{post.category}</Badge>
            <h1 className="font-display text-3xl md:text-4xl font-bold mb-4">{post.title}</h1>
            <div className="flex flex-wrap gap-4 text-sm text-muted-foreground mb-8">
              <span className="flex items-center gap-1"><User className="h-3.5 w-3.5" />{post.author}</span>
              <span className="flex items-center gap-1"><Calendar className="h-3.5 w-3.5" />{post.date}</span>
              <span className="flex items-center gap-1"><Clock className="h-3.5 w-3.5" />{post.readTime}</span>
            </div>

            <div className="prose-custom">
              {renderContent(post.content)}
            </div>

            {/* Detection Ideas */}
            <section className="mt-12 rounded-lg border border-border p-6 bg-card">
              <h2 className="font-display font-bold text-lg mb-4">Detection Ideas</h2>
              <ul className="space-y-2">
                {post.detectionIdeas.map((idea, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                    <span className="text-primary mt-1">•</span> {idea}
                  </li>
                ))}
              </ul>
            </section>

            {/* Mitigations */}
            <section className="mt-4 rounded-lg border border-border p-6 bg-card">
              <h2 className="font-display font-bold text-lg mb-4">Mitigation Strategies</h2>
              <ul className="space-y-2">
                {post.mitigations.map((m, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-muted-foreground">
                    <span className="text-primary mt-1">•</span> {m}
                  </li>
                ))}
              </ul>
            </section>

            {/* References */}
            <section className="mt-4 rounded-lg border border-border p-6 bg-card">
              <h2 className="font-display font-bold text-lg mb-4">References</h2>
              <ul className="space-y-2">
                {post.references.map((ref, i) => (
                  <li key={i}>
                    <a href={ref} target="_blank" rel="noopener noreferrer" className="text-sm text-primary hover:underline break-all">{ref}</a>
                  </li>
                ))}
              </ul>
            </section>

            {/* Tags */}
            <div className="mt-8 flex flex-wrap gap-2">
              {post.tags.map((tag) => (
                <Badge key={tag} variant="outline" className="border-border text-muted-foreground">{tag}</Badge>
              ))}
            </div>
          </article>
        </div>
      </div>
    </Layout>
  );
};

export default ArticlePage;
