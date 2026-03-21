import { useState } from "react";
import { Layout } from "@/components/Layout";
import { ArticleCard } from "@/components/ArticleCard";
import { researchPosts } from "@/data/research";
import { Badge } from "@/components/ui/badge";

const categories = ["All", "IAM Abuse", "Cloud Attacks", "Detection Rules"];

const ResearchPage = () => {
  const [activeFilter, setActiveFilter] = useState("All");

  const filtered = activeFilter === "All"
    ? researchPosts
    : researchPosts.filter((p) => p.category === activeFilter);

  return (
    <Layout>
      <div className="container py-12">
        <h1 className="font-display text-3xl font-bold mb-2">Research Library</h1>
        <p className="text-muted-foreground mb-8">In-depth cloud security research and analysis.</p>

        <div className="flex flex-col lg:flex-row gap-8">
          {/* Filters */}
          <aside className="lg:w-56 shrink-0">
            <h3 className="text-sm font-semibold mb-3 text-muted-foreground uppercase tracking-wider">Categories</h3>
            <div className="flex flex-row lg:flex-col flex-wrap gap-2">
              {categories.map((cat) => (
                <Badge
                  key={cat}
                  variant={activeFilter === cat ? "default" : "outline"}
                  className={`cursor-pointer transition-colors ${
                    activeFilter === cat
                      ? "bg-primary text-primary-foreground"
                      : "border-border text-muted-foreground hover:text-foreground"
                  }`}
                  onClick={() => setActiveFilter(cat)}
                >
                  {cat}
                </Badge>
              ))}
            </div>
          </aside>

          {/* Posts */}
          <div className="flex-1">
            <div className="grid grid-cols-1 gap-4">
              {filtered.map((post) => (
                <ArticleCard key={post.slug} {...post} />
              ))}
            </div>
            {filtered.length === 0 && (
              <p className="text-center text-muted-foreground py-12">No articles found.</p>
            )}
          </div>
        </div>
      </div>
    </Layout>
  );
};

export default ResearchPage;
