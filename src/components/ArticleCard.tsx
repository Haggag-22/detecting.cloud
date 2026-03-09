import { Link } from "react-router-dom";
import { Clock, Calendar } from "lucide-react";
import { Badge } from "@/components/ui/badge";

interface ArticleCardProps {
  slug: string;
  title: string;
  preview: string;
  category: string;
  readTime: string;
  date: string;
  tags: string[];
}

export function ArticleCard({ slug, title, preview, category, readTime, date, tags }: ArticleCardProps) {
  return (
    <Link
      to={`/research/${slug}`}
      className="group block rounded-lg border border-border/50 bg-card p-5 transition-all hover:border-primary/30 hover:bg-card/80"
    >
      <div className="flex items-center gap-2 mb-3">
        <Badge variant="secondary" className="text-xs bg-primary/10 text-primary border-0">{category}</Badge>
        <span className="text-xs text-muted-foreground flex items-center gap-1"><Clock className="h-3 w-3" />{readTime}</span>
        <span className="text-xs text-muted-foreground flex items-center gap-1"><Calendar className="h-3 w-3" />{date}</span>
      </div>
      <h3 className="font-display font-semibold mb-2 group-hover:text-primary transition-colors">{title}</h3>
      <p className="text-sm text-muted-foreground line-clamp-2 mb-3">{preview}</p>
      <div className="flex flex-wrap gap-1.5">
        {tags.map((tag) => (
          <Badge key={tag} variant="outline" className="text-xs border-border/50 text-muted-foreground">{tag}</Badge>
        ))}
      </div>
    </Link>
  );
}
