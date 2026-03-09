import { Link } from "react-router-dom";
import { type LucideIcon } from "lucide-react";

interface TopicCardProps {
  icon: LucideIcon;
  title: string;
  to: string;
}

export function TopicCard({ icon: Icon, title, to }: TopicCardProps) {
  return (
    <Link
      to={to}
      className="flex items-center gap-3 rounded-lg border border-border/50 bg-card px-4 py-3 transition-all hover:border-primary/30 hover:bg-primary/5"
    >
      <Icon className="h-4 w-4 text-primary shrink-0" />
      <span className="text-sm font-medium">{title}</span>
    </Link>
  );
}
