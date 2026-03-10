import { useState } from "react";
import { Dialog, DialogContent } from "@/components/ui/dialog";
import { Search } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { researchPosts } from "@/data/research";
import { attackPaths } from "@/data/attackPaths";
import { techniques } from "@/data/techniques";
import { detections } from "@/data/detections";

interface SearchDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function SearchDialog({ open, onOpenChange }: SearchDialogProps) {
  const [query, setQuery] = useState("");
  const navigate = useNavigate();

  const allItems = [
    ...researchPosts.map((p) => ({ title: p.title, description: p.preview, url: `/research/${p.slug}`, type: "Research" })),
    ...attackPaths.map((a) => ({ title: a.title, description: a.description, url: `/attack-paths?technique=${a.slug}`, type: "Attack Path" })),
    ...techniques.map((t) => ({ title: t.name, description: t.description, url: `/attack-paths/technique/${t.id}`, type: "Technique" })),
    ...detections.map((d) => ({ title: d.title, description: d.description, url: `/detection-engineering?rule=${d.id}`, type: "Detection" })),
  ];

  const filtered = query.length > 1
    ? allItems.filter((item) =>
        item.title.toLowerCase().includes(query.toLowerCase()) ||
        item.description.toLowerCase().includes(query.toLowerCase())
      )
    : [];

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg p-0 bg-card border-border">
        <div className="flex items-center gap-3 border-b border-border px-4 py-3">
          <Search className="h-4 w-4 text-muted-foreground shrink-0" />
          <input
            autoFocus
            placeholder="Search research, attack paths, detections..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            className="flex-1 bg-transparent text-sm outline-none placeholder:text-muted-foreground"
          />
        </div>
        {filtered.length > 0 && (
          <div className="max-h-72 overflow-y-auto p-2">
            {filtered.map((item, i) => (
              <button
                key={i}
                onClick={() => { navigate(item.url); onOpenChange(false); setQuery(""); }}
                className="w-full text-left px-3 py-2 rounded-md hover:bg-muted transition-colors"
              >
                <div className="text-xs text-primary mb-0.5">{item.type}</div>
                <div className="text-sm font-medium">{item.title}</div>
                <div className="text-xs text-muted-foreground line-clamp-1">{item.description}</div>
              </button>
            ))}
          </div>
        )}
        {query.length > 1 && filtered.length === 0 && (
          <div className="p-6 text-center text-sm text-muted-foreground">No results found.</div>
        )}
      </DialogContent>
    </Dialog>
  );
}
