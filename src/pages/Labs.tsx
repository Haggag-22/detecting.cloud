import { Layout } from "@/components/Layout";
import { labs } from "@/data/labs";
import { Badge } from "@/components/ui/badge";
import { FlaskConical, Cloud } from "lucide-react";

const difficultyColor: Record<string, string> = {
  Beginner: "bg-green-500/10 text-green-400",
  Intermediate: "bg-amber-500/10 text-amber-400",
  Advanced: "bg-destructive/10 text-destructive",
};

const LabsPage = () => {
  return (
    <Layout>
      <div className="container py-12">
        <h1 className="font-display text-3xl font-bold mb-2">Security Labs</h1>
        <p className="text-muted-foreground mb-8">Hands-on labs for practicing cloud security techniques.</p>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {labs.map((lab) => (
            <div key={lab.slug} className="rounded-lg border border-border/50 bg-card p-6 hover:border-primary/30 transition-all">
              <div className="flex items-center gap-2 mb-3">
                <Badge className={`text-xs border-0 ${difficultyColor[lab.difficulty]}`}>{lab.difficulty}</Badge>
                <Badge variant="outline" className="text-xs border-border text-muted-foreground flex items-center gap-1">
                  <Cloud className="h-3 w-3" />{lab.provider}
                </Badge>
              </div>
              <div className="flex items-start gap-3">
                <div className="shrink-0 rounded-lg bg-gradient-subtle p-2.5 mt-0.5">
                  <FlaskConical className="h-5 w-5 text-primary" />
                </div>
                <div>
                  <h3 className="font-semibold mb-1">{lab.title}</h3>
                  <p className="text-sm text-muted-foreground">{lab.description}</p>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </Layout>
  );
};

export default LabsPage;
