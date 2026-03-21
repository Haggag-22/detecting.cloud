import { useState } from "react";
import { Link } from "react-router-dom";
import { Github, Twitter, Mail } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import logoImg from "@/assets/logo.png";
import { supabase } from "@/integrations/supabase/client";

export function Footer() {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);

  const handleSubscribe = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes("@")) {
      toast.error("Please enter a valid email");
      return;
    }
    setLoading(true);
    const { error } = await supabase.from("subscribers").insert({ email });
    if (error) {
      if (error.code === "23505") {
        toast.info("You're already subscribed!");
      } else {
        toast.error("Something went wrong. Please try again.");
      }
    } else {
      toast.success("Subscribed! You'll receive the latest cloud security updates.");
    }
    setEmail("");
    setLoading(false);
  };

  return (
    <footer className="border-t border-border/50 bg-card/50">
      <div className="container py-12">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-8">
          <div className="md:col-span-2">
            <Link to="/" className="flex items-center gap-2 font-display font-bold text-lg mb-3">
              <img src={logoImg} alt="Detecting.Cloud logo" className="h-8 w-8 rounded" />
              <span>Detecting<span className="text-primary">.Cloud</span></span>
            </Link>
            <p className="text-sm text-muted-foreground max-w-sm mb-4">
              Researching real-world cloud attack paths and building practical detections for defenders.
            </p>

            {/* Newsletter subscription */}
            <form onSubmit={handleSubscribe} className="flex gap-2 max-w-sm">
              <div className="relative flex-1">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  type="email"
                  placeholder="your@email.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className="pl-9 h-9 text-sm"
                />
              </div>
              <Button type="submit" size="sm" disabled={loading} className="h-9 px-4">
                Subscribe
              </Button>
            </form>
            <p className="text-xs text-muted-foreground mt-2">Get the latest cloud security research & detections.</p>

            <div className="flex gap-3 mt-4">
              <a href="https://github.com" target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-foreground transition-colors">
                <Github className="h-5 w-5" />
              </a>
              <a href="https://twitter.com" target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-foreground transition-colors">
                <Twitter className="h-5 w-5" />
              </a>
            </div>
          </div>
          <div>
            <h4 className="font-semibold text-sm mb-3">Platform</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li><Link to="/attack-paths" className="hover:text-foreground transition-colors">Attack Paths</Link></li>
              <li><Link to="/detection-engineering" className="hover:text-foreground transition-colors">Detection Rules</Link></li>
              <li><Link to="/simulator" className="hover:text-foreground transition-colors">Attack Simulator</Link></li>
              <li><Link to="/community-rules" className="hover:text-foreground transition-colors">Community Rules</Link></li>
            </ul>
          </div>
        </div>
        <div className="mt-10 pt-6 border-t border-border/50 text-center text-xs text-muted-foreground">
          © {new Date().getFullYear()} Detecting.Cloud. All rights reserved.
        </div>
      </div>
    </footer>
  );
}
