import { Link } from "react-router-dom";
import { Github, Twitter } from "lucide-react";
import logoImg from "@/assets/logo.jpeg";

export function Footer() {
  return (
    <footer className="border-t border-border/50 bg-card/50">
      <div className="container py-12">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
          <div className="md:col-span-2">
            <Link to="/" className="flex items-center gap-2 font-display font-bold text-lg mb-3">
              <Shield className="h-5 w-5 text-primary" />
              <span>Detecting<span className="text-primary">.Cloud</span></span>
            </Link>
            <p className="text-sm text-muted-foreground max-w-sm">
              Researching real-world cloud attack paths and building practical detections for defenders.
            </p>
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
              <li><Link to="/research" className="hover:text-foreground transition-colors">Research</Link></li>
              <li><Link to="/attack-paths" className="hover:text-foreground transition-colors">Attack Paths</Link></li>
              <li><Link to="/detection-engineering" className="hover:text-foreground transition-colors">Detection Engineering</Link></li>
              <li><Link to="/labs" className="hover:text-foreground transition-colors">Labs</Link></li>
            </ul>
          </div>
          <div>
            <h4 className="font-semibold text-sm mb-3">Company</h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              <li><Link to="/about" className="hover:text-foreground transition-colors">About</Link></li>
              <li><a href="mailto:contact@detecting.cloud" className="hover:text-foreground transition-colors">Contact</a></li>
              <li><Link to="/privacy" className="hover:text-foreground transition-colors">Privacy Policy</Link></li>
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
