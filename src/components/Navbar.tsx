import { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import { Search, Github, Twitter, Menu, X } from "lucide-react";
import logoImg from "@/assets/logo.png";
import { Button } from "@/components/ui/button";
import { SearchDialog } from "@/components/SearchDialog";
import { SidebarTrigger } from "@/components/ui/sidebar";
import { ThemeToggle } from "@/components/ThemeToggle";

const navLinks = [
  { label: "Home", to: "/" },
  { label: "Research", to: "/research" },
  { label: "Attack Paths", to: "/attack-paths" },
  { label: "Attack Graph", to: "/attack-graph" },
  { label: "Coverage", to: "/coverage" },
  { label: "Detection Engineering", to: "/detection-engineering" },
  { label: "About", to: "/about" },
];

export function Navbar({ showSidebarTrigger = false }: { showSidebarTrigger?: boolean }) {
  const [mobileOpen, setMobileOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const location = useLocation();

  return (
    <>
      <nav className="fixed top-0 left-0 right-0 z-50 border-b border-border/50 bg-background/80 backdrop-blur-xl">
        <div className="container flex h-16 items-center justify-between">
          <div className="flex items-center gap-2">
            {showSidebarTrigger && <SidebarTrigger className="text-muted-foreground hover:text-foreground" />}
            <Link to="/" className="flex items-center gap-2 font-display font-bold text-lg">
              <img src={logoImg} alt="Detecting.Cloud logo" className="h-8 w-8 rounded" />
              <span>Detecting<span className="text-primary">.Cloud</span></span>
            </Link>
          </div>

          <div className="hidden lg:flex items-center gap-1">
            {navLinks.map((link) => (
              <Link
                key={link.to}
                to={link.to}
                className={`px-3 py-2 text-sm rounded-md transition-colors ${
                  location.pathname === link.to
                    ? "text-primary bg-primary/10"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted"
                }`}
              >
                {link.label}
              </Link>
            ))}
          </div>

          <div className="flex items-center gap-2">
            <Button variant="ghost" size="icon" onClick={() => setSearchOpen(true)} className="text-muted-foreground hover:text-foreground">
              <Search className="h-4 w-4" />
            </Button>
            <a href="https://github.com/Haggag-22/detecting.cloud" target="_blank" rel="noopener noreferrer">
              <Button variant="ghost" size="icon" className="text-muted-foreground hover:text-foreground">
                <Github className="h-4 w-4" />
              </Button>
            </a>
            <a href="https://twitter.com" target="_blank" rel="noopener noreferrer">
              <Button variant="ghost" size="icon" className="text-muted-foreground hover:text-foreground hidden sm:flex">
                <Twitter className="h-4 w-4" />
              </Button>
            </a>
            <Button variant="ghost" size="icon" className="lg:hidden text-muted-foreground" onClick={() => setMobileOpen(!mobileOpen)}>
              {mobileOpen ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
            </Button>
          </div>
        </div>

        {mobileOpen && (
          <div className="lg:hidden border-t border-border/50 bg-background/95 backdrop-blur-xl">
            <div className="container py-4 flex flex-col gap-1">
              {navLinks.map((link) => (
                <Link
                  key={link.to}
                  to={link.to}
                  onClick={() => setMobileOpen(false)}
                  className={`px-3 py-2 text-sm rounded-md transition-colors ${
                    location.pathname === link.to
                      ? "text-primary bg-primary/10"
                      : "text-muted-foreground hover:text-foreground"
                  }`}
                >
                  {link.label}
                </Link>
              ))}
            </div>
          </div>
        )}
      </nav>

      <SearchDialog open={searchOpen} onOpenChange={setSearchOpen} />
    </>
  );
}
