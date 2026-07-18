import { useState } from "react";
import {
  Sidebar,
  SidebarContent,
  SidebarHeader,
  SidebarInput,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupLabel,
  SidebarGroupContent,
} from "@/components/ui/sidebar";
import {
  Search,
  Crosshair,
  ShieldCheck,
  Bug,
  Route,
  Network as NetworkIcon,
  BarChart3,
  LayoutGrid,
  FileJson,
  Github,
  Play,
  Home,
} from "lucide-react";
import { Link, useLocation } from "react-router-dom";
import { attackPaths } from "@/data/attackPaths";
import { techniques } from "@/data/techniques";
import { detections } from "@/data/detections";
import { LucideIcon } from "lucide-react";
import { ThemeToggle } from "@/components/ThemeToggle";
import logoImg from "@/assets/logo.png";

interface SidebarSection {
  key: string;
  label: string;
  icon?: LucideIcon;
  to: string;
}

interface SidebarNavStructure {
  home: SidebarSection;
  redTeam: SidebarSection[];
  blueTeam: SidebarSection[];
}

function buildSidebarNav(): SidebarNavStructure {
  const home: SidebarSection = {
    key: "home",
    label: "Home",
    icon: Home,
    to: "/",
  };

  const redTeam: SidebarSection[] = [
    {
      key: "attack-paths",
      label: "Attack Paths",
      icon: Crosshair,
      to: "/attack-paths",
    },
    {
      key: "techniques",
      label: "Techniques Library",
      icon: Route,
      to: "/techniques",
    },
    {
      key: "attack-graph",
      label: "Attack Graph",
      icon: NetworkIcon,
      to: "/attack-graph",
    },
    {
      key: "simulator",
      label: "Attack Simulator",
      icon: Play,
      to: "/simulator",
    },
    {
      key: "threat-matrix",
      label: "Threat Matrix",
      icon: LayoutGrid,
      to: "/threat-matrix",
    },
  ];

  const blueTeam: SidebarSection[] = [
    {
      key: "detections",
      label: "Detection Rules",
      icon: ShieldCheck,
      to: "/detection-engineering",
    },
    {
      key: "coverage",
      label: "Detection Coverage",
      icon: BarChart3,
      to: "/coverage",
    },
    {
      key: "cloudtrail-analyzer",
      label: "CloudTrail Analyzer",
      icon: FileJson,
      to: "/cloudtrail-analyzer",
    },
    {
      key: "community-rules",
      label: "Community Rules",
      icon: Bug,
      to: "/community-rules",
    },
  ];

  return { home, redTeam, blueTeam };
}

function renderNavLink(section: SidebarSection, location: { pathname: string }) {
  const isActive =
    section.to === "/"
      ? location.pathname === "/"
      : location.pathname.startsWith(section.to);

  return (
    <div className="px-2 py-0.5">
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton asChild tooltip={section.label} isActive={isActive} className="text-sm font-medium">
            <Link to={section.to}>
              {section.icon && <section.icon className="h-4 w-4" />}
              <span className="flex-1">{section.label}</span>
            </Link>
          </SidebarMenuButton>
        </SidebarMenuItem>
      </SidebarMenu>
    </div>
  );
}

export function AppSidebar() {
  const location = useLocation();
  const currentPath = location.pathname + location.search;
  const nav = buildSidebarNav();
  const [search, setSearch] = useState("");

  const allSearchItems: { label: string; to: string; type: string }[] = [];
  attackPaths.forEach((ap) => allSearchItems.push({ label: ap.title, to: `/attack-paths?technique=${ap.slug}`, type: "Attack Path" }));
  techniques.forEach((t) => allSearchItems.push({ label: t.name, to: `/attack-paths/technique/${t.id}`, type: "Technique" }));
  detections.forEach((d) => allSearchItems.push({ label: d.title, to: `/detection-engineering?rule=${d.id}`, type: "Detection" }));
  allSearchItems.push({ label: "CloudTrail Analyzer", to: "/cloudtrail-analyzer", type: "Tool" });
  allSearchItems.push({ label: "Threat Matrix", to: "/threat-matrix", type: "Tool" });

  const searchResults = search.trim()
    ? allSearchItems.filter((item) => item.label.toLowerCase().includes(search.toLowerCase()))
    : [];

  return (
    <Sidebar collapsible="icon" className="border-r border-border/50">
      <SidebarHeader className="p-4 space-y-4">
        <Link to="/" className="flex items-center gap-2.5 group-data-[collapsible=icon]:justify-center">
          <img src={logoImg} alt="Detecting.Cloud logo" className="h-8 w-8 rounded-lg shrink-0" />
          <span className="font-display font-bold text-base tracking-tight group-data-[collapsible=icon]:hidden">
            Detecting<span className="text-primary">.Cloud</span>
          </span>
        </Link>

        <div className="relative group-data-[collapsible=icon]:hidden">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <SidebarInput
            placeholder="Search..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8 h-8 text-sm"
          />
        </div>
      </SidebarHeader>

      <SidebarContent className="overflow-y-auto will-change-scroll" style={{ overscrollBehavior: "contain" }}>
        {search.trim() && (
          <div className="px-2 pb-2">
            {searchResults.length === 0 ? (
              <p className="text-sm text-muted-foreground px-2 py-3">No results found</p>
            ) : (
              <SidebarMenu>
                {searchResults.slice(0, 15).map((item) => (
                  <SidebarMenuItem key={item.to}>
                    <SidebarMenuButton asChild isActive={currentPath === item.to}>
                      <Link to={item.to} onClick={() => setSearch("")}>
                        <span className="text-xs text-muted-foreground shrink-0 w-16">{item.type}</span>
                        <span className="truncate text-sm">{item.label}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            )}
          </div>
        )}

        {!search.trim() && (
          <>
            {renderNavLink(nav.home, location)}
            <SidebarGroup className="border-l-2 border-red-500/25 pl-1.5 py-1">
              <SidebarGroupLabel className="text-[10px] font-bold uppercase tracking-wider text-red-400/90">
                Red team
              </SidebarGroupLabel>
              <SidebarGroupContent className="space-y-0">
                {nav.redTeam.map((section) => (
                  <div key={section.key}>{renderNavLink(section, location)}</div>
                ))}
              </SidebarGroupContent>
            </SidebarGroup>
            <SidebarGroup className="border-l-2 border-blue-500/25 pl-1.5 py-1">
              <SidebarGroupLabel className="text-[10px] font-bold uppercase tracking-wider text-blue-400/90">
                Blue team
              </SidebarGroupLabel>
              <SidebarGroupContent className="space-y-0">
                {nav.blueTeam.map((section) => (
                  <div key={section.key}>{renderNavLink(section, location)}</div>
                ))}
              </SidebarGroupContent>
            </SidebarGroup>
          </>
        )}
      </SidebarContent>

      <SidebarFooter className="p-3 border-t border-border/50">
        <div className="flex items-center justify-between group-data-[collapsible=icon]:justify-center">
          <ThemeToggle />
          <div className="flex items-center gap-1 group-data-[collapsible=icon]:hidden">
            <a
              href="https://github.com/Haggag-22/detecting.cloud"
              target="_blank"
              rel="noopener noreferrer"
              className="p-1.5 rounded-md text-muted-foreground hover:text-foreground transition-colors"
            >
              <Github className="h-4 w-4" />
            </a>
          </div>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}
