import { useState, useEffect } from "react";
import {
  Sidebar,
  SidebarContent,
  SidebarHeader,
  SidebarInput,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarMenuSub,
  SidebarMenuSubItem,
  SidebarMenuSubButton,
} from "@/components/ui/sidebar";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Shield,
  KeyRound,
  TrendingUp,
  Server,
  Network,
  Database,
  Search,
  Crosshair,
  FlaskConical,
  ShieldCheck,
  FileText,
  Eye,
  Zap,
  AlertTriangle,
  Lock,
  ChevronRight,
  BookOpen,
  ExternalLink,
  Bug,
} from "lucide-react";
import { Link, useLocation } from "react-router-dom";
import { attackPaths, attackPathCategories } from "@/data/attackPaths";
import { detections } from "@/data/detections";
import { researchPosts } from "@/data/research";
import { labs } from "@/data/labs";
import { LucideIcon } from "lucide-react";

// Persist expanded sections in sessionStorage
const STORAGE_KEY = "sidebar-expanded";

function getPersistedState(): Record<string, boolean> {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : {};
  } catch {
    return {};
  }
}

function persistState(state: Record<string, boolean>) {
  sessionStorage.setItem(STORAGE_KEY, JSON.stringify(state));
}

interface SidebarSection {
  key: string;
  label: string;
  icon: LucideIcon;
  to?: string;
  children?: {
    key: string;
    label: string;
    icon: LucideIcon;
    to?: string;
    children?: { label: string; to: string }[];
  }[];
}

const categoryIcons: Record<string, LucideIcon> = {
  "iam-abuse": KeyRound,
  "privilege-escalation": TrendingUp,
  "persistence": Server,
  "lateral-movement": Network,
  "data-exfiltration": Database,
};

const detectionTypeIcons: Record<string, LucideIcon> = {
  Sigma: Eye,
  CloudTrail: Search,
  Splunk: Zap,
  SIEM: AlertTriangle,
};

function buildSections(): SidebarSection[] {
  // Build Attack Paths section with nested categories → techniques
  const attackCategories = Object.entries(attackPathCategories).map(([catKey, catMeta]) => {
    const techniques = attackPaths
      .filter((ap) => ap.category === catKey)
      .map((ap) => ({ label: ap.title, to: `/attack-paths?technique=${ap.slug}` }));
    return {
      key: `ap-${catKey}`,
      label: catMeta.label,
      icon: categoryIcons[catKey] || Crosshair,
      children: techniques.length > 0 ? techniques : undefined,
    };
  });

  // Build Detection Engineering section by type
  const detectionTypes = Array.from(new Set(detections.map((d) => d.type)));
  const detectionCategories = detectionTypes.map((type) => {
    const rules = detections
      .filter((d) => d.type === type)
      .map((d) => ({ label: d.title, to: `/detection-engineering?rule=${d.id}` }));
    return {
      key: `det-${type}`,
      label: `${type} Rules`,
      icon: detectionTypeIcons[type] || ShieldCheck,
      children: rules,
    };
  });

  return [
    {
      key: "research",
      label: "Research",
      icon: FileText,
      to: "/research",
      children: researchPosts.map((p) => ({
        key: `res-${p.slug}`,
        label: p.title,
        icon: BookOpen,
        to: undefined,
        children: [{ label: p.title, to: `/research/${p.slug}` }],
      })).length > 0
        ? [
            {
              key: "res-all",
              label: "All Articles",
              icon: FileText,
              to: "/research",
            },
            ...researchPosts.slice(0, 6).map((p) => ({
              key: `res-${p.slug}`,
              label: p.title.length > 35 ? p.title.substring(0, 35) + "…" : p.title,
              icon: BookOpen,
              to: `/research/${p.slug}`,
            })),
          ]
        : undefined,
    },
    {
      key: "attack-paths",
      label: "Attack Paths",
      icon: Crosshair,
      to: "/attack-paths",
      children: [
        { key: "ap-all", label: "All Attack Paths", icon: Crosshair, to: "/attack-paths" },
        ...attackCategories,
      ],
    },
    {
      key: "detections",
      label: "Detection Engineering",
      icon: ShieldCheck,
      to: "/detection-engineering",
      children: [
        { key: "det-all", label: "All Detections", icon: ShieldCheck, to: "/detection-engineering" },
        ...detectionCategories,
      ],
    },
    {
      key: "labs",
      label: "Labs",
      icon: FlaskConical,
      to: "/labs",
      children: [
        { key: "lab-all", label: "All Labs", icon: FlaskConical, to: "/labs" },
        ...labs.map((l) => ({
          key: `lab-${l.slug}`,
          label: l.title,
          icon: Lock,
          to: `/labs?lab=${l.slug}`,
        })),
      ],
    },
    {
      key: "attack-graph",
      label: "Attack Graph",
      icon: Network,
      to: "/attack-graph",
      children: [
        { key: "graph-full", label: "Full Graph", icon: Network, to: "/attack-graph" },
      ],
    },
    {
      key: "resources",
      label: "Resources",
      icon: ExternalLink,
      children: [
        { key: "res-about", label: "About", icon: Bug, to: "/about" },
      ],
    },
  ];
}

export function AppSidebar() {
  const location = useLocation();
  const currentPath = location.pathname + location.search;
  const sections = buildSections();

  const [expanded, setExpanded] = useState<Record<string, boolean>>(() => {
    const persisted = getPersistedState();
    // Default: expand the section matching current path
    const defaults: Record<string, boolean> = {};
    sections.forEach((s) => {
      if (s.to && location.pathname.startsWith(s.to)) {
        defaults[s.key] = true;
      }
    });
    return { ...defaults, ...persisted };
  });

  useEffect(() => {
    persistState(expanded);
  }, [expanded]);

  const toggleSection = (key: string) => {
    setExpanded((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const [search, setSearch] = useState("");

  // Flatten all items for search
  const allSearchItems: { label: string; to: string; type: string }[] = [];
  attackPaths.forEach((ap) => allSearchItems.push({ label: ap.title, to: `/attack-paths?technique=${ap.slug}`, type: "Attack Path" }));
  detections.forEach((d) => allSearchItems.push({ label: d.title, to: `/detection-engineering?rule=${d.id}`, type: "Detection" }));
  researchPosts.forEach((p) => allSearchItems.push({ label: p.title, to: `/research/${p.slug}`, type: "Research" }));
  labs.forEach((l) => allSearchItems.push({ label: l.title, to: `/labs?lab=${l.slug}`, type: "Lab" }));

  const searchResults = search.trim()
    ? allSearchItems.filter((item) => item.label.toLowerCase().includes(search.toLowerCase()))
    : [];

  return (
    <Sidebar collapsible="icon" className="border-r border-sidebar-border">
      <SidebarHeader className="p-3 space-y-3">
        <Link to="/" className="flex items-center gap-2 font-display font-bold text-sm">
          <Shield className="h-4 w-4 shrink-0 text-primary" />
          <span className="truncate">
            Detecting<span className="text-primary">.Cloud</span>
          </span>
        </Link>
        <div className="relative group-data-[collapsible=icon]:hidden">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <SidebarInput
            placeholder="Search techniques..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-8 h-8 text-xs"
          />
        </div>
      </SidebarHeader>

      <SidebarContent className="overflow-y-auto">
        {/* Search results */}
        {search.trim() && (
          <div className="px-2 pb-2">
            {searchResults.length === 0 ? (
              <p className="text-xs text-muted-foreground px-2 py-3">No results found</p>
            ) : (
              <SidebarMenu>
                {searchResults.slice(0, 15).map((item) => (
                  <SidebarMenuItem key={item.to}>
                    <SidebarMenuButton asChild isActive={currentPath === item.to}>
                      <Link to={item.to} onClick={() => setSearch("")}>
                        <span className="text-xs text-muted-foreground shrink-0 w-16">{item.type}</span>
                        <span className="truncate text-xs">{item.label}</span>
                      </Link>
                    </SidebarMenuButton>
                  </SidebarMenuItem>
                ))}
              </SidebarMenu>
            )}
          </div>
        )}

        {/* Main navigation (hidden during search) */}
        {!search.trim() &&
          sections.map((section) => (
            <div key={section.key} className="px-2 py-0.5">
              <Collapsible
                open={expanded[section.key] ?? false}
                onOpenChange={() => toggleSection(section.key)}
              >
                <SidebarMenu>
                  <SidebarMenuItem>
                    <CollapsibleTrigger asChild>
                      <SidebarMenuButton
                        tooltip={section.label}
                        className="font-medium text-xs uppercase tracking-wider text-muted-foreground hover:text-foreground"
                      >
                        <section.icon className="h-4 w-4" />
                        <span className="flex-1">{section.label}</span>
                        <ChevronRight
                          className={`h-3.5 w-3.5 transition-transform duration-200 ${
                            expanded[section.key] ? "rotate-90" : ""
                          }`}
                        />
                      </SidebarMenuButton>
                    </CollapsibleTrigger>

                    <CollapsibleContent>
                      {section.children && (
                        <SidebarMenuSub>
                          {section.children.map((child) =>
                            child.children && child.children.length > 0 ? (
                              // Nested collapsible (e.g., category → techniques)
                              <NestedCollapsible
                                key={child.key}
                                item={child}
                                currentPath={currentPath}
                                expanded={expanded}
                                toggleSection={toggleSection}
                              />
                            ) : (
                              <SidebarMenuSubItem key={child.key}>
                                <SidebarMenuSubButton
                                  asChild
                                  isActive={child.to === currentPath}
                                  size="sm"
                                >
                                  <Link to={child.to || "#"}>
                                    <child.icon className="h-3.5 w-3.5" />
                                    <span>{child.label}</span>
                                  </Link>
                                </SidebarMenuSubButton>
                              </SidebarMenuSubItem>
                            )
                          )}
                        </SidebarMenuSub>
                      )}
                    </CollapsibleContent>
                  </SidebarMenuItem>
                </SidebarMenu>
              </Collapsible>
            </div>
          ))}
      </SidebarContent>
    </Sidebar>
  );
}

function NestedCollapsible({
  item,
  currentPath,
  expanded,
  toggleSection,
}: {
  item: {
    key: string;
    label: string;
    icon: LucideIcon;
    to?: string;
    children?: { label: string; to: string }[];
  };
  currentPath: string;
  expanded: Record<string, boolean>;
  toggleSection: (key: string) => void;
}) {
  return (
    <SidebarMenuSubItem>
      <Collapsible
        open={expanded[item.key] ?? false}
        onOpenChange={() => toggleSection(item.key)}
      >
        <CollapsibleTrigger asChild>
          <SidebarMenuSubButton size="sm" className="cursor-pointer">
            <item.icon className="h-3.5 w-3.5" />
            <span className="flex-1">{item.label}</span>
            <ChevronRight
              className={`h-3 w-3 transition-transform duration-200 ${
                expanded[item.key] ? "rotate-90" : ""
              }`}
            />
          </SidebarMenuSubButton>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <SidebarMenuSub>
            {item.children?.map((technique) => (
              <SidebarMenuSubItem key={technique.to}>
                <SidebarMenuSubButton
                  asChild
                  isActive={currentPath === technique.to}
                  size="sm"
                >
                  <Link to={technique.to}>
                    <span className="truncate">{technique.label}</span>
                  </Link>
                </SidebarMenuSubButton>
              </SidebarMenuSubItem>
            ))}
          </SidebarMenuSub>
        </CollapsibleContent>
      </Collapsible>
    </SidebarMenuSubItem>
  );
}
