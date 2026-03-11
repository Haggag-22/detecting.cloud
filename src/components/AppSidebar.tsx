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
  SidebarFooter,
} from "@/components/ui/sidebar";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Search,
  Crosshair,
  ShieldCheck,
  ChevronRight,
  ExternalLink,
  Bug,
  Route,
  Network as NetworkIcon,
  KeyRound,
  TrendingUp,
  Server,
  Wifi,
  Database,
  ShieldOff,
  Home,
  Info,
  BarChart3,
  Github,
  Twitter,
} from "lucide-react";
import { Link, useLocation } from "react-router-dom";
import { attackPaths, attackObjectiveLabels, type AttackObjective } from "@/data/attackPaths";
import { techniques, techniqueCategories, type TechniqueCategory } from "@/data/techniques";
import { detections, getDetectionsByService } from "@/data/detections";
import { researchPosts } from "@/data/research";
import { LucideIcon } from "lucide-react";
import { getAwsServiceIcon } from "@/components/AwsIcons";
import { ThemeToggle } from "@/components/ThemeToggle";
import logoImg from "@/assets/logo.png";

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

const objectiveColors: Record<AttackObjective, string> = {
  "credential-access": "text-purple-400",
  "privilege-escalation": "text-red-400",
  "persistence": "text-orange-400",
  "lateral-movement": "text-blue-400",
  "exfiltration": "text-emerald-400",
};

const techniqueCategoryColors: Record<string, string> = {
  "initial-access": "text-cyan-400",
  "credential-access": "text-purple-400",
  "privilege-escalation": "text-red-400",
  "persistence": "text-orange-400",
  "lateral-movement": "text-blue-400",
  "exfiltration": "text-emerald-400",
  "defense-evasion": "text-amber-400",
};

interface SidebarSection {
  key: string;
  label: string;
  icon?: LucideIcon;
  to?: string;
  children?: SidebarChild[];
}

interface SidebarChild {
  key: string;
  label: string;
  icon?: LucideIcon;
  iconColorClass?: string;
  customIcon?: React.ReactNode;
  to?: string;
  children?: { label: string; to: string }[];
}

function buildSections(): SidebarSection[] {
  const attackPathChildren: SidebarChild[] = [
    { key: "ap-all", label: "All Attack Paths", icon: Crosshair, to: "/attack-paths" },
    ...attackPaths.map((ap) => ({
      key: `ap-${ap.slug}`,
      label: ap.title.length > 35 ? ap.title.substring(0, 35) + "…" : ap.title,
      icon: Route,
      iconColorClass: objectiveColors[ap.objective],
      to: `/attack-paths?technique=${ap.slug}`,
    })),
  ];

  const techniqueCategoryIcons: Record<string, LucideIcon> = {
    "initial-access": Crosshair,
    "credential-access": KeyRound,
    "privilege-escalation": TrendingUp,
    "persistence": Server,
    "lateral-movement": Wifi,
    "exfiltration": Database,
    "defense-evasion": ShieldOff,
  };

  const techniqueChildren: SidebarChild[] = [
    { key: "tech-all", label: "All Techniques", icon: Route, to: "/techniques" },
    ...(Object.keys(techniqueCategories) as TechniqueCategory[]).map((catKey) => {
      const catTechs = techniques.filter((t) => t.category === catKey);
      const colorClass = techniqueCategoryColors[catKey] || "text-muted-foreground";
      return {
        key: `tech-cat-${catKey}`,
        label: techniqueCategories[catKey].label,
        icon: techniqueCategoryIcons[catKey] || Crosshair,
        iconColorClass: colorClass,
        children: catTechs.map((t) => ({
          label: t.name.length > 35 ? t.name.substring(0, 35) + "…" : t.name,
          to: `/attack-paths/technique/${t.id}`,
        })),
      };
    }).filter((c) => c.children.length > 0),
  ];

  const detectionsByService = getDetectionsByService();
  const detectionServiceChildren: SidebarChild[] = [
    { key: "det-all", label: "All Detections", icon: ShieldCheck, to: "/detection-engineering" },
    ...Object.entries(detectionsByService).map(([service, rules]) => {
      const ServiceIcon = getAwsServiceIcon(service);
      return {
        key: `det-svc-${service}`,
        label: service,
        customIcon: ServiceIcon ? <ServiceIcon size={14} /> : undefined,
        children: rules.map((d) => ({
          label: d.title.length > 40 ? d.title.substring(0, 40) + "…" : d.title,
          to: `/detection-engineering?rule=${d.id}`,
        })),
      };
    }),
  ];

  return [
    {
      key: "home",
      label: "Home",
      icon: Home,
      to: "/",
    },
    {
      key: "attack-paths",
      label: "Attack Paths",
      icon: Crosshair,
      to: "/attack-paths",
      children: attackPathChildren,
    },
    {
      key: "techniques",
      label: "Techniques Library",
      icon: Route,
      to: "/techniques",
      children: techniqueChildren,
    },
    {
      key: "detections",
      label: "Detection Engineering",
      icon: ShieldCheck,
      to: "/detection-engineering",
      children: detectionServiceChildren,
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
      icon: Route,
      to: "/simulator",
    },
    {
      key: "coverage",
      label: "Detection Coverage",
      icon: BarChart3,
      to: "/coverage",
    },
    {
      key: "gap-analysis",
      label: "Gap Analysis",
      icon: ShieldCheck,
      to: "/gap-analysis",
    },
    {
      key: "community-rules",
      label: "Community Rules",
      icon: Bug,
      to: "/community-rules",
    },
    {
      key: "about",
      label: "About",
      icon: Info,
      to: "/about",
    },
  ];
}

export function AppSidebar() {
  const location = useLocation();
  const currentPath = location.pathname + location.search;
  const sections = buildSections();

  const [expanded, setExpanded] = useState<Record<string, boolean>>(() => {
    const persisted = getPersistedState();
    const defaults: Record<string, boolean> = {};
    sections.forEach((s) => {
      if (s.to && location.pathname.startsWith(s.to) && s.to !== "/") {
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

  const allSearchItems: { label: string; to: string; type: string }[] = [];
  attackPaths.forEach((ap) => allSearchItems.push({ label: ap.title, to: `/attack-paths?technique=${ap.slug}`, type: "Attack Path" }));
  techniques.forEach((t) => allSearchItems.push({ label: t.name, to: `/attack-paths/technique/${t.id}`, type: "Technique" }));
  detections.forEach((d) => allSearchItems.push({ label: d.title, to: `/detection-engineering?rule=${d.id}`, type: "Detection" }));
  researchPosts.forEach((p) => allSearchItems.push({ label: p.title, to: `/research/${p.slug}`, type: "Research" }));

  const searchResults = search.trim()
    ? allSearchItems.filter((item) => item.label.toLowerCase().includes(search.toLowerCase()))
    : [];

  return (
    <Sidebar collapsible="icon" className="border-r border-border/50">
      <SidebarHeader className="p-4 space-y-4">
        {/* Logo & Brand */}
        <Link to="/" className="flex items-center gap-2.5 group-data-[collapsible=icon]:justify-center">
          <img src={logoImg} alt="Detecting.Cloud logo" className="h-8 w-8 rounded-lg shrink-0" />
          <span className="font-display font-bold text-base tracking-tight group-data-[collapsible=icon]:hidden">
            Detecting<span className="text-primary">.Cloud</span>
          </span>
        </Link>

        {/* Search */}
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

      <SidebarContent className="overflow-y-auto will-change-scroll" style={{ overscrollBehavior: 'contain' }}>
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

        {!search.trim() &&
          sections.map((section) => {
            if (!section.children) {
              const isActive = section.to === "/" 
                ? location.pathname === "/" 
                : section.to ? location.pathname.startsWith(section.to) : false;
              return (
                <div key={section.key} className="px-2 py-0.5">
                  <SidebarMenu>
                    <SidebarMenuItem>
                      <SidebarMenuButton asChild tooltip={section.label} isActive={isActive}
                        className="text-sm font-medium"
                      >
                        <Link to={section.to || "#"}>
                          {section.icon && <section.icon className="h-4 w-4" />}
                          <span className="flex-1">{section.label}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  </SidebarMenu>
                </div>
              );
            }

            return (
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
                          className="text-sm font-medium text-muted-foreground hover:text-foreground"
                        >
                          {section.icon && <section.icon className="h-4 w-4" />}
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
                                      {child.customIcon || (child.icon && (
                                        <child.icon className={`h-3.5 w-3.5 ${child.iconColorClass || ""}`} />
                                      ))}
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
            );
          })}
      </SidebarContent>

      {/* Footer with theme toggle and social links */}
      <SidebarFooter className="p-3 border-t border-border/50">
        <div className="flex items-center justify-between group-data-[collapsible=icon]:justify-center">
          <ThemeToggle />
          <div className="flex items-center gap-1 group-data-[collapsible=icon]:hidden">
            <a href="https://github.com/Haggag-22/detecting.cloud" target="_blank" rel="noopener noreferrer"
              className="p-1.5 rounded-md text-muted-foreground hover:text-foreground transition-colors">
              <Github className="h-4 w-4" />
            </a>
            <a href="https://twitter.com" target="_blank" rel="noopener noreferrer"
              className="p-1.5 rounded-md text-muted-foreground hover:text-foreground transition-colors">
              <Twitter className="h-4 w-4" />
            </a>
          </div>
        </div>
      </SidebarFooter>
    </Sidebar>
  );
}

function NestedCollapsible({
  item,
  currentPath,
  expanded,
  toggleSection,
}: {
  item: SidebarChild;
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
            {item.customIcon || (item.icon ? (
              <item.icon className={`h-3.5 w-3.5 shrink-0 ${item.iconColorClass || ""}`} />
            ) : (
              <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${item.iconColorClass ? item.iconColorClass.replace("text-", "bg-") : "bg-muted-foreground"}`} />
            ))}
            <span className={`flex-1 font-semibold ${item.iconColorClass || ""}`}>{item.label}</span>
            <ChevronRight
              className={`h-3 w-3 transition-transform duration-200 ${
                expanded[item.key] ? "rotate-90" : ""
              }`}
            />
          </SidebarMenuSubButton>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <SidebarMenuSub>
            {item.children?.map((child) => (
              <SidebarMenuSubItem key={child.to}>
                <SidebarMenuSubButton
                  asChild
                  isActive={currentPath === child.to}
                  size="sm"
                >
                  <Link to={child.to}>
                    <span className="truncate">{child.label}</span>
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
