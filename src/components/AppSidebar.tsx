import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarMenu,
  SidebarMenuItem,
  SidebarMenuButton,
  SidebarHeader,
} from "@/components/ui/sidebar";
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
  Bug,
  AlertTriangle,
  Eye,
  Zap,
  Lock,
} from "lucide-react";
import { Link, useLocation } from "react-router-dom";

const sections = [
  {
    label: "Research",
    items: [
      { icon: FileText, title: "All Research", to: "/research" },
      { icon: Shield, title: "Cloud Attacks", to: "/research?cat=cloud-attacks" },
      { icon: Bug, title: "Threat Intelligence", to: "/research?cat=threat-intel" },
    ],
  },
  {
    label: "Attack Paths",
    items: [
      { icon: Crosshair, title: "All Attack Paths", to: "/attack-paths" },
      { icon: KeyRound, title: "IAM Abuse", to: "/attack-paths?cat=iam" },
      { icon: TrendingUp, title: "Privilege Escalation", to: "/attack-paths?cat=privesc" },
      { icon: Server, title: "Persistence", to: "/attack-paths?cat=persistence" },
      { icon: Database, title: "Data Exfiltration", to: "/attack-paths?cat=exfil" },
      { icon: Network, title: "Lateral Movement", to: "/attack-paths?cat=lateral" },
    ],
  },
  {
    label: "Detection Engineering",
    items: [
      { icon: ShieldCheck, title: "All Detections", to: "/detection-engineering" },
      { icon: Eye, title: "Sigma Rules", to: "/detection-engineering?cat=sigma" },
      { icon: Search, title: "CloudTrail Queries", to: "/detection-engineering?cat=cloudtrail" },
      { icon: Zap, title: "Splunk Queries", to: "/detection-engineering?cat=splunk" },
      { icon: AlertTriangle, title: "SIEM Detections", to: "/detection-engineering?cat=siem" },
    ],
  },
  {
    label: "Labs",
    items: [
      { icon: FlaskConical, title: "All Labs", to: "/labs" },
      { icon: Lock, title: "IAM Security", to: "/labs?cat=iam" },
      { icon: Search, title: "Log Analysis", to: "/labs?cat=logs" },
    ],
  },
];

export function AppSidebar() {
  const location = useLocation();
  const currentPath = location.pathname + location.search;

  return (
    <Sidebar collapsible="icon" className="border-r border-sidebar-border">
      <SidebarHeader className="p-4">
        <Link to="/" className="flex items-center gap-2 font-display font-bold text-sm">
          <Shield className="h-4 w-4 shrink-0 text-primary" />
          <span className="truncate">
            Detecting<span className="text-primary">.Cloud</span>
          </span>
        </Link>
      </SidebarHeader>
      <SidebarContent>
        {sections.map((section) => (
          <SidebarGroup key={section.label}>
            <SidebarGroupLabel className="text-xs uppercase tracking-wider text-muted-foreground">
              {section.label}
            </SidebarGroupLabel>
            <SidebarGroupContent>
              <SidebarMenu>
                {section.items.map((item) => {
                  const isActive = currentPath === item.to || 
                    (location.pathname === item.to.split("?")[0] && !item.to.includes("?") && !location.search);
                  return (
                    <SidebarMenuItem key={item.title}>
                      <SidebarMenuButton asChild isActive={isActive} tooltip={item.title}>
                        <Link to={item.to}>
                          <item.icon className="h-4 w-4" />
                          <span>{item.title}</span>
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  );
                })}
              </SidebarMenu>
            </SidebarGroupContent>
          </SidebarGroup>
        ))}
      </SidebarContent>
    </Sidebar>
  );
}
