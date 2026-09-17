import type { LucideIcon } from "lucide-react";
import {
  Crosshair,
  KeyRound,
  TrendingUp,
  Server,
  Wifi,
  Database,
  ShieldOff,
  Search,
  Bomb,
} from "lucide-react";
import type { TechniqueCategory } from "@/data/techniques";

export const TECHNIQUE_CATEGORY_ICON: Record<TechniqueCategory, LucideIcon> = {
  "initial-access": Crosshair,
  "credential-access": KeyRound,
  "privilege-escalation": TrendingUp,
  persistence: Server,
  "lateral-movement": Wifi,
  exfiltration: Database,
  "defense-evasion": ShieldOff,
  discovery: Search,
  impact: Bomb,
};

export const TECHNIQUE_CATEGORY_ICON_COLOR: Record<TechniqueCategory, string> = {
  "initial-access": "text-cyan-400",
  "credential-access": "text-purple-400",
  "privilege-escalation": "text-red-400",
  persistence: "text-orange-400",
  "lateral-movement": "text-blue-400",
  exfiltration: "text-emerald-400",
  "defense-evasion": "text-amber-400",
  discovery: "text-sky-400",
  impact: "text-rose-400",
};

export const TECHNIQUE_CATEGORY_BADGE: Record<TechniqueCategory, string> = {
  "initial-access": "bg-cyan-500/15 text-cyan-400",
  "credential-access": "bg-purple-500/15 text-purple-400",
  "privilege-escalation": "bg-red-500/15 text-red-400",
  persistence: "bg-orange-500/15 text-orange-400",
  "lateral-movement": "bg-blue-500/15 text-blue-400",
  exfiltration: "bg-emerald-500/15 text-emerald-400",
  "defense-evasion": "bg-amber-500/15 text-amber-400",
  discovery: "bg-sky-500/15 text-sky-400",
  impact: "bg-rose-500/15 text-rose-400",
};

export const TECHNIQUE_CATEGORY_BADGE_BORDER: Record<TechniqueCategory, string> = {
  "initial-access": "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  "credential-access": "bg-purple-500/15 text-purple-400 border-purple-500/30",
  "privilege-escalation": "bg-red-500/15 text-red-400 border-red-500/30",
  persistence: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  "lateral-movement": "bg-blue-500/15 text-blue-400 border-blue-500/30",
  exfiltration: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  "defense-evasion": "bg-amber-500/15 text-amber-400 border-amber-500/30",
  discovery: "bg-sky-500/15 text-sky-400 border-sky-500/30",
  impact: "bg-rose-500/15 text-rose-400 border-rose-500/30",
};

export const TECHNIQUE_CATEGORY_BORDER_HOVER: Record<TechniqueCategory, string> = {
  "initial-access": "hover:border-cyan-500/40",
  "credential-access": "hover:border-purple-500/40",
  "privilege-escalation": "hover:border-red-500/40",
  persistence: "hover:border-orange-500/40",
  "lateral-movement": "hover:border-blue-500/40",
  exfiltration: "hover:border-emerald-500/40",
  "defense-evasion": "hover:border-amber-500/40",
  discovery: "hover:border-sky-500/40",
  impact: "hover:border-rose-500/40",
};
