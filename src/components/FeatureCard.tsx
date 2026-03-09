import { type LucideIcon } from "lucide-react";
import { motion } from "framer-motion";

interface FeatureCardProps {
  icon: LucideIcon;
  title: string;
  description: string;
  delay?: number;
}

export function FeatureCard({ icon: Icon, title, description, delay = 0 }: FeatureCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={{ once: true }}
      transition={{ delay, duration: 0.5 }}
      className="group relative rounded-lg border border-border/50 bg-card p-6 transition-all hover:border-primary/30 hover:glow-primary"
    >
      <div className="mb-4 inline-flex rounded-lg bg-gradient-subtle p-2.5">
        <Icon className="h-5 w-5 text-primary" />
      </div>
      <h3 className="font-display font-semibold mb-2">{title}</h3>
      <p className="text-sm text-muted-foreground leading-relaxed">{description}</p>
    </motion.div>
  );
}
