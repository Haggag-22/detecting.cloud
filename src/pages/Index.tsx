import { Layout } from "@/components/Layout";
import { FeatureCard } from "@/components/FeatureCard";
import { ArticleCard } from "@/components/ArticleCard";
import { TopicCard } from "@/components/TopicCard";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import { Shield, Search, Crosshair, FlaskConical, KeyRound, TrendingUp, Server, Network, Database, ShieldCheck } from "lucide-react";
import { researchPosts } from "@/data/research";

const features = [
  { icon: Search, title: "Cloud Attack Research", description: "In-depth analysis of real-world cloud attack techniques targeting AWS infrastructure." },
  { icon: ShieldCheck, title: "Detection Engineering", description: "Practical detection rules and queries for identifying cloud threats in your environment." },
  { icon: Crosshair, title: "Adversary Simulation", description: "Simulated attack scenarios to validate your detection and response capabilities." },
  { icon: FlaskConical, title: "Security Labs", description: "Hands-on labs for learning cloud security techniques in safe environments." },
];

const topics = [
  { icon: KeyRound, title: "IAM Abuse", to: "/research" },
  { icon: TrendingUp, title: "Privilege Escalation", to: "/research" },
  { icon: Server, title: "AWS Persistence", to: "/research" },
  { icon: Network, title: "Cloud Lateral Movement", to: "/research" },
  { icon: Database, title: "Cloud Data Exfiltration", to: "/research" },
  { icon: Shield, title: "Detection Engineering", to: "/detection-engineering" },
];

const Index = () => {
  return (
    <Layout>
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 grid-pattern opacity-30" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full bg-gradient-primary opacity-[0.04] blur-3xl" />
        <div className="container relative py-24 md:py-36">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="max-w-3xl mx-auto text-center"
          >
            <h1 className="font-display text-4xl md:text-6xl font-bold tracking-tight mb-6">
              <span className="text-gradient">Detecting.Cloud</span>
              <br />
              <span className="text-foreground/90">Cloud Attack Research &amp; Detection Engineering</span>
            </h1>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto mb-8 leading-relaxed">
              Researching real-world cloud attack paths and building practical detections for defenders.
            </p>
            <div className="flex flex-wrap gap-3 justify-center">
              <Link to="/research">
                <Button size="lg" className="bg-gradient-primary hover:opacity-90 text-primary-foreground font-semibold">
                  Read Research
                </Button>
              </Link>
              <Link to="/attack-paths">
                <Button size="lg" variant="outline" className="border-border hover:bg-muted">
                  Explore Attack Paths
                </Button>
              </Link>
            </div>
          </motion.div>
        </div>
      </section>

      {/* Features */}
      <section className="container py-20">
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {features.map((f, i) => (
            <FeatureCard key={f.title} {...f} delay={i * 0.1} />
          ))}
        </div>
      </section>

      {/* Latest Research */}
      <section className="container py-16">
        <div className="flex items-center justify-between mb-8">
          <h2 className="font-display text-2xl font-bold">Latest Research</h2>
          <Link to="/research" className="text-sm text-primary hover:underline">View all →</Link>
        </div>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {researchPosts.slice(0, 4).map((post) => (
            <ArticleCard key={post.slug} {...post} />
          ))}
        </div>
      </section>

      {/* Topics */}
      <section className="container py-16 pb-24">
        <h2 className="font-display text-2xl font-bold mb-8">Cloud Security Topics</h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {topics.map((t) => (
            <TopicCard key={t.title} {...t} />
          ))}
        </div>
      </section>
    </Layout>
  );
};

export default Index;
