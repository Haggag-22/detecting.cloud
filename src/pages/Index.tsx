import { Layout } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import logoImg from "@/assets/logo.png";
import { techniques } from "@/data/techniques";
import { attackPaths } from "@/data/attackPaths";
import { detections } from "@/data/detections";
import { Shield, Route, Crosshair, Server, Mail, CheckCircle } from "lucide-react";
import { Input } from "@/components/ui/input";
import { addSubscriber } from "@/pages/AdminSubscribers";
import { toast } from "sonner";
import { useState } from "react";

const Index = () => {
  const [email, setEmail] = useState("");
  const [loading, setLoading] = useState(false);
  const [subscribed, setSubscribed] = useState(false);

  const handleSubscribe = (e: React.FormEvent) => {
    e.preventDefault();
    if (!email || !email.includes("@")) {
      toast.error("Please enter a valid email");
      return;
    }
    setLoading(true);
    setTimeout(() => {
      const added = addSubscriber(email);
      if (added) {
        toast.success("Subscribed! You'll receive the latest cloud security updates.");
        setSubscribed(true);
      } else {
        toast.info("You're already subscribed!");
        setSubscribed(true);
      }
      setEmail("");
      setLoading(false);
    }, 300);
  };

  return (
    <Layout>
      <section className="relative overflow-hidden min-h-screen flex items-center">
        <div className="absolute inset-0 grid-pattern opacity-30" />
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-[600px] h-[600px] rounded-full bg-gradient-primary opacity-[0.04] blur-3xl" />

        {/* Large blurred logo background */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 pointer-events-none">
          <img
            src={logoImg}
            alt=""
            className="w-[400px] h-[400px] md:w-[500px] md:h-[500px] object-contain opacity-[0.06] blur-2xl"
          />
        </div>

        <div className="container relative py-24 md:py-36">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.6 }}
            className="max-w-3xl mx-auto text-center"
          >
            {/* Logo */}
            <motion.img
              src={logoImg}
              alt="Detecting.Cloud logo"
              className="w-20 h-20 md:w-24 md:h-24 rounded-2xl mx-auto mb-8 shadow-2xl ring-1 ring-border/50"
              initial={{ opacity: 0, scale: 0.8 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ duration: 0.5, delay: 0.1 }}
            />

            <h1 className="font-display text-4xl md:text-6xl font-bold tracking-tight mb-6">
              <span className="text-gradient">Detecting.Cloud</span>
              <br />
              <span className="text-foreground/90">Cloud Attack Research &amp; Detection Engineering</span>
            </h1>
            <p className="text-lg text-muted-foreground max-w-2xl mx-auto mb-8 leading-relaxed">
              Researching real-world cloud attack paths and building practical detections for defenders.
            </p>
            <div className="flex flex-wrap gap-3 justify-center">
              <Link to="/detection-engineering">
                <Button size="lg" className="bg-primary hover:bg-primary/90 text-primary-foreground font-semibold">
                  Explore Detection Rules
                </Button>
              </Link>
              <Link to="/attack-paths">
                <Button size="lg" variant="outline" className="border-primary/30 text-primary hover:bg-primary/10">
                  Explore Attack Paths
                </Button>
              </Link>
            </div>

            {/* Stats Bar */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              transition={{ duration: 0.6, delay: 0.4 }}
              className="flex flex-wrap items-center justify-center gap-6 mt-10 text-sm text-muted-foreground"
            >
              {[
                { icon: Crosshair, label: "Techniques", count: techniques.length },
                { icon: Route, label: "Attack Paths", count: attackPaths.length },
                { icon: Shield, label: "Detection Rules", count: detections.length },
                { icon: Server, label: "AWS Services", count: new Set(techniques.flatMap(t => t.services)).size },
              ].map((stat) => (
                <div key={stat.label} className="flex items-center gap-2">
                  <stat.icon className="h-4 w-4 text-primary/70" />
                  <span className="font-semibold text-foreground">{stat.count}</span>
                  <span>{stat.label}</span>
                </div>
              ))}
            </motion.div>

            {/* Subscribe Panel */}
            <motion.div
              initial={{ opacity: 0, y: 16 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.6 }}
              className="mt-12 max-w-md mx-auto"
            >
              <div className="rounded-xl border border-border/50 bg-card/60 backdrop-blur-sm p-6">
                <div className="flex items-center justify-center gap-2 mb-3">
                  <Mail className="h-5 w-5 text-primary" />
                  <h3 className="font-semibold text-foreground text-sm">Stay Updated</h3>
                </div>
                <p className="text-xs text-muted-foreground mb-4">
                  Get the latest cloud security research, detections & attack paths in your inbox.
                </p>
                {subscribed ? (
                  <div className="flex items-center justify-center gap-2 text-sm text-primary">
                    <CheckCircle className="h-4 w-4" />
                    <span>You're subscribed!</span>
                  </div>
                ) : (
                  <form onSubmit={handleSubscribe} className="flex gap-2">
                    <div className="relative flex-1">
                      <Mail className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                      <Input
                        type="email"
                        placeholder="your@email.com"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className="pl-9 h-9 text-sm bg-background/50"
                      />
                    </div>
                    <Button type="submit" size="sm" disabled={loading} className="h-9 px-5">
                      Subscribe
                    </Button>
                  </form>
                )}
              </div>
            </motion.div>
          </motion.div>
        </div>
      </section>
    </Layout>
  );
};

export default Index;
