import { Layout } from "@/components/Layout";
import { Button } from "@/components/ui/button";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import logoImg from "@/assets/logo.png";

const Index = () => {
  return (
    <Layout>
      <section className="relative overflow-hidden min-h-[calc(100vh-4rem)] flex items-center">
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
                <Button size="lg" className="bg-gradient-primary hover:opacity-90 text-primary-foreground font-semibold">
                  Explore Detection Rules
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
    </Layout>
  );
};

export default Index;
