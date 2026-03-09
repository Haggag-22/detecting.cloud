import { Layout } from "@/components/Layout";
import { Shield } from "lucide-react";

const AboutPage = () => {
  return (
    <Layout>
      <div className="container py-12 max-w-2xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="rounded-lg bg-gradient-subtle p-3">
            <Shield className="h-6 w-6 text-primary" />
          </div>
          <h1 className="font-display text-3xl font-bold">About Detecting.Cloud</h1>
        </div>
        <div className="space-y-4 text-muted-foreground leading-relaxed">
          <p>
            Detecting.Cloud is a research platform dedicated to cloud attack techniques, detection engineering, and defensive security for AWS environments.
          </p>
          <p>
            Our mission is to bridge the gap between offensive cloud security research and practical defensive strategies. We publish in-depth technical research, detection rules, and hands-on labs to help security teams protect their cloud infrastructure.
          </p>
          <p>
            All content is created by security researchers with real-world experience in cloud penetration testing, incident response, and detection engineering.
          </p>
          <h2 className="text-foreground font-display font-bold text-xl pt-4">What We Cover</h2>
          <ul className="space-y-2 ml-4">
            <li className="flex items-start gap-2"><span className="text-primary">•</span>Cloud attack techniques and tradecraft</li>
            <li className="flex items-start gap-2"><span className="text-primary">•</span>Detection engineering for AWS environments</li>
            <li className="flex items-start gap-2"><span className="text-primary">•</span>IAM security and privilege escalation research</li>
            <li className="flex items-start gap-2"><span className="text-primary">•</span>Adversary simulation frameworks</li>
            <li className="flex items-start gap-2"><span className="text-primary">•</span>Practical security labs and exercises</li>
          </ul>
        </div>
      </div>
    </Layout>
  );
};

export default AboutPage;
