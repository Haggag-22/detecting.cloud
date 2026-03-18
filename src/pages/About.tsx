import { Layout } from "@/components/Layout";
import { Link } from "react-router-dom";
import { Shield, BookOpen, GitPullRequest } from "lucide-react";

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

          <h2 className="text-foreground font-display font-bold text-xl pt-6 flex items-center gap-2">
            <BookOpen className="h-5 w-5" />
            Research Blog
          </h2>
          <p>
            Our <Link to="/research" className="text-primary hover:underline font-medium">Research Library</Link> is a blog-style collection of in-depth articles on cloud attack techniques, IAM abuse, privilege escalation paths, and defensive strategies. Each post includes technical analysis, detection ideas, mitigations, and references. Subscribe via the footer to get new research and detections delivered to your inbox.
          </p>

          <h2 className="text-foreground font-display font-bold text-xl pt-6">What We Cover</h2>
          <ul className="space-y-2 ml-4">
            <li className="flex items-start gap-2"><span className="text-primary">•</span>Cloud attack techniques and tradecraft</li>
            <li className="flex items-start gap-2"><span className="text-primary">•</span>Detection engineering for AWS environments</li>
            <li className="flex items-start gap-2"><span className="text-primary">•</span>IAM security and privilege escalation research</li>
            <li className="flex items-start gap-2"><span className="text-primary">•</span>Adversary simulation frameworks</li>
            <li className="flex items-start gap-2"><span className="text-primary">•</span>Practical security labs and exercises</li>
          </ul>

          <h2 className="text-foreground font-display font-bold text-xl pt-6 flex items-center gap-2">
            <GitPullRequest className="h-5 w-5" />
            How to Contribute
          </h2>
          <p>
            We welcome community detection rules. To contribute:
          </p>
          <ol className="space-y-2 ml-4 list-decimal">
            <li><strong>Fork & clone</strong> the <a href="https://github.com/Haggag-22/detecting.cloud" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">repo</a></li>
            <li><strong>Add your rule</strong> to <code className="bg-muted px-1.5 py-0.5 rounded text-sm">src/data/communityRules.ts</code> (community rules only — core rules in <code className="bg-muted px-1.5 py-0.5 rounded text-sm">detections.ts</code> are maintained by the project)</li>
            <li><strong>Test locally</strong> with <code className="bg-muted px-1.5 py-0.5 rounded text-sm">npm run dev</code> and verify on the Community Rules page</li>
            <li><strong>Open a Pull Request</strong> against <code className="bg-muted px-1.5 py-0.5 rounded text-sm">main</code> with a brief description of what the rule detects</li>
          </ol>
          <p>
            See the full <a href="https://github.com/Haggag-22/detecting.cloud/blob/main/CONTRIBUTING.md" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">CONTRIBUTING.md</a> for severity levels, rule format, and code of conduct. Questions? <a href="https://github.com/Haggag-22/detecting.cloud/issues" target="_blank" rel="noopener noreferrer" className="text-primary hover:underline">Open an issue</a>.
          </p>
        </div>
      </div>
    </Layout>
  );
};

export default AboutPage;
