import { Layout } from "@/components/Layout";
import { Link } from "react-router-dom";
import { BookOpen, GitPullRequest, Info } from "lucide-react";
import { PageTitleWithIcon } from "@/components/PageTitleWithIcon";

const AboutPage = () => {
  return (
    <Layout>
      <div className="container py-12 max-w-2xl">
        <PageTitleWithIcon team="neutral" icon={Info} className="mb-6">
          About Detecting.Cloud
        </PageTitleWithIcon>
        <div className="space-y-4 text-muted-foreground leading-relaxed">
          <p>
            Detecting.Cloud is a research platform dedicated to cloud attack techniques, detection rules, and defensive security for AWS environments.
          </p>
          <p>
            Our mission is to bridge the gap between offensive cloud security research and practical defensive strategies. We publish in-depth technical research, detection rules, and hands-on labs to help security teams protect their cloud infrastructure.
          </p>
          <p>
            All content is created by security researchers with real-world experience in cloud penetration testing, incident response, and building detection rules.
          </p>

          <h2 className="text-foreground font-display font-bold text-xl pt-6 flex items-center gap-2">
            <BookOpen className="h-5 w-5" />
            Content library
          </h2>
          <p>
            Explore{" "}
            <Link to="/attack-paths" className="text-primary hover:underline font-medium">
              attack paths
            </Link>
            , the{" "}
            <Link to="/techniques" className="text-primary hover:underline font-medium">
              techniques library
            </Link>
            , and{" "}
            <Link to="/detection-engineering" className="text-primary hover:underline font-medium">
              detection rules
            </Link>{" "}
            for AWS cloud security. Subscribe via the footer for updates.
          </p>

          <h2 className="text-foreground font-display font-bold text-xl pt-6">What We Cover</h2>
          <ul className="space-y-2 ml-4">
            <li className="flex items-start gap-2"><span className="text-primary">•</span>Cloud attack techniques and tradecraft</li>
            <li className="flex items-start gap-2"><span className="text-primary">•</span>Detection rules for AWS environments</li>
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
