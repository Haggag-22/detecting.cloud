export interface Lab {
  slug: string;
  title: string;
  difficulty: "Beginner" | "Intermediate" | "Advanced";
  provider: string;
  description: string;
}

export const labs: Lab[] = [
  {
    slug: "detecting-iam-privesc",
    title: "Detecting IAM Privilege Escalation",
    difficulty: "Intermediate",
    provider: "AWS",
    description: "Learn to detect various IAM privilege escalation techniques using CloudTrail logs and custom detection rules.",
  },
  {
    slug: "investigating-cloudtrail",
    title: "Investigating CloudTrail Logs",
    difficulty: "Beginner",
    provider: "AWS",
    description: "Hands-on lab for analyzing CloudTrail logs to identify suspicious activity and build incident timelines.",
  },
  {
    slug: "simulating-lateral-movement",
    title: "Simulating Cloud Lateral Movement",
    difficulty: "Advanced",
    provider: "AWS",
    description: "Simulate and detect lateral movement techniques across AWS accounts and services using real-world attack scenarios.",
  },
  {
    slug: "s3-bucket-forensics",
    title: "S3 Bucket Forensics",
    difficulty: "Intermediate",
    provider: "AWS",
    description: "Investigate S3 bucket compromise scenarios including data exfiltration, policy manipulation, and access logging analysis.",
  },
];
