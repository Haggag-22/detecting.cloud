import React from "react";

interface IconProps {
  className?: string;
  size?: number;
}

const defaultSize = 24;

/** Map service names to icon filenames in /icons/ */
const awsIconPaths: Record<string, string> = {
  IAM: "/icons/IAM%20Identity%20Center.png",
  Lambda: "/icons/Lambda.png",
  EC2: "/icons/EC2.png",
  S3: "/icons/Simple%20Storage%20Service.png",
  EBS: "/icons/Elastic%20Block%20Store.png",
  DynamoDB: "/icons/DynamoDB.png",
  CloudTrail: "/icons/CloudTrail.png",
  KMS: "/icons/Key%20Management%20Service.png",
  EKS: "/icons/EKS%20Cloud.png",
  ECS: "/icons/ECS%20Anywhere.png",
  "Secrets Manager": "/icons/Secrets%20Manager.png",
  SSM: "/icons/Systems%20Manager.png",
  Organizations: "/icons/Organizations.png",
  SageMaker: "/icons/SageMaker.png",
  SES: "/icons/Simple%20Email%20Service.png",
  CodeBuild: "/icons/CodeBuild.png",
  "Elastic Beanstalk": "/icons/Elastic%20Beanstalk.png",
  CloudFront: "/icons/CloudFront.png",
};

/** Fallback SVG for STS (no icon file) */
const AwsStsIconFallback: React.FC<IconProps> = ({ className, size = defaultSize }) => (
  <svg viewBox="0 0 40 40" width={size} height={size} className={className} xmlns="http://www.w3.org/2000/svg">
    <rect x="4" y="4" width="32" height="32" rx="2" fill="#DD344C" />
    <path d="M14 16h12v10H14z" fill="none" stroke="#fff" strokeWidth="2" />
    <path d="M17 16v-3a3 3 0 0 1 6 0v3" fill="none" stroke="#fff" strokeWidth="2" />
    <circle cx="20" cy="22" r="1.5" fill="#fff" />
  </svg>
);

function createAwsIconComponent(iconPath: string): React.FC<IconProps> {
  return ({ className, size = defaultSize }) => (
    <img src={iconPath} alt="" width={size} height={size} className={className} style={{ objectFit: "contain" }} />
  );
}

const iconComponents: Record<string, React.FC<IconProps>> = {
  IAM: createAwsIconComponent(awsIconPaths.IAM ?? ""),
  Lambda: createAwsIconComponent(awsIconPaths.Lambda ?? ""),
  EC2: createAwsIconComponent(awsIconPaths.EC2 ?? ""),
  S3: createAwsIconComponent(awsIconPaths.S3 ?? ""),
  EBS: createAwsIconComponent(awsIconPaths.EBS ?? ""),
  DynamoDB: createAwsIconComponent(awsIconPaths.DynamoDB ?? ""),
  CloudTrail: createAwsIconComponent(awsIconPaths.CloudTrail ?? ""),
  KMS: createAwsIconComponent(awsIconPaths.KMS ?? ""),
  EKS: createAwsIconComponent(awsIconPaths.EKS ?? ""),
  ECS: createAwsIconComponent(awsIconPaths.ECS ?? ""),
  "Secrets Manager": createAwsIconComponent(awsIconPaths["Secrets Manager"] ?? ""),
  SSM: createAwsIconComponent(awsIconPaths.SSM ?? ""),
  Organizations: createAwsIconComponent(awsIconPaths.Organizations ?? ""),
  SageMaker: createAwsIconComponent(awsIconPaths.SageMaker ?? ""),
  SES: createAwsIconComponent(awsIconPaths.SES ?? ""),
  CodeBuild: createAwsIconComponent(awsIconPaths.CodeBuild ?? ""),
  "Elastic Beanstalk": createAwsIconComponent(awsIconPaths["Elastic Beanstalk"] ?? ""),
  CloudFront: createAwsIconComponent(awsIconPaths.CloudFront ?? ""),
  STS: AwsStsIconFallback,
};

export const awsServiceIcons: Record<string, React.FC<IconProps>> = iconComponents;

export const AwsIamIcon = iconComponents.IAM;
export const AwsLambdaIcon = iconComponents.Lambda;
export const AwsEc2Icon = iconComponents.EC2;
export const AwsS3Icon = iconComponents.S3;
export const AwsEbsIcon = iconComponents.EBS;
export const AwsDynamoDbIcon = iconComponents.DynamoDB;
export const AwsCloudTrailIcon = iconComponents.CloudTrail;
export const AwsKmsIcon = iconComponents.KMS;
export const AwsEksIcon = iconComponents.EKS;
export const AwsStsIcon = iconComponents.STS;
export const AwsEcsIcon = iconComponents.ECS;
export const AwsSecretsManagerIcon = iconComponents["Secrets Manager"];
export const AwsSsmIcon = iconComponents.SSM;
export const AwsOrganizationsIcon = iconComponents.Organizations;
export const AwsSageMakerIcon = iconComponents.SageMaker;
export const AwsSesIcon = iconComponents.SES;
export const AwsCodeBuildIcon = iconComponents.CodeBuild;
export const AwsElasticBeanstalkIcon = iconComponents["Elastic Beanstalk"];
export const AwsCloudFrontIcon = iconComponents.CloudFront;

export function getAwsServiceIcon(service: string): React.FC<IconProps> | null {
  return awsServiceIcons[service] || null;
}
