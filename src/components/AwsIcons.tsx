import React from "react";

import iconIAM from "@/assets/icons/IAM.png";
import iconLambda from "@/assets/icons/Lambda.png";
import iconEC2 from "@/assets/icons/EC2.png";
import iconS3 from "@/assets/icons/S3.png";
import iconEBS from "@/assets/icons/EBS.png";
import iconDynamoDB from "@/assets/icons/DynamoDB.png";
import iconCloudTrail from "@/assets/icons/CloudTrail.png";
import iconKMS from "@/assets/icons/KMS.png";
import iconEKS from "@/assets/icons/EKS.png";
import iconECS from "@/assets/icons/ECS.png";
import iconSecretsManager from "@/assets/icons/SecretsManager.png";
import iconSSM from "@/assets/icons/SSM.png";
import iconOrganizations from "@/assets/icons/Organizations.png";
import iconSageMaker from "@/assets/icons/SageMaker.png";
import iconSES from "@/assets/icons/SES.png";
import iconCodeBuild from "@/assets/icons/CodeBuild.png";
import iconElasticBeanstalk from "@/assets/icons/ElasticBeanstalk.png";
import iconCloudFront from "@/assets/icons/CloudFront.png";

interface IconProps {
  className?: string;
  size?: number;
}

const defaultSize = 24;

/** Map service names to bundled icon URLs (Vite resolves paths) */
const awsIconPaths: Record<string, string> = {
  IAM: iconIAM,
  Lambda: iconLambda,
  EC2: iconEC2,
  S3: iconS3,
  EBS: iconEBS,
  DynamoDB: iconDynamoDB,
  CloudTrail: iconCloudTrail,
  KMS: iconKMS,
  EKS: iconEKS,
  ECS: iconECS,
  "Secrets Manager": iconSecretsManager,
  SSM: iconSSM,
  Organizations: iconOrganizations,
  SageMaker: iconSageMaker,
  SES: iconSES,
  CodeBuild: iconCodeBuild,
  "Elastic Beanstalk": iconElasticBeanstalk,
  CloudFront: iconCloudFront,
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
