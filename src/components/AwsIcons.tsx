import React from "react";
import type { AwsIconComponent } from "@aws-icons/react/architecture-service";
import {
  AwsAutoScaling,
  AwsBackup,
  AmazonBedrock,
  AwsCloudFormation,
  AmazonCognito,
  AmazonEventBridge,
} from "@aws-icons/react/architecture-service";
import {
  AwsIdentityAccessManagementAwsSts,
  AwsIdentityAccessManagementIamRolesAnywhere,
} from "@aws-icons/react/resource";

import iconIAM from "@/assets/icons/IAM.png";
import iconLambda from "@/assets/icons/Lambda.png";
import iconEC2 from "@/assets/icons/EC2.png";
import iconS3 from "@/assets/icons/S3.png";
import iconEBS from "@/assets/icons/EBS.png";
import iconEFS from "@/assets/icons/EFS.png";
import iconDynamoDB from "@/assets/icons/DynamoDB.png";
import iconRDS from "@/assets/icons/RDS.png";
import iconCloudTrail from "@/assets/icons/CloudTrail.png";
import iconConfig from "@/assets/icons/Config.png";
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
import iconGuardDuty from "@/assets/icons/GuardDuty.png";
import iconSecurityHub from "@/assets/icons/SecurityHub.png";
import iconVPC from "@/assets/icons/VPC.png";
import iconELB from "@/assets/icons/ELB.png";
import iconRoute53 from "@/assets/icons/Route53.png";
import iconGlue from "@/assets/icons/Glue.png";
import iconDirectoryService from "@/assets/icons/DirectoryService.png";
import iconIAMIdentityCenter from "@/assets/icons/IAMIdentityCenter.png";

import iconEntraID from "@/assets/icons/azure/EntraID.svg";
import iconEntraIDProtection from "@/assets/icons/azure/EntraIDProtection.svg";
import iconEntraIDApps from "@/assets/icons/azure/EntraIDApps.svg";
import iconEntraIDPIM from "@/assets/icons/azure/EntraIDPIM.svg";
import iconKeyVault from "@/assets/icons/azure/KeyVault.svg";
import iconAKS from "@/assets/icons/azure/AKS.svg";
import iconAzureActivity from "@/assets/icons/azure/AzureActivity.svg";
import iconAzureNetworking from "@/assets/icons/azure/AzureNetworking.svg";

import iconGcpIAM from "@/assets/icons/gcp/IAM.png";
import iconGke from "@/assets/icons/gcp/GKE.png";
import iconCloudStorage from "@/assets/icons/gcp/CloudStorage.png";
import iconCloudSql from "@/assets/icons/gcp/CloudSQL.png";
import iconGcpNetworking from "@/assets/icons/gcp/Networking.png";
import iconWorkspace from "@/assets/icons/gcp/Workspace.png";
import iconDlp from "@/assets/icons/gcp/DLP.png";
import iconGcp from "@/assets/icons/gcp/GCP.png";
import iconGcpAudit from "@/assets/icons/gcp/GCPAudit.png";

interface IconProps {
  className?: string;
  size?: number;
}

const defaultSize = 24;

function createAwsIconComponent(iconPath: string): React.FC<IconProps> {
  return ({ className, size = defaultSize }) => (
    <img src={iconPath} alt="" width={size} height={size} className={className} style={{ objectFit: "contain" }} />
  );
}

/** Wrap official @aws-icons/react components into our size/className API */
function wrapPackageIcon(Icon: AwsIconComponent): React.FC<IconProps> {
  return ({ className, size = defaultSize }) => (
    <Icon width={size} height={size} className={className} style={{ display: "block", flexShrink: 0 }} />
  );
}

/** Explicit map keeps Vite from tree-shaking service icon assets */
const iconComponents: Record<string, React.FC<IconProps>> = {
  IAM: createAwsIconComponent(iconIAM),
  Lambda: createAwsIconComponent(iconLambda),
  EC2: createAwsIconComponent(iconEC2),
  S3: createAwsIconComponent(iconS3),
  EBS: createAwsIconComponent(iconEBS),
  EFS: createAwsIconComponent(iconEFS),
  DynamoDB: createAwsIconComponent(iconDynamoDB),
  RDS: createAwsIconComponent(iconRDS),
  CloudTrail: createAwsIconComponent(iconCloudTrail),
  Config: createAwsIconComponent(iconConfig),
  KMS: createAwsIconComponent(iconKMS),
  EKS: createAwsIconComponent(iconEKS),
  ECS: createAwsIconComponent(iconECS),
  "Secrets Manager": createAwsIconComponent(iconSecretsManager),
  SSM: createAwsIconComponent(iconSSM),
  Organizations: createAwsIconComponent(iconOrganizations),
  SageMaker: createAwsIconComponent(iconSageMaker),
  SES: createAwsIconComponent(iconSES),
  CodeBuild: createAwsIconComponent(iconCodeBuild),
  "Elastic Beanstalk": createAwsIconComponent(iconElasticBeanstalk),
  CloudFront: createAwsIconComponent(iconCloudFront),
  GuardDuty: createAwsIconComponent(iconGuardDuty),
  "Security Hub": createAwsIconComponent(iconSecurityHub),
  VPC: createAwsIconComponent(iconVPC),
  ELB: createAwsIconComponent(iconELB),
  "Route 53": createAwsIconComponent(iconRoute53),
  Route53: createAwsIconComponent(iconRoute53),
  Glue: createAwsIconComponent(iconGlue),
  "Directory Service": createAwsIconComponent(iconDirectoryService),
  "IAM Identity Center": createAwsIconComponent(iconIAMIdentityCenter),

  // Official AWS Architecture Icons (@aws-icons/react)
  STS: wrapPackageIcon(AwsIdentityAccessManagementAwsSts),
  "Auto Scaling": wrapPackageIcon(AwsAutoScaling),
  Backup: wrapPackageIcon(AwsBackup),
  Bedrock: wrapPackageIcon(AmazonBedrock),
  CloudFormation: wrapPackageIcon(AwsCloudFormation),
  Cognito: wrapPackageIcon(AmazonCognito),
  EventBridge: wrapPackageIcon(AmazonEventBridge),
  "Roles Anywhere": wrapPackageIcon(AwsIdentityAccessManagementIamRolesAnywhere),

  // Azure
  "Entra ID": createAwsIconComponent(iconEntraID),
  "Entra ID Protection": createAwsIconComponent(iconEntraIDProtection),
  "Entra ID Apps": createAwsIconComponent(iconEntraIDApps),
  "Entra ID PIM": createAwsIconComponent(iconEntraIDPIM),
  "Key Vault": createAwsIconComponent(iconKeyVault),
  AKS: createAwsIconComponent(iconAKS),
  "Azure Activity": createAwsIconComponent(iconAzureActivity),
  "Azure Networking": createAwsIconComponent(iconAzureNetworking),

  // GCP
  "GCP IAM": createAwsIconComponent(iconGcpIAM),
  GKE: createAwsIconComponent(iconGke),
  "Cloud Storage": createAwsIconComponent(iconCloudStorage),
  "Cloud SQL": createAwsIconComponent(iconCloudSql),
  "Cloud DNS": createAwsIconComponent(iconGcpNetworking),
  "VPC Firewall": createAwsIconComponent(iconGcpNetworking),
  "Google Workspace": createAwsIconComponent(iconWorkspace),
  "Cloud DLP": createAwsIconComponent(iconDlp),
  "GCP Audit Logs": createAwsIconComponent(iconGcpAudit),
  GCP: createAwsIconComponent(iconGcp),
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

/** Always returns an icon — known service or IAM as a neutral fallback. */
const GenericFallbackIcon = createAwsIconComponent(iconIAM);

export function getServiceIconOrFallback(service: string): React.FC<IconProps> {
  return awsServiceIcons[service] || GenericFallbackIcon;
}
