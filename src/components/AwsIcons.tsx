import React from "react";

import iconIAM from "@/assets/icons/aws/IAM.svg";
import iconLambda from "@/assets/icons/aws/Lambda.svg";
import iconEC2 from "@/assets/icons/aws/EC2.svg";
import iconS3 from "@/assets/icons/aws/S3.svg";
import iconEBS from "@/assets/icons/aws/EBS.svg";
import iconEFS from "@/assets/icons/aws/EFS.svg";
import iconDynamoDB from "@/assets/icons/aws/DynamoDB.svg";
import iconRDS from "@/assets/icons/aws/RDS.svg";
import iconCloudTrail from "@/assets/icons/aws/CloudTrail.svg";
import iconConfig from "@/assets/icons/aws/Config.svg";
import iconKMS from "@/assets/icons/aws/KMS.svg";
import iconEKS from "@/assets/icons/aws/EKS.svg";
import iconECS from "@/assets/icons/aws/ECS.svg";
import iconSecretsManager from "@/assets/icons/aws/SecretsManager.svg";
import iconSSM from "@/assets/icons/aws/SSM.svg";
import iconOrganizations from "@/assets/icons/aws/Organizations.svg";
import iconSageMaker from "@/assets/icons/aws/SageMaker.svg";
import iconSES from "@/assets/icons/aws/SES.svg";
import iconCodeBuild from "@/assets/icons/aws/CodeBuild.svg";
import iconElasticBeanstalk from "@/assets/icons/aws/ElasticBeanstalk.svg";
import iconCloudFront from "@/assets/icons/aws/CloudFront.svg";
import iconGuardDuty from "@/assets/icons/aws/GuardDuty.svg";
import iconSecurityHub from "@/assets/icons/aws/SecurityHub.svg";
import iconVPC from "@/assets/icons/aws/VPC.svg";
import iconELB from "@/assets/icons/aws/ELB.svg";
import iconRoute53 from "@/assets/icons/aws/Route53.svg";
import iconGlue from "@/assets/icons/aws/Glue.svg";
import iconDirectoryService from "@/assets/icons/aws/DirectoryService.svg";
import iconIAMIdentityCenter from "@/assets/icons/aws/IAMIdentityCenter.svg";
import iconSTS from "@/assets/icons/aws/STS.svg";
import iconAutoScaling from "@/assets/icons/aws/AutoScaling.svg";
import iconBackup from "@/assets/icons/aws/Backup.svg";
import iconBedrock from "@/assets/icons/aws/Bedrock.svg";
import iconCloudFormation from "@/assets/icons/aws/CloudFormation.svg";
import iconCognito from "@/assets/icons/aws/Cognito.svg";
import iconEventBridge from "@/assets/icons/aws/EventBridge.svg";
import iconRolesAnywhere from "@/assets/icons/aws/RolesAnywhere.svg";

import iconEntraID from "@/assets/icons/azure/EntraID.svg";
import iconEntraIDProtection from "@/assets/icons/azure/EntraIDProtection.svg";
import iconEntraIDApps from "@/assets/icons/azure/EntraIDApps.svg";
import iconEntraIDPIM from "@/assets/icons/azure/EntraIDPIM.svg";
import iconKeyVault from "@/assets/icons/azure/KeyVault.svg";
import iconAKS from "@/assets/icons/azure/AKS.svg";
import iconAzureActivity from "@/assets/icons/azure/AzureActivity.svg";
import iconAzureNetworking from "@/assets/icons/azure/AzureNetworking.svg";

import iconGcpIAM from "@/assets/icons/gcp/IdentityAndAccessManagement.svg";
import iconGke from "@/assets/icons/gcp/GoogleKubernetesEngine.svg";
import iconCloudStorage from "@/assets/icons/gcp/CloudStorage.svg";
import iconCloudSql from "@/assets/icons/gcp/CloudSQL.svg";
import iconCloudDns from "@/assets/icons/gcp/CloudDNS.svg";
import iconGcpFirewall from "@/assets/icons/gcp/CloudFirewallRules.svg";
import iconWorkspace from "@/assets/icons/gcp/IdentityPlatform.svg";
import iconDlp from "@/assets/icons/gcp/DataLossPrevention.svg";
import iconGcp from "@/assets/icons/gcp/CloudGeneric.svg";
import iconGcpAudit from "@/assets/icons/gcp/CloudAuditLogs.svg";

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
  STS: createAwsIconComponent(iconSTS),
  "Auto Scaling": createAwsIconComponent(iconAutoScaling),
  Backup: createAwsIconComponent(iconBackup),
  Bedrock: createAwsIconComponent(iconBedrock),
  CloudFormation: createAwsIconComponent(iconCloudFormation),
  Cognito: createAwsIconComponent(iconCognito),
  EventBridge: createAwsIconComponent(iconEventBridge),
  "Roles Anywhere": createAwsIconComponent(iconRolesAnywhere),

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
  "Cloud DNS": createAwsIconComponent(iconCloudDns),
  "VPC Firewall": createAwsIconComponent(iconGcpFirewall),
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
