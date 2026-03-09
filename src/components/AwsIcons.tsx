import React from "react";

interface IconProps {
  className?: string;
  size?: number;
}

const defaultSize = 24;

export const AwsIamIcon: React.FC<IconProps> = ({ className, size = defaultSize }) => (
  <svg viewBox="0 0 40 40" width={size} height={size} className={className} xmlns="http://www.w3.org/2000/svg">
    <path d="M20 4L6 10v12c0 8.5 5.5 16 14 18 8.5-2 14-9.5 14-18V10L20 4z" fill="#DD344C" />
    <path d="M20 8l-10 4.5v9c0 6.4 4.1 12 10 13.5V8z" fill="#DD344C" opacity="0.6" />
    <circle cx="20" cy="18" r="4" fill="#fff" />
    <path d="M16 24h8v3H16z" fill="#fff" />
  </svg>
);

export const AwsLambdaIcon: React.FC<IconProps> = ({ className, size = defaultSize }) => (
  <svg viewBox="0 0 40 40" width={size} height={size} className={className} xmlns="http://www.w3.org/2000/svg">
    <rect x="4" y="4" width="32" height="32" rx="2" fill="#E7A33E" />
    <path d="M14 30L20 10l6 20H14z" fill="#fff" />
    <path d="M16.5 28L20 16l3.5 12h-7z" fill="#E7A33E" />
  </svg>
);

export const AwsEc2Icon: React.FC<IconProps> = ({ className, size = defaultSize }) => (
  <svg viewBox="0 0 40 40" width={size} height={size} className={className} xmlns="http://www.w3.org/2000/svg">
    <rect x="4" y="4" width="32" height="32" rx="2" fill="#ED7100" />
    <rect x="12" y="12" width="16" height="16" rx="1" fill="none" stroke="#fff" strokeWidth="2" />
    <rect x="16" y="16" width="8" height="8" fill="#fff" />
  </svg>
);

export const AwsS3Icon: React.FC<IconProps> = ({ className, size = defaultSize }) => (
  <svg viewBox="0 0 40 40" width={size} height={size} className={className} xmlns="http://www.w3.org/2000/svg">
    <rect x="4" y="4" width="32" height="32" rx="2" fill="#3F8624" />
    <path d="M12 14h16l-2 14H14L12 14z" fill="#fff" />
    <ellipse cx="20" cy="14" rx="8" ry="3" fill="#fff" />
  </svg>
);

export const AwsEbsIcon: React.FC<IconProps> = ({ className, size = defaultSize }) => (
  <svg viewBox="0 0 40 40" width={size} height={size} className={className} xmlns="http://www.w3.org/2000/svg">
    <rect x="4" y="4" width="32" height="32" rx="2" fill="#3F8624" />
    <rect x="13" y="10" width="14" height="20" rx="2" fill="none" stroke="#fff" strokeWidth="2" />
    <path d="M16 14h8M16 18h8M16 22h5" stroke="#fff" strokeWidth="1.5" />
  </svg>
);

export const AwsDynamoDbIcon: React.FC<IconProps> = ({ className, size = defaultSize }) => (
  <svg viewBox="0 0 40 40" width={size} height={size} className={className} xmlns="http://www.w3.org/2000/svg">
    <rect x="4" y="4" width="32" height="32" rx="2" fill="#2E73B8" />
    <ellipse cx="20" cy="13" rx="8" ry="3" fill="none" stroke="#fff" strokeWidth="2" />
    <path d="M12 13v14c0 1.7 3.6 3 8 3s8-1.3 8-3V13" fill="none" stroke="#fff" strokeWidth="2" />
    <ellipse cx="20" cy="20" rx="8" ry="3" fill="none" stroke="#fff" strokeWidth="1.5" />
  </svg>
);

export const AwsCloudTrailIcon: React.FC<IconProps> = ({ className, size = defaultSize }) => (
  <svg viewBox="0 0 40 40" width={size} height={size} className={className} xmlns="http://www.w3.org/2000/svg">
    <rect x="4" y="4" width="32" height="32" rx="2" fill="#E7157B" />
    <path d="M10 26l5-8 4 4 6-10 5 8" fill="none" stroke="#fff" strokeWidth="2" strokeLinejoin="round" />
    <circle cx="10" cy="26" r="2" fill="#fff" />
    <circle cx="30" cy="20" r="2" fill="#fff" />
  </svg>
);

export const AwsKmsIcon: React.FC<IconProps> = ({ className, size = defaultSize }) => (
  <svg viewBox="0 0 40 40" width={size} height={size} className={className} xmlns="http://www.w3.org/2000/svg">
    <rect x="4" y="4" width="32" height="32" rx="2" fill="#DD344C" />
    <circle cx="18" cy="18" r="5" fill="none" stroke="#fff" strokeWidth="2" />
    <path d="M22 22l8 8M27 27l3-3M27 27l3 3" stroke="#fff" strokeWidth="2" />
  </svg>
);

export const AwsEksIcon: React.FC<IconProps> = ({ className, size = defaultSize }) => (
  <svg viewBox="0 0 40 40" width={size} height={size} className={className} xmlns="http://www.w3.org/2000/svg">
    <rect x="4" y="4" width="32" height="32" rx="2" fill="#ED7100" />
    <circle cx="20" cy="20" r="6" fill="none" stroke="#fff" strokeWidth="2" />
    <path d="M20 14v-4M20 30v-4M26 20h4M10 20h4M25 15l3-3M12 28l3-3M25 25l3 3M12 12l3 3" stroke="#fff" strokeWidth="1.5" />
  </svg>
);

export const AwsStsIcon: React.FC<IconProps> = ({ className, size = defaultSize }) => (
  <svg viewBox="0 0 40 40" width={size} height={size} className={className} xmlns="http://www.w3.org/2000/svg">
    <rect x="4" y="4" width="32" height="32" rx="2" fill="#DD344C" />
    <path d="M14 16h12v10H14z" fill="none" stroke="#fff" strokeWidth="2" />
    <path d="M17 16v-3a3 3 0 0 1 6 0v3" fill="none" stroke="#fff" strokeWidth="2" />
    <circle cx="20" cy="22" r="1.5" fill="#fff" />
  </svg>
);

export const awsServiceIcons: Record<string, React.FC<IconProps>> = {
  IAM: AwsIamIcon,
  Lambda: AwsLambdaIcon,
  EC2: AwsEc2Icon,
  S3: AwsS3Icon,
  EBS: AwsEbsIcon,
  DynamoDB: AwsDynamoDbIcon,
  CloudTrail: AwsCloudTrailIcon,
  KMS: AwsKmsIcon,
  EKS: AwsEksIcon,
  STS: AwsStsIcon,
};

export function getAwsServiceIcon(service: string): React.FC<IconProps> | null {
  return awsServiceIcons[service] || null;
}
