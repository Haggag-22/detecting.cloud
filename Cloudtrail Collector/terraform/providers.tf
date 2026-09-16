provider "aws" {
  # Region and credentials come from the environment (AWS_PROFILE / AWS_REGION,
  # SSO, or an instance role) rather than being hardcoded, so the same config
  # serves every engagement.
  default_tags {
    tags = var.tags
  }
}
