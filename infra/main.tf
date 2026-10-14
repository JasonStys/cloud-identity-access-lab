# Jason Stys: provider-free AWS trust/identity/boundary document generator, not a cloud deployment.
# BEGIN CODE MAP (generated; python scripts/code_map.py)
# configuration: required_version — line 44
# variable: account_id — line 48
# configuration: type — line 49
# configuration: default — line 50
# configuration: condition — line 52
# configuration: error_message — line 53
# variable: subject — line 56
# configuration: type — line 57
# configuration: default — line 58
# configuration: condition — line 60
# configuration: error_message — line 61
# variable: bucket — line 64
# configuration: type — line 65
# configuration: default — line 66
# configuration: condition — line 68
# configuration: error_message — line 69
# configuration: resource — line 75
# configuration: trust — line 76
# configuration: Version — line 77
# configuration: Statement — line 78
# configuration: Effect — line 79
# configuration: Action — line 80
# configuration: Principal — line 81
# configuration: Condition — line 82
# configuration: identity — line 88
# configuration: Version — line 89
# configuration: Statement — line 90
# configuration: Effect — line 91
# configuration: Action — line 92
# configuration: Resource — line 93
# configuration: boundary — line 96
# configuration: Version — line 97
# configuration: Statement — line 98
# output: trust — line 104
# configuration: value — line 105
# output: identity — line 107
# configuration: value — line 108
# output: boundary — line 110
# configuration: value — line 111
# END CODE MAP
terraform {
  required_version = "= 1.16.5"
}

# Defaults are fictional. Exact immutable IDs prevent subject-prefix/wildcard trust.
variable "account_id" {
  type    = string
  default = "111122223333"
  validation {
    condition     = can(regex("^[0-9]{12}$", var.account_id))
    error_message = "Expected an exact 12-digit synthetic AWS account identifier."
  }
}
variable "subject" {
  type    = string
  default = "repo:synthetic-org@101/synthetic-release@202:ref:refs/heads/main"
  validation {
    condition     = can(regex("^repo:[A-Za-z0-9_-]+@[0-9]+/[A-Za-z0-9_.-]+@[0-9]+:ref:refs/heads/[A-Za-z0-9_/-]+$", var.subject))
    error_message = "Expected one exact immutable GitHub branch subject; wildcards and environment ambiguity are forbidden."
  }
}
variable "bucket" {
  type    = string
  default = "synthetic-alpha-artifacts"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,61}[a-z0-9]$", var.bucket))
    error_message = "Expected a simple exact bucket name, without ARN, slash or wildcard."
  }
}

# AWS-shaped documents are separate from the generic Rego resource model.
locals {
  resource = "arn:aws:s3:::${var.bucket}/releases/*"
  trust = {
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRoleWithWebIdentity"
      Principal = { Federated = "arn:aws:iam::${var.account_id}:oidc-provider/token.actions.githubusercontent.com" }
      Condition = { StringEquals = {
        "token.actions.githubusercontent.com:aud" = "sts.amazonaws.com"
        "token.actions.githubusercontent.com:sub" = var.subject
      } }
    }]
  }
  identity = {
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject"]
      Resource = local.resource
    }]
  }
  boundary = {
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["s3:PutObject"], Resource = local.resource },
      { Effect = "Deny", Action = ["s3:DeleteObject"], Resource = local.resource }
    ]
  }
}
output "trust" {
  value = local.trust
}
output "identity" {
  value = local.identity
}
output "boundary" {
  value = local.boundary
}
