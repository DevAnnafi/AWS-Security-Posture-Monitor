# Environment Setup

This document describes the AWS environment for the Security Posture Monitor and the reasoning behind its structure. All commands were run and verified on 08/25/2026.

## Account structure

This is a dedicated sandbox account with no real data or workloads. I will be deliberately provisioning misconfigured resources, so account isolation makes it safe to do this.

## IAM: user vs. scanner role

* `annafi-cli` — admin IAM user, CLI-only (no console password), used for Terraform and account administration.
* `cspm-scanner-role` — IAM role with the AWS-managed `SecurityAudit` policy (read-only), assumed by the scanner.

If the scanner is buggy or compromised, it can inspect and read the AWS resources and configuration that `SecurityAudit` permits, but it cannot use the scanner identity to modify, delete, create, or administer those resources.

MFA is enabled, there are no root access keys, and the root user is unused after initial setup.

## Budget guardrails

I set a **$15 AWS budget** with two alert thresholds:

* **~$5 (33%)** — early warning that spending has started to increase.
* **$15 (100%)** — alert when the full budget has been reached.

Both alerts **email me directly**.

AWS Budgets only sends notifications; it does **not** automatically stop spending or terminate resources. If an alert fires, I log into AWS, identify which resource or service caused the charge, and if it was created accidentally, I destroy it and investigate why it was created.

## CLI profile chain

There are two AWS CLI profiles.

`cspm` holds the long-lived credentials for the `annafi-cli` IAM user:

```ini
[profile cspm]
region = us-east-1
output = json
```

`cspm-scanner` does not have credentials of its own. It uses `source_profile = cspm` to authenticate as the IAM user and then assumes the scanner role:

```ini
[profile cspm-scanner]
role_arn = arn:aws:iam::<account-id>:role/cspm-scanner-role
source_profile = cspm
region = us-east-1
```

This means the scanner only operates with **temporary STS credentials** from the assumed role rather than storing another set of long-lived access keys.

The credential flow is:

`cspm` → `annafi-cli` IAM user → STS AssumeRole → `cspm-scanner-role` → temporary credentials → CSPM scanner

## Verification

### Verify the administrative profile

```bash
aws sts get-caller-identity --profile cspm
```

This proves that the `cspm` profile successfully authenticates as the `annafi-cli` IAM user and returns the user's ARN.

The output should identify the IAM user, for example:

```text
arn:aws:iam::<account-id>:user/annafi-cli
```

### Verify the scanner profile

```bash
aws sts get-caller-identity --profile cspm-scanner
```

This proves that the profile successfully assumes `cspm-scanner-role` and returns an assumed-role ARN, for example:

```text
arn:aws:sts::<account-id>:assumed-role/cspm-scanner-role/...
```

The scanner is therefore operating under the role's `SecurityAudit` permissions rather than the administrative user's permissions.

## Repository hygiene

The Terraform repository lives outside cloud-synced folders because Terraform state can be written non-atomically. A sync client can interfere with those writes and cause state conflicts or corruption.

`.gitignore` excludes Terraform state, the Terraform working directory, and environment files:

```gitignore
*.tfstate
*.tfstate.backup
.terraform/
.env
```

Terraform state can contain sensitive infrastructure information, so it should not be treated like ordinary source code or committed to the repository.

## Defense questions

### Why does the scanner need read-only but the remediation Lambda write?

The scanner reads because detection does not require mutation. The remediation Lambda writes because fixing a finding requires changing resources. They therefore use separate roles with different permissions, following least privilege.

### What's the risk if they share a role?

If they share a role, a scanner bug or compromise could give the scanner the remediation Lambda's write permissions. That collapses the least-privilege boundary and increases the blast radius of a scanner compromise.

### What's the blast radius if `~/.aws/credentials` leaks?

The file contains the long-lived credentials for my `cspm` profile, which authenticates as the `annafi-cli` IAM user. Because that user is used for Terraform and account administration, an attacker with those credentials could potentially make changes across the account to the extent of that user's permissions.

The scanner's read-only role does not protect against this because the leaked credentials belong to the administrative user, not the scanner role.

In the first five minutes, I would disable the exposed access key, check CloudTrail for activity using it, rotate the credentials, update my laptop's `~/.aws/credentials` with the replacement credentials, and check for unauthorized IAM changes or resources.
