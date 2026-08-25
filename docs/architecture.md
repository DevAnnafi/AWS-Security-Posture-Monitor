# Architecture notes

## Threat Model

| Misconfiguration | STRIDE category | Attack narrative | CIS control |
| :--- | :--- | :--- | :--- |
| Public S3 bucket | Information Disclosure | An attacker can read, steal, modify, or delete data and use a public Amazon S3 bucket to host malware if the permissions allow it. | 3.1.4 |
| SSH open to 0.0.0.0/0 | Elevation of Privilege | An attacker can brute force the SSH daemon, create a shell on the instance and steal that user's credentials. | 6.3 |
| Policies that grant full `*:*` admin attached directly to users | Elevation of Privilege | A leaked credential gives an attacker full administrative access to the account. One compromised credential can therefore become control of the entire account. | 2.14 |
| Disabled CloudTrail or Config | Repudiation | An attacker can operate inside a cloud environment with complete invisibility, destroying accountability and blocking forensic investigations. | 4.1 |
| IAM user without MFA or access keys unrotated 90+ days | Spoofing and Information Disclosure | Without MFA, a stolen credential is enough for an attacker to act as the IAM user. If the access key is never rotated, the stolen key remains usable. | 2.10, 2.12 |

## CIS Control References

The following controls are from the **CIS Amazon Web Services Foundations Benchmark v7.0.0**. All six are Level 1 recommendations; 2.10, 2.12, 2.14, 3.1.4, and 6.3 are Automated, while 4.1 is Manual.

| Control | CIS recommendation | Profile | Assessment |
| :--- | :--- | :--- | :--- |
| 2.10 | Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password | Level 1 | Automated |
| 2.12 | Ensure access keys are rotated every 90 days or less | Level 1 | Automated |
| 2.14 | Ensure IAM policies that allow full "*:*" administrative privileges are not attached | Level 1 | Automated |
| 3.1.4 | Ensure that S3 is configured with 'Block Public Access' enabled | Level 1 | Automated |
| 4.1 | Ensure CloudTrail is enabled in all regions | Level 1 | Manual |
| 6.3 | Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports | Level 1 | Automated |

## Scope Boundary

The Security Posture Monitor is intentionally limited to **cloud configuration posture**. It evaluates whether AWS resources are configured in ways that create recognizable security weaknesses; it does not attempt to become a complete runtime security, data governance, or multi-account security platform.

- **Runtime detection:** Runtime compromise, malicious processes, command execution, persistence, and other activity occurring after a resource has been compromised are outside the monitor's scope. These concerns are better covered by **EDR, workload runtime security, and SIEM/behavioral detection tooling**.
- **Data classification:** The monitor can identify configuration conditions such as public S3 access, but it does not determine whether the underlying data is public, confidential, regulated, or otherwise sensitive. These concerns are better covered by **data discovery, classification, DLP, and data-security tooling**.
- **Multi-account governance:** The monitor does not assess organization-wide account structure, cross-account guardrails, or centralized governance. These concerns are better covered by **AWS Organizations, Control Tower, SCP analysis, and multi-account CSPM/governance tooling**.
- **Application vulnerabilities:** The monitor does not inspect application source code, dependencies, or application behavior for vulnerabilities. These concerns are better covered by **SAST, DAST, SCA, and application-security tooling**.

These exclusions keep the project focused on detecting **configuration-level security weaknesses** rather than reproducing the capabilities of several separate security platforms.

## Severity Philosophy

Severity is based primarily on **internet exposure, the directness of the path to sensitive data or account takeover, and whether an attacker must first obtain a foothold**. A directly exposed administrative interface or a configuration that turns one compromised credential into full account control is therefore more severe than a weakness that requires an existing foothold or additional conditions. Because the tool cannot determine the sensitivity of the underlying data, severity assumes worst-case contents when evaluating a configuration that could expose data.

## Defense Questions

### Why CIS instead of NIST 800-53 or AWS Foundational Security Best Practices?

CIS AWS Foundations Benchmark is a **prescriptive configuration benchmark** maintained by the Center for Internet Security and focused on concrete, testable AWS configuration recommendations. NIST SP 800-53 is a broader **security and privacy control catalog** maintained by NIST; it defines organizational and technical controls that can be implemented across many types of information systems rather than prescribing AWS-specific configuration checks. AWS Foundational Security Best Practices is a **vendor-native AWS security standard** maintained by AWS and implemented through AWS security tooling such as Security Hub.

If NIST 800-53 had been selected, the project would cite NIST control identifiers and would need to translate broader controls into AWS-specific checks. If AWS Foundational Security Best Practices had been selected, the findings would instead cite AWS-native control identifiers and align more directly with the AWS tooling ecosystem. The actual check set, finding references, and integration points would therefore change even where the underlying security objective was similar. MITRE ATT&CK could complement either choice by describing adversary behavior, but it is not a substitute for the configuration baseline itself.

### Which control produces the most false positives?

**6.3 — Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports** is the most likely to produce an intentional finding. An organization may deliberately expose an administration port in a controlled design, such as a bastion host, provided another security mechanism controls or protects the access path. The CIS guidance itself recognizes this operational consideration.

**2.12** can also produce legitimate findings for service accounts or legacy integrations that require long-lived access keys, but that does not eliminate the underlying credential-lifetime risk. The control specifically requires access keys to be rotated every 90 days or less.

## Design Decisions

Design decisions for the check interface and finding storage will be added in later units. recommended that all access keys be rotated regularly and at least every 90 days. | Level 1 |
| 2.14 | It is recommended and considered standard security advice to grant least privilege, granting only the permissions required to perform a task | Level 1 | 
| 3.1.4 | Whether to block public access to all or some buckets is an organizational decision that should be based on data sensitivity, least privilege, and use case. | Level 1 |
| 4.1 | Ensure CloudTrail is enabled in all regions | Level 1 | 
| 6.3 | Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports | Level 1 |

These controls were selected because they provide concrete configuration checks for identity, authorization, storage exposure, logging, and network exposure. CIS defines Level 1 as the baseline security profile intended to reduce common attack surface without requiring the more restrictive assumptions of Level 2.




