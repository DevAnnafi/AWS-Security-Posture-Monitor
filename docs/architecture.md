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

These controls were selected because they provide concrete configuration checks across identity, authorization, storage exposure, logging, and network exposure. CIS defines Level 1 as the baseline security profile intended to reduce common attack surface without requiring the more restrictive assumptions of Level 2.

## Scope Boundary

The Security Posture Monitor is intentionally limited to **cloud configuration posture**. It evaluates whether AWS resources are configured in ways that create recognizable security weaknesses; it does not attempt to become a complete runtime security, data governance, or multi-account security platform.

- **Runtime detection:** Runtime compromise, malicious processes, command execution, persistence, and other activity occurring after a resource has been compromised are outside the monitor's scope. These concerns are better covered by **EDR, workload runtime security, and SIEM/behavioral detection tooling**.
- **Data classification:** The monitor can identify configuration conditions such as public S3 access, but it does not determine whether the underlying data is public, confidential, regulated, or otherwise sensitive. These concerns are better covered by **data discovery, classification, DLP, and data-security tooling**.
- **Multi-account governance:** The monitor does not assess organization-wide account structure, cross-account guardrails, or centralized governance. These concerns are better covered by **AWS Organizations, Control Tower, SCP analysis, and multi-account CSPM/governance tooling**.
- **Application vulnerabilities:** The monitor does not inspect application source code, dependencies, or application behavior for vulnerabilities. These concerns are better covered by **SAST, DAST, SCA, and application-security tooling**.

These exclusions keep the project focused on detecting **configuration-level security weaknesses** rather than reproducing the capabilities of several separate security platforms.

## Severity Philosophy

Severity is based primarily on **internet exposure, the directness of the path to sensitive data or account takeover, and whether an attacker must first obtain a foothold**. A directly exposed administrative interface or a configuration that turns one compromised credential into full account control is therefore more severe than a weakness that requires an existing foothold or additional conditions. Because the tool cannot determine the sensitivity of the underlying data, severity assumes worst-case contents when evaluating a configuration that could expose data.

---

## Design Decisions

### 1. Checks return a `CheckResult` with an explicit status, not a bare list of findings

A check has three possible outcomes, not two: it found violations, it evaluated the resources and found them compliant, or it could not evaluate them at all. Returning a bare `list[Finding]` collapses the second and third cases into the same empty list.

That collapse is a security failure, not just an API wart. If the scanner lacks `s3:GetBucketPolicy` and the exception is swallowed, the scan reports zero findings and the operator concludes the environment is clean. A scanner that produces false confidence is more dangerous than one that crashes, because the operator acts on the result.

Checks therefore return a `CheckResult` carrying a status enum alongside any findings. A caller distinguishes compliant from unevaluable by inspecting `status`. "Unknown" is deliberately *not* a `Severity` member — an unevaluable check produces no `Finding` at all, because a finding asserts that something is wrong, and this case asserts only that we do not know.

**Cost:** every caller must handle three branches rather than truth-testing a list.

### 2. Check metadata lives on the check class

Each check is a subclass of an abstract `BaseCheck` and declares its CIS control ID, title, severity, remediability, and data dependencies as class attributes.

The alternative was decorated functions with metadata passed as decorator arguments. Class attributes were chosen because the registry can be introspected without executing any check — which means the README control table, the coverage comparison in `docs/tool-comparison.md`, and the API's control filter can all be generated from the registry rather than maintained by hand. Metadata that is duplicated by hand drifts; metadata with one source does not.

**Cost:** more ceremony per check than a bare decorated function, and a check that needs no state still has to be a class.

### 3. Collect-then-evaluate, not a memoized session

Collection and evaluation are separate phases. A collector gathers an inventory snapshot from AWS once; checks are pure functions over that snapshot and never call boto3 themselves.

The alternative was handing each check a memoized AWS session that caches calls. Both solve the immediate problem — three S3 checks should not each call `list_buckets` — but collect-then-evaluate buys three things the memoized session does not:

- **Testability.** A check under test receives a dictionary. The test suite needs no AWS credentials, no `moto`, and no stubbing. This is what makes the Unit 7 requirement — a credential-free suite in CI — cheap rather than laborious.
- **Point-in-time consistency.** Every check evaluates the same snapshot, so a resource changing mid-scan cannot produce a self-contradictory report.
- **Replayability.** A serialized snapshot can be re-scanned offline, which makes a finding reproducible without re-querying the account.

**Cost — two things given up:**

- **Laziness.** The collector gathers its whole inventory regardless of which checks will run, so a single-check scan pays for data it does not use.
- **Localization.** A check's data requirements no longer live in the check. Adding a check that needs data the collector does not yet gather means editing two files instead of one, and the snapshot schema becomes a contract between collector and checks that must be maintained deliberately.

The snapshot schema must also represent *why* data is absent. A bucket with no policy and a bucket whose policy could not be read are not the same state, so per-resource collection status is part of the schema rather than an afterthought. `BaseCheck` declares which snapshot sections it requires; the runner inspects collection status for those sections and returns `UNEVALUABLE` without invoking the check. This keeps the check pure while still surfacing the third outcome from decision 1.

### 4. Findings carry a deterministic ID with a sub-resource discriminator

`Finding.finding_id` is a SHA-256 digest computed in `__post_init__` from account ID, region, control ID, resource ID, and sub-resource ID, joined with `|`. It is not a random UUID and does not include the timestamp or the severity.

Determinism is required by suppression. If a user suppresses a finding on Monday, Tuesday's scan of the same unchanged misconfiguration must produce the same identifier, or the suppression silently fails to match and the finding reappears. Timestamp and severity are excluded for the same reason: the first changes every scan, and the second is recomputed by the scoring model, so including either would orphan existing suppressions.

`resource_sub_id` exists because account + region + control + resource is not always unique. A single security group with three rules opening `0.0.0.0/0` on three different administration ports is one resource violating one control three times. Without a discriminator those three findings hash identically, collapse into one, and suppressing one would suppress its siblings. Checks that have no sub-resource pass `None`, which is normalized to an empty string before hashing so that `None` and a literal `"None"` cannot collide.

**Cost:** the hash inputs and their order are a permanent contract. Changing either invalidates every stored suppression, so the field list is versioned rather than edited in place.

---

## Defense Questions

### Why CIS instead of NIST 800-53 or AWS Foundational Security Best Practices?

CIS AWS Foundations Benchmark is a **prescriptive configuration benchmark** maintained by the Center for Internet Security and focused on concrete, testable AWS configuration recommendations. NIST SP 800-53 is a broader **security and privacy control catalog** maintained by NIST; it defines organizational and technical controls that can be implemented across many types of information systems rather than prescribing AWS-specific configuration checks. AWS Foundational Security Best Practices is a **vendor-native AWS security standard** maintained by AWS and implemented through AWS security tooling such as Security Hub.

If NIST 800-53 had been selected, the project would cite NIST control identifiers and would need to translate broader controls into AWS-specific checks. If AWS Foundational Security Best Practices had been selected, the findings would instead cite AWS-native control identifiers and align more directly with the AWS tooling ecosystem. The actual check set, finding references, and integration points would therefore change even where the underlying security objective was similar. MITRE ATT&CK could complement either choice by describing adversary behavior, but it is not a substitute for the configuration baseline itself.

### Which control produces the most false positives?

**6.3 — Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports** is the most likely to produce an intentional finding. An organization may deliberately expose an administration port in a controlled design, such as a bastion host, provided another security mechanism controls or protects the access path. The CIS guidance itself recognizes this operational consideration.

**2.12** can also produce legitimate findings for service accounts or legacy integrations that require long-lived access keys, but that does not eliminate the underlying credential-lifetime risk. The control specifically requires access keys to be rotated every 90 days or less.