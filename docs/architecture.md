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

Severity is determined solely by the impact of the granted access: what an attacker can do with the exposed configuration. The scanner uses three severity levels based on that capability, with the level assigned independently for each finding. See Decision 9 for the rationale and detailed methodology.

---

## Design Decisions

### 1. Checks return a `CheckResult` with an explicit status, not a bare list of findings

A check has three possible outcomes, not two: it found violations, it evaluated the resources and found them compliant, or it could not evaluate them at all. Returning a bare `list[Finding]` collapses the second and third cases into the same empty list.

That collapse is a security failure, not just an API wart. If the scanner lacks `s3:GetBucketPolicy` and the exception is swallowed, the scan reports zero findings and the operator concludes the environment is clean. A scanner that produces false confidence is more dangerous than one that crashes, because the operator acts on the result.

Checks therefore return a `CheckResult` carrying a status enum alongside any findings. A caller distinguishes compliant from unevaluable by inspecting `status`. "Unknown" is deliberately *not* a `Severity` member — an unevaluable check produces no `Finding` at all, because a finding asserts that something is wrong, and this case asserts only that we do not know.

**Cost:** every caller must handle three branches rather than truth-testing a list.

### 2. Check metadata lives on the check class

Each check is a subclass of an abstract `BaseCheck` and declares its CIS control ID, title, remediability, and data dependencies as class attributes.

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

`BaseCheck` declares which snapshot sections it requires; the runner inspects collection status for those sections before invoking the check. This keeps the check pure while still surfacing the third outcome from decision 1. How absent data is represented within a section is covered in decision 5.

A caveat on point-in-time consistency: the snapshot is consistent but not atomic. Collection takes time, so a bucket read at second 2 and a security group read at second 40 reflect different moments, and a snapshot may describe a state the account never actually occupied. Atomicity is not achievable through the AWS APIs, so the snapshot records its own collection window and a scan is understood as approximately consistent over that window rather than as an instant.

### 4. Findings carry a deterministic ID with a sub-resource discriminator

`Finding.finding_id` is a SHA-256 digest computed in `__post_init__` from account ID, region, control ID, resource ID, and sub-resource ID, joined with `|`. It is not a random UUID and does not include the timestamp or the severity.

Determinism is required by suppression. If a user suppresses a finding on Monday, Tuesday's scan of the same unchanged misconfiguration must produce the same identifier, or the suppression silently fails to match and the finding reappears. Timestamp and severity are excluded for the same reason: the first changes every scan, and the second is recomputed by the scoring model, so including either would orphan existing suppressions.

`resource_sub_id` exists because account + region + control + resource is not always unique. A single security group with three rules opening `0.0.0.0/0` on three different administration ports is one resource violating one control three times. Without a discriminator those three findings hash identically, collapse into one, and suppressing one would suppress its siblings. Checks that have no sub-resource pass `None`, which is normalized to an empty string before hashing so that `None` and a literal `"None"` cannot collide.

**Cost:** the hash inputs and their order are a permanent contract. Changing either invalidates every stored suppression, so the field list is versioned rather than edited in place.

### 5. Every collected value carries its own retrieval status

Each value in the snapshot is wrapped in a dict holding a `status` that records whether the read succeeded, alongside the value itself. The value is not stored bare.

The motivating case is S3. A bucket with no policy attached and a bucket whose policy returned `AccessDenied` both have `document: None`. They are distinguished only by `status`:

```
bucket-b   policy: {"status": "ok",            "document": None}
bucket-c   policy: {"status": "access_denied", "document": None}
```

Without the wrapper the two are identical, and a check reading `policy` would see `None`, conclude "no policy, therefore not public," and report a potentially exposed bucket as clean. That is the silent false negative described in decision 1, arriving through the data layer rather than through exception handling.

Status is per value rather than per section, because failures are partial. `list_buckets` can succeed while `get_bucket_policy` fails on one bucket out of fifty. A section-level status alone would either discard forty-nine valid results or mask one unreadable resource.

The status vocabulary belongs to the collector and describes retrieval outcomes (`ok`, `access_denied`, and later throttling and not-found). It is deliberately distinct from `CheckStatus`, which describes a check's verdict. The collector reports what it managed to read; the check reports what that means.

**Cost:** every read inside a check is two levels deep, and the collector cannot store raw API responses unmodified.

### 6. Partial results

A check may evaluate some resources successfully and others not at all. In the S3 case, buckets A and B are fully readable while bucket C returned `AccessDenied` on its policy, so the check can reach a verdict for two of three buckets.

**Decision:** Add `PARTIAL` as a `CheckResult` status and add an `unevaluated` field identifying resources that could not be evaluated. `PARTIAL` is used when at least one resource was evaluated and at least one was unreachable. If no resources can be evaluated at all, the status is `CANT_EVALUATE`.

The rejected alternative is to keep the overall status as `VIOLATIONS` and put unreachable resources only in a separate field. That would require every consumer to remember to inspect the field; a consumer that forgets renders a complete-looking report of an incomplete scan. `PARTIAL` makes incompleteness part of the result's primary status rather than optional metadata.

**Rule:** Reachability and correctness are orthogonal. A resource being unreachable does not imply a violation, and a `PARTIAL` result must preserve the findings from resources that were successfully evaluated.

**Cost:** Consumers must distinguish `PARTIAL` from both clean and violating results, and operators need to inspect `findings` to determine whether the evaluated resources contained violations.

### 7. S3 Public Access Finding Design

S3 public-access findings use resource_sub_id to distinguish multiple findings produced for the same bucket and control. The sub-resource identifies the specific access mechanism, such as acl or policy.

Severity is determined by the granted permission represented by the finding, not by the access mechanism or group name. The previous PublicExposure severity model was removed; S3PublicAccess no longer carries per-mechanism severities. Each Finding receives its severity from the granted permission when it is constructed.


### 8. Deferred (and Realized) Multi-Region Support

Decision: Initially, the snapshot represented a single collection scope, intentionally deferring any regional wrappers until multi-region collection was actually built. In Unit 6, this was implemented: the structure evolved so that sections like `security_groups` became wrappers containing per-region entries.

Reasoning: Early on, a single section-level status was correct because a single API operation was the unit of collection. However, one status could not represent independent success and failure across multiple AWS regions. Rather than prematurely engineering a multi-region abstraction before it was needed, the structure was kept flat.

When multi-region collection was introduced, the model shifted: each regional entry now holds its own status and document. The outer wrapper aggregates these regional results — reporting ok if every region succeeded, access_denied if none did, and partial if mixed. The consuming checks were updated to match. For example, `SecurityGroupAdminPorts` now iterates through the regions and explicitly records any denied regions as target_type: "region" entries in the `unevaluated` list.

Cost: The predicted migration cost came due as written. The security_groups wrapper changed, `SecurityGroupAdminPorts` changed with it, and the test fixtures carrying that section were updated. Deferring the abstraction avoided building it against a collector that did not yet exist.

### 9. The impact of the granted access dictates each finding’s severity.

Decision: Severity uses one factor with three levels, mapped directly to Severity. The level is determined separately for each finding based on what the granted access permits an attacker to do. For policy findings, the level comes from the granted policy actions; for ACL findings, from the ACL permission; and for security-group findings, from the exposed port.

Reasoning: The model originally considered multiple factors, including exposure and blast radius, then separated capability before returning to a single factor. Reachability did not meaningfully discriminate among the current findings: three of the four findings represent unauthenticated access from the internet. A factor that is effectively constant across the findings does not provide useful separation, so severity is based on capability — what the access actually allows an attacker to do.

Rejected alternative: The rejected approach was to enumerate known write or otherwise dangerous actions and treat unknown actions as safe. This was rejected because the scanner cannot reliably determine whether an unfamiliar action is dangerous. Defaulting unknown permissions to safe would create false negatives. Instead, the scanner uses a safe-list inversion: it explicitly enumerates read-only actions that are provably safe and treats every other action as level 2. This follows the same unknown-assume-worse principle used elsewhere in the scanner.

Cost: The safe-list is deliberately conservative. An action such as s3:GetBucketLocation is harmless but currently scores as level 2 until it is explicitly added to the safe list. This creates some false severity elevation in exchange for avoiding the more dangerous assumption that an unknown permission is safe.

Why LOW is unused: Every finding currently emitted by this scanner represents an unintended public exposure, so none belongs at LOW. LOW is reserved for findings that are non-compliant but not themselves exploitable, such as access-key age or missing MFA; those findings arrive through controls 2.10 and 2.12 rather than the public-exposure checks.

Limitation: The severity levels are relative to the findings the scanner detects today, rather than an absolute ranking of all possible security findings. The current three-level model is calibrated around public-exposure findings and their granted capability. As additional checks are added, particularly IAM-specific checks, new findings may introduce capabilities that require the severity ladder or its ordering to be revisited. The model should therefore be treated as an explicit policy for the current detection surface, not as a permanently fixed severity hierarchy.

### 10. Remediation handlers are separate from checks and keyed by control ID

**Decision:** Remediation logic lives separately from detection checks and is registered by CIS control ID. A check determines whether a configuration violates a control; a remediation handler applies the corrective action in the Lambda execution context.

The execution contexts are deliberately different. Checks are pure functions over a read-only snapshot and never call boto3. Remediation runs inside Lambda in response to an EventBridge event and requires write permissions. Keeping the two concerns separate prevents write-capable remediation code from becoming part of the detection path and keeps checks independently testable.

The alternative was a `remediate()` method on each `BaseCheck` subclass. That would put detection and mutation in the same abstraction even though they have different inputs, permissions, and execution environments. A separate registry also makes the control ID the stable boundary between a finding and the action that can remediate it.

**Cost:** The expected deployment-size benefit did not materialize. The Lambda ships the whole scanner package anyway, so separating remediation from checks does not reduce the deployed package by excluding unused detection code. The separation is therefore for execution-context and design-boundary reasons, not package-size optimization.

---

### 11. The remediation Lambda re-scans the resource instead of trusting the event payload

**Decision:** When a configuration-change event triggers the remediation Lambda, the Lambda re-reads the affected resource from AWS and runs the same detection implementation before taking corrective action. The event identifies what changed; it is not treated as proof that the resource is currently in violation.

This keeps detection logic in one place. The same check that identifies a misconfiguration during a normal scan determines whether the resource still violates the control when remediation runs. The Lambda does not maintain a second, event-specific interpretation of the security condition.

Re-scanning also handles the case where the resource changed again between the original event and Lambda execution. The remediation decision is based on the current AWS state rather than on potentially stale event data.

**Cost:** Every remediation invocation makes additional AWS API calls to read the resource and evaluate the finding. The Lambda therefore needs read permissions in addition to the write permissions required to fix the configuration. This is an intentional trade-off for using one detection implementation and acting on current state rather than stale event data.

---

### 12. Auto-remediation is threshold-based and limited to exact administrative ports

**Decision:** Auto-remediation applies only when the detected exposure crosses a narrow, explicit threshold. For security groups, the automatic remediation condition is an exact administrative-port match: TCP port 22 or 3389 exposed to `0.0.0.0/0`. Broad port ranges are reported as findings but are not automatically modified.

`IpProtocol: "-1"` is never automatically remediated. AWS omits the port fields for this rule type because it represents unrestricted protocol and port access. Although it clearly represents a serious exposure, automatically changing an unrestricted rule requires making a broader assumption about the intended network configuration.

The same principle applies to ranges. A rule covering `0-65535` includes ports 22 and 3389, but it may have been deliberately created for an application or network design that the scanner cannot infer. The scanner therefore alerts on broad ranges rather than assuming that deleting or narrowing the rule is safe.

The threshold answers the operational question: **when would auto-remediation cause an outage?** It could cause an outage when the scanner changes a rule that was intentionally required by an application or administrator. Auto-remediation is therefore restricted to the cases where the intended corrective action is sufficiently specific to justify an automatic change.

**Cost:** Some genuinely dangerous configurations will remain for manual remediation. A broad range or unrestricted `IpProtocol: "-1"` rule can be more permissive than an exact port-22 rule, but the system deliberately accepts an alert instead of taking an action that could disrupt legitimate traffic.

---

### 13. CIS 2.14 is detect-only

**Decision:** CIS 2.14 detects attached IAM policies granting full `*:*` administrative privileges but does not automatically detach or modify the policy.

The finding is clear enough to detect, but the safe corrective action is not. An attached administrative policy may be intentional and may support a legitimate workload, deployment system, or administrator. Automatically detaching it could remove permissions that a real system requires.

This follows the same remediation boundary used elsewhere: auto-remediation requires confidence that the corrective action is safe, not merely confidence that the configuration violates the benchmark. For 2.14, the scanner can establish the violation but cannot establish that detaching the policy is operationally safe.

A remediation that causes an outage is worse than leaving the finding in place for an operator to review. The control is therefore intentionally **detect-only** until the project has enough context to distinguish an unwanted administrative attachment from a legitimate one.

**Cost:** IAM findings require manual remediation. The system may continue to report an attached `*:*` policy until an operator determines whether removing it is safe.

### 14. The Choice Of A Database

I chose Postgres over SQLite because the application is intended to resemble a production deployment, where scans may eventually run concurrently and multiple workers may write findings at the same time. Postgres also provides JSONB, allowing the evidence field to remain structured while still being queryable.

The rejected alternative was SQLite. SQLite would have kept the test suite dependency-free and eliminated the need for Docker Compose and a database service in CI, making local development simpler. I accepted those additional costs because Postgres better matches the expected production environment and provides stronger support for concurrent writes and structured evidence queries.


### Open questions

ACL and account-level Block Public Access are already represented in the bucket entries. They use the same per-value status wrapper as policy, so each read can fail independently. Account-level BPA is also represented in the collected snapshot rather than being absent from the S3 bucket data model.


---

## Defense Questions

### Why CIS instead of NIST 800-53 or AWS Foundational Security Best Practices?

CIS AWS Foundations Benchmark is a **prescriptive configuration benchmark** maintained by the Center for Internet Security and focused on concrete, testable AWS configuration recommendations. NIST SP 800-53 is a broader **security and privacy control catalog** maintained by NIST; it defines organizational and technical controls that can be implemented across many types of information systems rather than prescribing AWS-specific configuration checks. AWS Foundational Security Best Practices is a **vendor-native AWS security standard** maintained by AWS and implemented through AWS security tooling such as Security Hub.

If NIST 800-53 had been selected, the project would cite NIST control identifiers and would need to translate broader controls into AWS-specific checks. If AWS Foundational Security Best Practices had been selected, the findings would instead cite AWS-native control identifiers and align more directly with the AWS tooling ecosystem. The actual check set, finding references, and integration points would therefore change even where the underlying security objective was similar. MITRE ATT&CK could complement either choice by describing adversary behavior, but it is not a substitute for the configuration baseline itself.

### Which control produces the most false positives?

**6.3 — Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports** is the most likely to produce an intentional finding. An organization may deliberately expose an administration port in a controlled design, such as a bastion host, provided another security mechanism controls or protects the access path. The CIS guidance itself recognizes this operational consideration.

**2.12** can also produce legitimate findings for service accounts or legacy integrations that require long-lived access keys, but that does not eliminate the underlying credential-lifetime risk. The control specifically requires access keys to be rotated every 90 days or less.

### Why is a scanner that silently reports no findings worse than one that crashes?

A crash is loud and self-correcting: the traceback is seen, the missing permission is granted, the scan is re-run. A silent zero is worse than no scan at all. An unavailable scanner leaves the operator appropriately uncertain, while a clean report actively creates false confidence — it is filed, reported upward, and displaces the scrutiny that would otherwise have occurred. The misconfiguration remains and nobody is looking for it. The distinction is between a tool that failed and a tool that lied.

### How is "the setting is off" distinguished from "I could not determine the setting"?

Through decision 5 at the data layer and decision 1 at the result layer. A violation produces a `Finding` inside a `CheckResult` with status `VIOLATIONS`. A compliant resource produces no finding and status `EVALUATED`. An unreadable resource produces no `Finding` at all — status `CANT_EVALUATE` with a populated `error`.

The `Finding` model deliberately does not express the third state. A finding asserts that something is wrong; "could not determine" asserts only absence of knowledge. Placing both in the same container would require every downstream consumer — dashboard, API, remediation trigger — to remember to filter one out, and a consumer that forgot would act on an unconfirmed finding.

Under collect-then-evaluate the check never observes the failure directly. The `AccessDenied` is caught by the collector, recorded as per-value collection status in the snapshot, and interpreted by the runner or the check reading that status. The check remains a pure function and needs no knowledge of AWS failure modes.

### CVSS exists. Why didn't you use it, or if you adapted it, what did you change?

For essentially every misconfiguration this scanner produces, key CVSS metrics collapse: Attack Vector is Network, Privileges Required is None, and User Interaction is None. There often isn't even an exploit or meaningful Attack Complexity to model—the system is simply behaving as configured. So CVSS can produce a score, but it doesn't discriminate well between configuration findings.

The tradeoff is that CVSS gives us portability and standardization: a security team already understands what a 9.1 means, and platforms like Security Hub can consume it. Our custom model requires people to learn our prioritization ladder. I chose the custom approach because, for this specific problem, better discrimination is more valuable than a standardized number.

### Given Prowler exists and is free, what's the argument for this project existing at all?

Prowler’s IAM admin checks can miss policies whose effective permissions are contained in a custom policy document rather than identified by a managed-policy ARN. In the lab, Prowler missed `cspm-lab-full-access-test`, while the scanner detected it by evaluating the policy document.

Prowler 3.11.3 is pinned because current Prowler releases failed to import under Python 3.14, so the comparison ran in a 3.12 virtual environment where pip resolved 3.11.3. The version is pinned in the comparison environment so the result remains reproducible.