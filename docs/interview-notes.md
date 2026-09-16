## Defense Questions

### Why CIS instead of NIST 800-53 or AWS Foundational Security Best Practices?

CIS AWS Foundations Benchmark is a **prescriptive configuration benchmark** maintained by the Center for Internet Security and focused on concrete, testable AWS configuration recommendations. NIST SP 800-53 is a broader **security and privacy control catalog** maintained by NIST; it defines organizational and technical controls that can be implemented across many types of information systems rather than prescribing AWS-specific configuration checks. AWS Foundational Security Best Practices is a **vendor-native AWS security standard** maintained by AWS and implemented through AWS security tooling such as Security Hub.

If NIST 800-53 had been selected, the project would cite NIST control identifiers and would need to translate broader controls into AWS-specific checks. If AWS Foundational Security Best Practices had been selected, the findings would instead cite AWS-native control identifiers and align more directly with the AWS tooling ecosystem. The actual check set, finding references, and integration points would therefore change even where the underlying security objective was similar. MITRE ATT&CK could complement either choice by describing adversary behavior, but it is not a substitute for the configuration baseline itself.

### Which control produces the most false positives?

**6.3 — Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports** is the most likely to produce an intentional finding. An organization may deliberately expose an administration port in a controlled design, such as a bastion host, provided another security mechanism controls or protects the access path. The CIS guidance itself recognizes this operational consideration.

**2.12** can also produce legitimate findings for service accounts or legacy integrations that require long-lived access keys, but that does not eliminate the underlying credential-lifetime risk. The control specifically requires access keys to be rotated every 90 days or less.

### How does the system prevent suppression from silently hiding risk?

Suppression is an explicit exception rather than a deletion of the finding. `FindingStateUpdateSchema` requires `suppressed_by`, `justification`, and `expires_at` before a finding can enter the suppressed state, and the requirement is covered by a test. The fields make the exception attributable, explainable, and time-bounded.

The expiration is evaluated when finding status is read, so an expired suppression stops producing `SUPPRESSED` without requiring a background job to rewrite the finding. The original finding and its suppression metadata remain available for auditability.

There is an important remaining limitation: these fields are accountability metadata, not authentication. Because the API currently has no authentication or authorization, `suppressed_by` does not independently verify who made the request.

### Why is a scanner that silently reports no findings worse than one that crashes?

A crash is loud and self-correcting: the traceback is seen, the missing permission is granted, and the scan is re-run. A silent zero is worse than no scan at all. An unavailable scanner leaves the operator appropriately uncertain, while a clean report actively creates false confidence. It can be filed, reported upward, and displace the scrutiny that would otherwise have occurred.

The distinction is between a tool that failed and a tool that incorrectly reported success.

### How is "the setting is off" distinguished from "I could not determine the setting"?

Through decision 5 at the data layer and decision 1 at the result layer.

A violation produces a `Finding` inside a `CheckResult` with status `VIOLATIONS`. A compliant resource produces no finding and status `EVALUATED`. An unreadable resource produces no `Finding` at all — status `CANT_EVALUATE` with a populated `error`.

The `Finding` model deliberately does not express the third state. A finding asserts that something is wrong; "could not determine" asserts only absence of knowledge. Placing both in the same container would require every downstream consumer — dashboard, API, remediation trigger — to remember to filter one out, and a consumer that forgot could act on an unconfirmed finding.

Under collect-then-evaluate, the check never observes the failure directly. The `AccessDenied` is caught by the collector, recorded as per-value collection status in the snapshot, and interpreted by the runner or the check reading that status. The check remains a pure function and needs no knowledge of AWS failure modes.

### CVSS exists. Why didn't you use it, or if you adapted it, what did you change?

For essentially every misconfiguration this scanner produces, key CVSS metrics collapse: Attack Vector is Network, Privileges Required is None, and User Interaction is None. There often isn't even an exploit or meaningful Attack Complexity to model — the system is simply behaving as configured. So CVSS can produce a score, but it doesn't discriminate well between configuration findings.

The tradeoff is that CVSS gives us portability and standardization: a security team already understands what a 9.1 means, and platforms like Security Hub can consume it. Our custom model requires people to learn our prioritization ladder. I chose the custom approach because, for this specific problem, better discrimination is more valuable than a standardized number.

### Given Prowler exists and is free, what's the argument for this project existing at all?

Prowler's IAM admin checks can miss policies whose effective permissions are contained in a custom policy document rather than identified by a managed-policy ARN. In the lab, Prowler missed `cspm-lab-full-access-test`, while the scanner detected it by evaluating the policy document.

Prowler 3.11.3 is pinned because current Prowler releases failed to import under Python 3.14, so the comparison ran in a 3.12 virtual environment where pip resolved 3.11.3. The version is pinned in the comparison environment so the result remains reproducible.

### Why does the scanner need read-only but the remediation Lambda needs write? What's the risk if they shared a role?

The scanner only needs to inspect AWS resources, so I gave it read-only permissions. The remediation Lambda is separate because it actually modifies resources and therefore needs write permissions.

Sharing the same role would violate the principle of least privilege. If the scanner or one of its dependencies were compromised, an attacker could potentially use the remediation permissions to modify AWS infrastructure.

Separating the roles limits the blast radius.

The basic principle is:

> **The scanner observes. The remediation Lambda changes. They should not have the same permissions.**

### Bucket policy vs ACL vs BPA — which did you use, and which is the likelier real misconfiguration?

I used S3 Block Public Access (BPA) as the main check.

The three mechanisms operate at different levels:

* **Bucket policy** — a resource-based IAM policy that can grant access to principals.
* **ACL** — an older S3 access-control mechanism attached to buckets or objects.
* **Block Public Access (BPA)** — a set of controls designed to prevent public access through bucket policies and ACLs.

For a modern S3 configuration, I would pay particular attention to BPA and bucket policies. ACLs are still another possible source of exposure, but they're less central in newer S3 configurations, especially when S3 Object Ownership is configured with Bucket owner enforced.

The actual security problem I'm looking for is unintended public access.

I wouldn't assume that one mechanism is always responsible. A bucket could have a restrictive policy but still have another configuration issue, or it could have a permissive policy that is blocked by BPA.

So my check focuses on the actual security condition rather than treating BPA, ACLs, and policies as interchangeable.

### Class-based checks vs decorated functions — what did you give up?

I chose class-based checks because I wanted a consistent interface and room for individual checks to become more complex.

The tradeoff is additional boilerplate.

A decorator-based approach could make registration and discovery much simpler. For example:

```python
@check("s3_public_access")
def check_s3_public_access(...):
    ...
```

With a class-based architecture, I get a more explicit structure:

```python
class S3PublicAccessCheck:
    ...
```

What I gave up was mainly:

* Simpler registration
* Less boilerplate
* Lightweight check implementations
* Easy function-based discovery

What I gained was:

* A consistent interface
* Better separation of responsibilities
* Room for check-specific dependencies or configuration
* Easier extension as checks become more complex

If the checks remained very small, I could justify decorated functions. I chose classes because I wanted the architecture to support more complex checks as the project grows.

### Where did the scan time actually go? Did you profile or guess?

I measured wall-clock time rather than using a profiler. In Unit 6, I compared sequential execution against ten workers at two different scales.

With **53 buckets**, sequential scanning took **11.41 seconds**, while using ten workers reduced it to **4.02 seconds**.

With only **3 buckets**, sequential scanning took **2.10 seconds**, while ten workers actually took **2.36 seconds**.

That told me something specific. As the number of buckets grows, the per-bucket AWS API calls become a larger part of the total runtime, so concurrency helps hide that network latency.

At small scale, however, the workload has a meaningful fixed component. Roughly seven API calls occur sequentially regardless of the number of buckets: STS, `list_buckets`, account-level Block Public Access, and one `DescribeSecurityGroups` call per region. Worker setup and coordination also contribute to overhead.

So the measurements showed that the benefit of parallelism depends on workload size. I didn't use a profiler because the question I needed to answer was whether parallelizing the per-bucket work improved end-to-end scan time, and the wall-clock measurements answered that directly.

### `moto` mocks AWS — where does the mock diverge, and what bugs would that miss?

I actually didn't use Moto. I used `botocore.stub.Stubber` in Unit 7 because I wanted the tests to validate the AWS responses against botocore's service model.

That caught a real issue for me. I initially provided `PolicyVersion.Document` as a dictionary, but Stubber rejected it because the AWS API model says that field is returned as a string. That was useful because the test caught an incorrect assumption about the AWS API rather than simply accepting whatever response shape I invented.

The limitation is that Stubber is still a stub. It validates my stubbed response against botocore's service model, but it doesn't actually call AWS.

For example, I can stub a `NoSuchBucketPolicy` response and verify that my scanner handles it correctly, but that doesn't prove AWS will actually return that exact error code under the circumstances I'm testing.

That's where my live AWS runs matter. They cover the gap between:

> "My code handles the botocore-defined response correctly."

and:

> "The real AWS service actually behaves this way."

If I guessed an AWS error code incorrectly, Stubber could still let me test my handling of that exact stubbed response. A live AWS run is what validates that the real service produces the behavior I'm expecting.

### What is the blast radius if `~/.aws/credentials` leaks?

If `~/.aws/credentials` contains long-lived AWS access keys and those credentials leak, the blast radius is determined primarily by the IAM permissions attached to those credentials.

If they're administrator credentials, the compromise could potentially affect the entire AWS account or other resources those credentials can access. If they're restricted to the scanner's read-only permissions, the attacker would have a much smaller capability set.

That's another reason I separate scanner and remediation permissions. The credentials used for detection should not automatically provide the ability to modify infrastructure.

I would also avoid treating the credentials file itself as a security boundary. For deployed workloads, the stronger design is to use temporary credentials through IAM roles rather than distributing long-lived access keys.

The important distinction is:

> **Credential exposure is bad, but the permissions attached to the credential determine what the attacker can actually do.**

### Why parameterize the name prefix?

I parameterized the resource name prefix so that the scanner's test resources are isolated and identifiable without hard-coding a single environment-specific name.

For example:

```text
cspm-lab-<prefix>-...
```

This makes the infrastructure easier to create, clean up, and run repeatedly without collisions.

It also keeps the scanner and its tests from assuming that a resource has one exact name. The code can operate against a controlled namespace while still exercising the same AWS APIs it would use against arbitrary resources.

The prefix is therefore a testability and isolation mechanism, not a security control.

### Does a check know how to remediate itself?

No. Detection and remediation are intentionally separate.

A check's responsibility is to determine whether the AWS state violates the security rule and produce a finding. The remediation layer decides whether that finding is eligible for automatic remediation and then invokes the appropriate remediation logic.

That separation prevents every check from becoming responsible for both identifying and modifying infrastructure.

It also means a finding can exist without automatically granting the check permission to change the resource.

The architecture is essentially:

```text
Collector
    ↓
Snapshot
    ↓
Check
    ↓
Finding
    ↓
Remediation decision
    ↓
Remediation Lambda
```

This keeps the scanner read-only while giving remediation its own narrower write permissions.

### Is the scan a point-in-time view of AWS?

Yes. A scan represents the state observed during a particular collection window. It is not a continuously consistent transaction across the AWS account.

The scanner can collect S3 state at one moment and security-group state slightly later. A resource could change between those API calls.

That means a finding describes:

> "This was the state observed during this scan."

It does not guarantee that the resource remains in exactly that state afterward.

This matters particularly for remediation. The remediation layer should not blindly assume that the finding is still current. It should verify the current resource state before making a potentially destructive change and re-scan afterward to verify the result.

### How does caching affect correctness? What invalidates the cache?

Caching can improve performance by avoiding repeated AWS API calls, but cached configuration can become stale.

For a security posture scanner, that creates a correctness problem because a finding may be based on state that has already changed.

The basic rule is that a scan should operate on a coherent snapshot of the data it collected rather than repeatedly fetching the same AWS state during evaluation.

The snapshot is effectively invalidated by a new scan. A new scan collects fresh AWS state and therefore provides a new point-in-time view.

The caveat is that the snapshot itself is still only consistent with the collection window. It doesn't become a continuously updated representation of AWS.

For remediation, the safest approach is to verify the current state again immediately before making a consequential change rather than relying indefinitely on an old snapshot.

### How would you validate that the severity model is correct?

I don't currently have a formal validation method for the severity model.

The current model is an engineering judgment based on the relative security impact of the controls rather than a statistically validated severity prediction.

To validate it properly, I would define an independent reference set of findings and have experienced security practitioners classify their severity without seeing the scanner's assigned value. I could then compare the scanner's classifications against that reference set and measure disagreement.

I'd also test whether the model consistently distinguishes things such as:

* Public exposure versus internal exposure
* Administrative access versus ordinary application access
* Credential-management issues versus direct exposure
* Single-resource findings versus findings with broader account impact

Until that evaluation is performed, I would describe the severity model as **heuristic**, not objectively validated.

### What's your backoff strategy, and how did you pick the parameters?

The project inherits **boto3's default retry behavior** rather than implementing its own retry loop.

Boto3's standard retry behavior handles transient failures such as throttling using exponential backoff with jitter, with the default retry configuration providing a limited number of attempts.

I did not configure or tune `max_attempts` or the retry mode for this project, and I did not hit throttling at the scale I tested.

So I haven't empirically validated that boto3's defaults are optimal for this workload.

If this were being moved to a much larger production environment, I would measure throttling and retry behavior under realistic load and then decide whether the retry mode or `max_attempts` needed to be explicitly configured.

I also would not retry every error. An `AccessDenied` or invalid request is fundamentally different from a transient throttling or service error.

The honest answer is:

> **I inherit boto3's default retry behavior. I didn't configure `max_attempts` or the retry mode, and I never hit throttling at my test scale, so I haven't validated whether the defaults are appropriate for a larger workload.**

### How did you break the remediation loop, and what are your approach's failure modes?

I separate detection from remediation and make remediation **idempotent**.

The basic flow is:

```text
Scan
  ↓
Finding
  ↓
Check whether remediation is allowed
  ↓
Remediation
  ↓
Re-scan
  ↓
Verify the finding
```

The important part is that remediation shouldn't blindly trigger another remediation cycle.

If the remediation succeeds:

```text
Finding detected
       ↓
Remediation
       ↓
Re-scan
       ↓
Finding resolved
```

If it doesn't:

```text
Finding detected
       ↓
Remediation
       ↓
Re-scan
       ↓
Finding still exists
       ↓
Remediation failure
```

I also wouldn't allow unlimited retries.

The main failure modes are:

* AWS API failure
* Permission failure
* Stale AWS state
* Partial remediation
* Another system changing the resource back
* The remediation not actually resolving the finding
* A finding that can never be automatically remediated
* Repeated attempts against a permanently failing remediation

A production implementation should track remediation attempts and stop after a defined limit rather than continuously retrying.

### Auto-remediation in production is contentious — when would reverting cause an outage?

A security finding doesn't necessarily mean the configuration is unintentionally wrong.

For example, a security group allowing:

```text
0.0.0.0/0 → TCP 443
```

could be intentional if the application is a public web service.

Likewise, public S3 access could be intentional for a service serving public assets.

If the system automatically changed those configurations, it could break the application.

Another example would be automatically removing:

```text
0.0.0.0/0 → TCP 22
```

from a security group.

That could improve the security posture but simultaneously break legitimate administrative access.

So I would consider:

* Whether the remediation is predictable
* The blast radius
* Whether the change is reversible
* Whether the resource is explicitly excluded
* Whether the finding is high-confidence
* Whether approval is required

A reasonable production model is:

```text
Low-risk, well-understood change
        ↓
Automatic remediation

Higher-risk change
        ↓
Approval / manual remediation
```

The important point is:

> **A configuration can violate a security rule while still being intentional and operationally necessary.**

The remediation system therefore needs to consider operational context rather than blindly changing every finding.
