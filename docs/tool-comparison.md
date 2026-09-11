# Tools Comparison

## Scope

This comparison evaluates the AWS Security Posture Monitor against Prowler using the same lab environment.

The project currently defines **six security controls**, with **three implemented and producing findings**:

* `3.1.4` — S3 public access
* `6.3` — Internet-accessible administrative ports
* `2.14` — IAM wildcard permissions

The other three controls are defined in the architecture but are not part of the current scanner implementation.

Prowler was used as the external comparison tool because it was actually run against the lab. ScoutSuite was not run, so no ScoutSuite results are reported here.

## Test Environment

The project scanner and Prowler were run against AWS account `339712764484`.

Prowler was run using the default AWS profile with the `SecurityAudit` IAM role. This gives Prowler the read-only audit permissions expected for this type of scan. The project scanner has its own AWS collection permissions; this comparison does not claim that both tools used the identical IAM principal.

The lab currently contains **53 S3 buckets**, including buckets created for scale testing.

There is also an important region-scope difference:

* The project scanner currently checks four hardcoded US regions.
* Prowler scans all enabled AWS regions.

This means a finding that appears in one tool but not the other may be outside the project scanner's current regional scope.

### Prowler Version

Prowler was run with **version 3.11.3**.

The version was pinned because the current Prowler release could not be used with the project's Python 3.14 environment. A Python 3.12 virtual environment was created for Prowler, where version 3.11.3 ran successfully.

This is a tooling constraint rather than a security finding. It is documented so the comparison is reproducible and the reason for using 3.11.3 instead of the newest Prowler release is clear.

## Project Scanner Results

The project scanner produced three findings across the three currently implemented controls:

| Control | Status     | Resource                                                     | Severity |
| ------- | ---------- | ------------------------------------------------------------ | -------- |
| `3.1.4` | VIOLATIONS | `arn:aws:s3:::cspm-lab-public-bucket`                        | MEDIUM   |
| `6.3`   | VIOLATIONS | `sg-0ffefdfdc8b333268`, port 22                              | CRITICAL |
| `2.14`  | VIOLATIONS | `arn:aws:iam::339712764484:policy/cspm-lab-full-access-test` | CRITICAL |

The scanner completed successfully and returned one finding for each implemented control.

## Prowler Results

The Prowler comparison uses the **24 failed checks** from the lab scan, including their check IDs, severities, and affected resources.

Prowler reports findings at a different level of control granularity from the project. A single security issue can therefore appear as several Prowler checks.

This is especially visible in the S3 comparison.

## S3 Public Access — `3.1.4`

The project scanner reports:

```text
Control: 3.1.4
Resource: arn:aws:s3:::cspm-lab-public-bucket
Severity: MEDIUM
```

Prowler also identifies the same bucket, but evaluates it through several separate S3 controls, including:

* `s3_bucket_public_access`
* `s3_bucket_policy_public_write_access`
* `s3_bucket_level_public_access_block`
* `s3_account_level_public_access_block`
* `s3_bucket_no_mfa_delete`

This is a useful example of why finding counts cannot be compared directly. The project groups the public-access condition under one control, while Prowler separates related configuration checks.

The lab contains 53 S3 buckets. **Only `cspm-lab-public-bucket` was identified by the project scanner for the `3.1.4` condition; the other 52 buckets were not flagged.** That provides a useful true-negative result rather than simply demonstrating that the scanner can detect the intentionally vulnerable bucket.

### `s3_bucket_policy_public_write_access`

The Prowler result for `s3_bucket_policy_public_write_access` requires additional interpretation.

The visible policy associated with the test bucket grants `s3:GetObject`, which is a read operation. On that evidence alone, describing the Prowler result as a definite false positive would be premature.

The `STATUS_EXTENDED` field for the specific CSV row should be checked before classifying this result. If Prowler's extended status explains that the check is evaluating a broader form of public modification or policy access, the finding may be valid under Prowler's control definition. If it specifically claims public object-write permission that is not present in the policy, the false-positive assessment would be stronger.

For this comparison, the result is therefore treated as **requiring verification**, rather than as a confirmed false positive.

## Internet-Accessible SSH — `6.3`

The strongest direct agreement between the two tools is the SSH finding.

The project scanner reports:

```text
Control: 6.3
Security group: sg-0ffefdfdc8b333268
Port: 22
Severity: CRITICAL
```

Prowler reports:

```text
ec2_securitygroup_allow_ingress_from_internet_to_port_22
Resource: sg-0ffefdfdc8b333268
```

Both tools identify the same security group and the same exposed administrative port.

Prowler also reports:

```text
ec2_securitygroup_allow_ingress_from_internet_to_any_port
```

for the same security group. This is not a contradiction. Prowler has a broader check for unrestricted Internet ingress, while the project's `6.3` control is specifically concerned with Internet-accessible administrative ports.

This result provides the clearest validation that the project's `6.3` detection logic is identifying a real security posture issue.

## Default Security Groups

Prowler also reports:

```text
ec2_securitygroup_default_restrict_traffic
```

against four default security groups.

The project scanner does not currently detect this condition.

**Prowler is right to flag it, and this is a current coverage gap in the project.**

The project's `6.3` control is narrower: it looks for Internet-accessible administrative ports. Default security-group restrictions are a separate posture control and should not be folded into `6.3` simply to make the tools agree.

A future control should explicitly evaluate whether default security groups allow unnecessary inbound or outbound traffic.

## IAM Wildcard Permissions — `2.14`

The project scanner reports:

```text
Control: 2.14
Resource: arn:aws:iam::339712764484:policy/cspm-lab-full-access-test
Severity: CRITICAL
```

The test policy intentionally contains wildcard permissions.

Prowler did not produce a directly equivalent finding for this policy in the comparison dataset.

The important difference is how the two tools approach the problem. The project's `2.14` implementation evaluates IAM policy documents and looks for wildcard permissions directly. The relevant Prowler IAM check does not provide the same document-level evaluation for this test policy.

Therefore, the absence of a Prowler finding should not be interpreted as evidence that the project's `2.14` detection is incorrect.

This is an example of a control where the project provides a more specific detection path for the condition intentionally introduced into the lab.

## Coverage Gaps Identified by Prowler

Prowler identified several security controls that the current project does not implement.

Examples include:

* CloudTrail not configured for multi-region coverage
* CloudTrail logs not integrated with CloudWatch
* CloudTrail log file validation not enabled
* VPC Flow Logs not configured
* EBS default encryption disabled
* Public EBS snapshot exposure checks
* IMDSv1 enabled
* ACM certificate transparency logging disabled
* S3 server access logging not configured
* Default security-group traffic restrictions

These are legitimate candidates for future controls.

They also show that the current three implemented controls cover only a small portion of the security posture that a general-purpose AWS scanner evaluates.

## Region Coverage

The difference in region coverage is important when comparing results.

The project scanner currently checks four hardcoded US regions. Prowler checks all enabled regions.

The project should eventually discover enabled regions dynamically rather than relying on a fixed list. Until then, Prowler may identify resources or configuration issues that the project never evaluates because they exist outside the project's current scan scope.

This should be considered before treating a missing project finding as a detection failure.

## Finding Counts Are Not Directly Comparable

The two tools should not be judged by comparing their raw number of findings.

The project currently produces:

```text
3 findings across 3 implemented controls
```

Prowler evaluates hundreds of individual checks and splits related security conditions into separate findings.

For example, one public S3 bucket can produce several Prowler findings involving public access, bucket policy configuration, Public Access Block settings, and MFA delete.

A better comparison asks:

1. Did both tools identify the same underlying security issue?
2. Did they identify the same resource?
3. Are they evaluating the same control definition?
4. Are they scanning the same regions and resource scope?
5. If they disagree, can the difference be explained by control logic or tool scope?

Using those criteria gives a more useful comparison than raw finding counts.

## Comparison Summary

| Area                      | Project Scanner                           | Prowler                       | Result                                                     |
| ------------------------- | ----------------------------------------- | ----------------------------- | ---------------------------------------------------------- |
| S3 public bucket          | `3.1.4`                                   | Multiple S3 checks            | Same vulnerable bucket, different control granularity      |
| S3 true negatives         | 52 other buckets not flagged              | Broader S3 checks             | Useful evidence that the project did not flag every bucket |
| Internet SSH              | `6.3`, SG `sg-0ffefdfdc8b333268`, port 22 | Same SG and port 22           | Direct agreement                                           |
| Any-port Internet ingress | Not currently covered separately          | Detected                      | Broader Prowler coverage                                   |
| Default SG restrictions   | Not covered                               | Detected on four default SGs  | Valid project coverage gap                                 |
| IAM wildcard policy       | `2.14`, test policy detected              | No directly equivalent result | Different detection approach                               |
| CloudTrail posture        | Not covered                               | Multiple findings             | Project coverage gap                                       |
| VPC Flow Logs             | Not covered                               | Detected                      | Project coverage gap                                       |
| EBS encryption            | Not covered                               | Detected                      | Project coverage gap                                       |
| S3 logging                | Not covered                               | Detected                      | Project coverage gap                                       |
| Region scope              | Four hardcoded US regions                 | All enabled regions           | Prowler has broader scope                                  |

## Detection and Remediation

Prowler is used here as a validation and coverage reference. The project has a separate remediation workflow.

For the controls currently implemented, the scanner can pass findings into remediation logic and publish remediation notifications. This means the project's purpose is different from simply reproducing Prowler's check catalog.

The comparison therefore has two goals:

* Validate that implemented detections identify real AWS security issues.
* Identify useful controls that should be added to the project later.

The exact SSH finding is particularly useful for the first goal because both tools independently identify the same security group and port.

## What This Comparison Shows

Three conclusions are supported by the test:

### 1. The project detects real security issues

The `6.3` SSH finding matches Prowler on the same security group and port.

The `3.1.4` S3 finding also identifies the same intentionally exposed test bucket.

### 2. Differences do not automatically indicate incorrect detection

Prowler evaluates many more controls and uses different control boundaries. The IAM wildcard test is a good example: the project evaluates the policy document directly, while Prowler's relevant checks do not produce an equivalent result for the test policy.

Regional scope also matters because Prowler scans all enabled regions while the project currently scans four.

### 3. Prowler exposed real areas for future coverage

Default security groups, CloudTrail configuration, VPC Flow Logs, EBS encryption, S3 logging, and other controls are outside the current implementation.

The default security-group finding is intentionally treated as a real project gap rather than being dismissed as a Prowler false positive.

## Future Work

The comparison suggests several concrete improvements:

1. Add a dedicated default security-group restriction control.
2. Expand region discovery beyond the current four hardcoded US regions.
3. Add CloudTrail configuration checks.
4. Add VPC Flow Log checks.
5. Add EBS encryption and public snapshot checks.
6. Add S3 access-logging checks.
7. Expand IAM policy analysis while preserving the current document-level wildcard detection.
8. Verify the Prowler `s3_bucket_policy_public_write_access` result using its `STATUS_EXTENDED` value before classifying it as a false positive or valid finding.
9. Re-run the comparison with a current Prowler release once the project's Python compatibility constraints allow it.

## Conclusion

Prowler provides a useful external reference for the current scanner.

The strongest validation is the direct `6.3` match: both tools identify Internet-accessible SSH on `sg-0ffefdfdc8b333268`.

The S3 comparison also reaches the same vulnerable bucket, while the project's scan of all 53 lab buckets produced only the expected `3.1.4` violation and left the other 52 unflagged.

The differences are mainly explained by control granularity, detection logic, and scan scope. Prowler also identifies several controls that the project does not yet implement. Those findings give a concrete roadmap for expanding coverage rather than reasons to make the current controls artificially broader.

Prowler was not treated as an absolute source of truth for every individual result. Where its control definition differs from the project's implementation, the underlying AWS condition and the scope of each check are evaluated separately.
