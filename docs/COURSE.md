# AWS Security Posture Monitor — Course Specification

A self-directed build, structured as twelve units. Each unit states what the
component must do and how you'll know it works. None of them tell you how to
write it — that's the point.

**Estimated total effort:** 60–80 hours. At 8 hours/week, roughly a semester.

---

## How to use this document

Work the units in order; each depends on the last. For every unit:

1. Read the **Objective** and **Specification** before writing anything.
2. Implement it yourself. Reach for AWS documentation and the CIS Benchmark PDF,
   not for a reference implementation of this project.
3. Verify against the **Acceptance criteria** — they're written to be checkable,
   not aspirational.
4. Answer the **Defense questions** out loud before committing. These are the
   questions an interviewer will actually ask. If you can't answer one, you
   don't yet understand what you built.
5. Commit with the specified message. One unit, one commit (or a small series).

A unit is done when the acceptance criteria pass and you can defend the design.

---

## Unit 0 — Environment and safety

**Objective:** Establish an AWS environment you can deliberately break without
consequence.

**Specification**

- Create a dedicated AWS account, separate from any account holding real data.
- Create an IAM user for local CLI access with programmatic credentials, and a
  separate role or profile the scanner will assume. The scanner must never run
  as root.
- Enable MFA on the root account. Do not create root access keys.
- Configure an AWS Budget with an alert at $5 and a hard notification at $15.
- Configure the AWS CLI with a named profile. Confirm with
  `aws sts get-caller-identity`.
- Move the repository out of any cloud-synced folder (OneDrive, Dropbox,
  iCloud). Terraform state files are written non-atomically and sync clients
  corrupt them.

**Acceptance criteria**

- `aws sts get-caller-identity --profile <name>` returns the expected account ID.
- The budget alert exists and has your email attached.
- `git status` is clean and `.gitignore` covers `*.tfstate` and `.env`.

**Defense questions**

- Why does the scanner need read-only permissions but the remediation Lambda
  needs write? What's the risk if they share a role?
- What's the blast radius if the credentials in your `~/.aws/credentials` leak?

**Commit:** `Unit 0: environment setup notes` (document the setup in
`docs/setup.md` — no credentials, obviously)

---

## Unit 1 — Threat model and control selection

**Objective:** Decide what you're detecting and justify it in writing, before
writing detection code.

**Specification**

Write `docs/architecture.md` containing:

- A short threat model: what an attacker gains from each misconfiguration class
  you plan to detect. "Public S3 bucket" is not a threat; "unauthenticated read
  of customer PII leading to disclosure" is.
- The six CIS AWS Foundations Benchmark controls you'll implement in v1, each
  with its control number, the exact benchmark wording, and one sentence on why
  it made the cut.
- A stated scope boundary: what this tool explicitly does *not* cover, and why.
  (Runtime threats? Data classification? Multi-account?)
- Your severity philosophy in two or three sentences — what makes a finding
  Critical rather than High.

**Acceptance criteria**

- Every control cites a real CIS control number you verified against the actual
  benchmark document, not from memory.
- The scope boundary section is at least three items long.

**Defense questions**

- Why CIS rather than NIST 800-53 or the AWS Foundational Security Best
  Practices standard? What would change if you'd picked differently?
- Which of your six controls produces the most false positives in a real
  environment, and why?

**Commit:** `Unit 1: threat model and control selection`

---

## Unit 2 — The vulnerable lab

**Objective:** Build a reproducible, deliberately insecure target environment
in Terraform.

**Specification**

`terraform/` provisions, at minimum:

- An S3 bucket with public read access via bucket policy
- A second S3 bucket with server-side encryption explicitly disabled
- A security group permitting ingress on TCP/22 from `0.0.0.0/0`
- An IAM policy granting `Action: "*"` on `Resource: "*"`, attached to a role
- An unencrypted EBS volume
- CloudTrail enabled in a single region only

Requirements:

- All resources tagged with a common project tag so cleanup is verifiable.
- `variables.tf` parameterizes region and a name prefix. No hardcoded names.
- `outputs.tf` emits every resource ARN. The scanner's test fixtures will assert
  against these, so they must be complete.
- `terraform destroy` must remove everything. Verify by checking the console,
  not by trusting the output.

**Acceptance criteria**

- `terraform validate` and `terraform fmt -check` both pass.
- `terraform apply` succeeds from a clean state; `terraform destroy` leaves zero
  tagged resources.
- The public bucket is genuinely readable from an unauthenticated `curl`.

**Defense questions**

- Bucket policy vs. ACL vs. Block Public Access — three mechanisms, which one
  did you use to make the bucket public, and which one would a real
  misconfiguration most likely come from?
- Why parameterize the name prefix? What breaks without it?

**Commit:** `Unit 2: vulnerable lab environment`

---

## Unit 3 — Data model and check interface

**Objective:** Design the abstraction every check will implement. This is the
highest-leverage unit in the project.

**Specification**

Design and implement, in `scanner/models.py` and `scanner/registry.py`:

- A `Severity` type with a defined ordering (you need to sort and threshold on it).
- A `Finding` type carrying at minimum: control ID, human-readable title,
  severity, resource identifier, region, whether it is auto-remediable, and
  evidence (the actual API response fragment proving the finding).
- A mechanism by which checks declare themselves to a runner, such that adding
  a new check requires no edit to the runner.
- A means for checks that need the same upstream data (e.g. "list all buckets")
  to share one API call rather than each making their own.

Constraints:

- A check must be executable in isolation for testing.
- Adding check #40 must not require touching any file written in this unit.
- Findings must serialize to JSON losslessly.

**Acceptance criteria**

- You can add a trivial no-op check in a new file and have the runner discover
  it without editing the runner.
- A `Finding` round-trips through `json.dumps` / `json.loads` unchanged.
- Two checks requesting the same AWS data trigger exactly one API call. Prove it
  with a call counter.

**Defense questions**

- Class-based checks vs. decorated functions — which did you choose and what did
  you give up?
- Does a check know how to remediate itself, or is remediation a separate
  component that looks up a handler by control ID? Defend the coupling decision.
- Your caching layer: what's its invalidation story? Is a scan a single point in
  time, and what happens if the environment changes mid-scan?

**Commit:** `Unit 3: finding model and check registry`

---

## Unit 4 — First three checks

**Objective:** Validate the Unit 3 abstraction by implementing against it.

**Specification**

Implement, using the interface from Unit 3:

1. S3 bucket publicly accessible
2. S3 bucket encryption disabled
3. Security group open to `0.0.0.0/0` on port 22

Requirements:

- Each check returns zero findings against a clean environment and the correct
  count against the Unit 2 lab.
- Each finding's evidence field contains enough of the raw API response that a
  reviewer could verify the finding without re-running the scan.
- Handle the AWS API's inconsistencies: a bucket with no encryption
  configuration raises an exception rather than returning an empty result.
  Missing configuration is not the same as an API failure, and your code must
  distinguish them.

**Acceptance criteria**

- Run against the Unit 2 lab: exactly the expected findings, no more, no fewer.
- Run against an empty region: zero findings, zero crashes.
- Revoke a permission the scanner needs and confirm it fails loudly with a
  useful message rather than silently reporting zero findings.

**Defense questions**

- That last criterion is the important one. Why is a scanner that silently
  reports "no findings" when it lacks permissions worse than one that crashes?
- How did you distinguish "encryption is off" from "I couldn't determine whether
  encryption is on"? Does your `Finding` model express that third state?

**Commit:** `Unit 4: S3 and security group checks`

---

## Unit 5 — Severity scoring

**Objective:** Replace static per-check severity labels with a computed score.

**Specification**

Implement `scanner/scoring.py` such that severity is derived from properties of
the specific finding, not hardcoded per check type.

At minimum, score should account for:

- **Exposure** — is the affected resource reachable from the internet?
- **Blast radius** — how much privilege or data does compromise grant?

A public bucket containing one file and a public bucket containing a database
backup are the same check but should not necessarily be the same severity. You
decide how far to take this and document the reasoning.

**Acceptance criteria**

- Two findings from the same check receive different severities under
  appropriately different conditions.
- The scoring logic is unit-tested independently of AWS.
- `docs/architecture.md` explains the model.

**Defense questions**

- CVSS exists. Why didn't you use it, or if you adapted it, what did you change?
- Your model produces a severity. How would you validate that it's *correct*?

**Commit:** `Unit 5: severity scoring model`

---

## Unit 6 — Remaining checks and scan performance

**Objective:** Complete the v1 check set and confront the performance problem.

**Specification**

- Implement the remaining three controls from Unit 1.
- Add a scan across all enabled regions, not just one.
- Measure and record total scan wall-clock time in the README.

Performance requirement: a multi-region scan of six checks makes a lot of
sequential API calls. Make it faster. Concurrency, batching, or smarter caching
are all legitimate — but measure before and after, and record both numbers.

**Acceptance criteria**

- All six checks pass against the lab.
- Multi-region scan completes and reports findings tagged with the correct region.
- Documented before/after timings with the technique used.
- No AWS API throttling errors under normal operation. If you hit
  `ThrottlingException`, implement backoff.

**Defense questions**

- Where did the time actually go? Did you profile, or guess?
- Concurrency against the AWS API has a rate-limit ceiling. What's your backoff
  strategy and how did you pick the parameters?

**Commit:** `Unit 6: full check set and multi-region scanning`

---

## Unit 7 — Testing and CI

**Objective:** Make the test suite run without AWS credentials.

**Specification**

- Unit tests for every check using `moto` or `botocore.stub.Stubber`.
- Tests must cover: the violating case, the compliant case, and the error case
  (permission denied, resource missing).
- Scoring logic tested independently.
- GitHub Actions runs the suite on every push and pull request, plus
  `terraform validate` and `terraform fmt -check`.
- CI must pass with no AWS credentials configured.

**Acceptance criteria**

- `pytest` passes on a machine with no AWS credentials.
- The CI badge on the README is green and links to a real workflow run.
- Deliberately break one check and confirm CI catches it.

**Defense questions**

- `moto` mocks AWS behavior. Where does the mock diverge from the real API, and
  what class of bug would your tests therefore miss?

**Commit:** `Unit 7: test suite and CI pipeline`

---

## Unit 8 — Event-driven remediation

**Objective:** Close the loop from detection to response.

**Specification**

In `terraform/remediation/` and `lambda/`:

- CloudTrail feeding EventBridge rules that fire on the specific API calls that
  create your target misconfigurations.
- A Lambda that receives the event, identifies the resource, and reverts the
  change.
- Notification to SNS or a Slack webhook on every remediation, including what
  was changed and by whom.
- Remediate at least two finding types end to end.

Requirements:

- The Lambda's IAM role is scoped to exactly the actions it needs. No wildcards.
  You are building a security tool; it should not itself be a finding.
- Remediation must be idempotent — receiving the same event twice must not cause
  an error or a double-revert.
- Include a guard against remediation loops: your remediation makes an API call,
  which generates a CloudTrail event, which could trigger your rule again.

**Acceptance criteria**

- Manually make a bucket public. It reverts automatically, and you receive the
  notification.
- Record the elapsed time from misconfiguration to remediation.
- Replay the same event twice; confirm no error and no side effect.
- Confirm no remediation loop occurs. Prove it from the CloudTrail log.

**Defense questions**

- The loop guard is the interesting one. How did you break the cycle — event
  filtering, a marker tag, checking the invoking principal? What are the failure
  modes of your approach?
- Auto-remediation in production is contentious. When would automatically
  reverting a change cause an outage? How would you gate it?

**Commit:** `Unit 8: event-driven auto-remediation`

---

## Unit 9 — Benchmark against production tooling

**Objective:** Establish honest coverage numbers.

**Specification**

Run Prowler and ScoutSuite against the same lab environment. Write
`docs/tool-comparison.md` recording:

- What each tool found that yours missed
- What yours found that they missed, if anything
- False positives from any of the three
- A coverage percentage for your scanner against the CIS controls Prowler covers

Be accurate. A comparison showing your six checks against Prowler's several
hundred, stated plainly, is more credible than an inflated claim — and reviewers
who know the tools will check.

**Acceptance criteria**

- All three tools run against an identical environment state.
- The document names specific controls, not general impressions.
- Your scanner's gaps are stated explicitly.

**Defense questions**

- Given Prowler exists and is free, what's the argument for this project
  existing at all? (There is one. Find it and be able to say it.)

**Commit:** `Unit 9: coverage comparison against Prowler and ScoutSuite`

---

## Unit 10 — Findings API and dashboard

**Objective:** Make findings consumable by something other than a terminal.

**Specification**

- FastAPI service exposing findings with filtering by severity, region, and
  control ID, plus a summary endpoint for dashboard tiles.
- Persistence — decide between SQLite, Postgres, or DynamoDB and justify it in
  `docs/architecture.md`.
- A Next.js dashboard showing current posture: findings by severity, trend over
  time, and per-finding detail with the evidence field.
- Findings should have a lifecycle: new, acknowledged, remediated, suppressed.
  A tool that only reports and never tracks state is a report generator, not a
  monitor.

**Acceptance criteria**

- API returns correct results for every filter combination.
- Dashboard renders against real scan data.
- Suppressing a finding persists across scans.

**Defense questions**

- Suppression is a security-relevant feature. How do you prevent it from being
  used to silently hide real risk? Expiry, required justification, audit log?

**Commit:** `Unit 10: findings API and dashboard`

---

## Unit 11 — Packaging and defense

**Objective:** Make the repository legible to someone who has ninety seconds.

**Specification**

- README updated with real metrics — actual check count, actual measured
  remediation latency, actual coverage percentage. Every placeholder replaced or
  removed.
- A rendered architecture diagram, not ASCII.
- A short demo: an asciinema recording or a GIF showing a misconfiguration being
  created and auto-reverted.
- `docs/architecture.md` complete, with every design decision and its rationale.
- Repository description and topics set on GitHub.
- Write `docs/interview-notes.md` — your own answers to every Defense question
  in this document. Private notes, but write them down. The act of writing
  reveals which ones you can't actually answer.

**Acceptance criteria**

- Someone unfamiliar with the project can understand what it does from the
  README alone in under two minutes.
- No claim in the README is unverifiable from the repository.
- Every Defense question has a written answer.

**Commit:** `Unit 11: documentation and portfolio packaging`

---

## Grading rubric

Score yourself honestly. This maps to how a technical interviewer will read it.

| Criterion | Weight | What earns full marks |
|---|---|---|
| Correctness | 25% | Checks find real violations, no false negatives against the lab, permission failures surface loudly |
| Design quality | 20% | Adding a check requires one new file; abstractions hold up under the full check set |
| Security of the tool itself | 15% | Least-privilege IAM throughout, no secrets in the repo, remediation cannot be weaponized |
| Testing | 15% | Suite runs credential-free, covers error paths, CI green |
| Documentation | 15% | Design rationale written down, claims verifiable, honest about gaps |
| Operational realism | 10% | Handles throttling, multi-region, idempotency, remediation loops |

**Self-assessment gate:** if you cannot answer every Defense question in a unit
without notes, that unit is incomplete regardless of whether the code runs.

---