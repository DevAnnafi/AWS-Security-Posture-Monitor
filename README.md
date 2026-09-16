# AWS Security Posture Monitor

[![CI](https://github.com/DevAnnafi/AWS-Security-Posture-Monitor/actions/workflows/ci.yml/badge.svg)](https://github.com/DevAnnafi/AWS-Security-Posture-Monitor/actions/workflows/ci.yml)

A cloud security posture management (CSPM) pipeline that detects AWS misconfigurations against the CIS AWS Foundations Benchmark, prioritizes findings by the capability an attacker gains, remediates a narrow subset automatically, and reports honestly on what it could not evaluate.

> **Status: functional end to end.** The scanner collects from live AWS accounts, runs three CIS checks, persists findings to Postgres, serves them through a FastAPI service, and reverts two classes of misconfiguration automatically. 53 tests run in CI. Three of six planned checks are built. Sections below are labeled **Built** or **Planned**; the [Roadmap](#roadmap) tracks progress.

Design decisions are written up in a nine-part series: [Building an AWS Security Posture Monitor From Scratch](https://medium.com/@islamannafi).

---

## Why this exists

Most cloud breaches trace back to configuration, not exotic exploits — a bucket left public, an IAM role with `Action: "*"`, a security group open to the internet on 22. Commercial CSPM tools (Wiz, Prowler, ScoutSuite) solve this well; this project reimplements the core detection loop from scratch to demonstrate the underlying mechanics: how findings are gathered from cloud APIs, mapped to a control framework, scored, and reported.

The design question it takes most seriously is what a scanner does when it **cannot** see something. A tool that reports zero findings because its credentials lacked a permission is more dangerous than one that crashes, because the operator acts on the clean report. Every layer of this scanner distinguishes "I looked and found nothing" from "I could not look."

---

## Architecture

```mermaid
flowchart TB
    subgraph LAB["Lab environment — Terraform"]
        direction TB
        L1["Public-read S3 bucket"]
        L2["Unencrypted S3 bucket"]
        L3["Open security group<br/>SSH 0.0.0.0/0 · lab VPC"]
        L4["IAM policy *:* on inert role"]
        L5["Unencrypted EBS volume"]
        L6["Single-region CloudTrail"]
    end

    subgraph SCANNER["Scanner — Python + boto3"]
        direction TB
        C1["Collector<br/>per-value retrieval status"]
        C2["Snapshot<br/>account · regions · resources"]
        C3["Check registry<br/>requires-gated execution"]
        C4["Severity scoring<br/>capability granted"]
        C5["ScanResults<br/>findings + unevaluated"]
        C1 --> C2 --> C3 --> C4 --> C5
    end

    subgraph REMEDIATION["Remediation — EventBridge + Lambda"]
        direction TB
        R1["CloudTrail → EventBridge"]
        R2["Remediation Lambda<br/>re-scan affected resource"]
        R3["Threshold check"]
        R4["Remediation handler<br/>keyed by control"]
        R5["SNS notification"]
        R1 --> R2 --> R3 --> R4 --> R5
    end

    subgraph PLATFORM["Findings platform"]
        direction TB
        F1["Postgres findings store"]
        F2["FastAPI service"]
        F3["Next.js dashboard"]
        F4["Slack alerts"]
        F1 --> F2 --> F3
    end

    LAB -->|"read-only<br/>SecurityAudit role"| C1
    C5 -->|"findings"| F1
    LAB -.->|"config-change events"| R1
    R5 --> F4

    classDef planned stroke-dasharray:5 5,stroke:#888,color:#888;
    class F4 planned;
```

Everything except Slack alerting is implemented.

---

## Features

Legend: **Built** = implemented, tested, and committed · **Planned** = designed, not yet implemented.

- **Framework-mapped detection** *(Built).* Every check cites the CIS AWS Foundations Benchmark v7.0.0 control it enforces, so findings are auditable rather than ad hoc.
- **Honest reporting of blind spots** *(Built).* A check that cannot read a resource records what it could not evaluate and why, and the scan status reflects that incompleteness rather than burying it in an optional field.
- **Capability-based severity** *(Built).* Severity is derived per finding from what the exposed configuration actually grants — a policy allowing `s3:GetObject` and one allowing `s3:*` on the same bucket score differently.
- **Multi-region collection** *(Built).* Regions are collected independently, so a permission failure in one region does not discard results from the others.
- **Threshold-based auto-remediation** *(Built).* Narrowly defined findings are reverted through EventBridge → Lambda within seconds. Anything outside the threshold alerts instead.
- **Re-scan before remediation** *(Built).* The Lambda reads the affected resource again and runs the same detection logic before changing anything, so there is one detection implementation rather than two.
- **Suppression guardrails** *(Built).* Suppressing a finding requires a name, a justification, and an expiry. Expired suppressions return on their own.
- **Read-time finding status** *(Built).* Status is computed when findings are read, so an expired suppression stops applying without a background job rewriting historical rows.
- **Credential-free scanner tests** *(Built).* Check and collector tests run with no AWS configuration, including error branches a modern AWS account cannot produce.
- **Reproducible vulnerable lab** *(Built).* The insecure target environment is defined in Terraform, so results are reproducible by anyone cloning the repo.
- **Prowler coverage comparison** *(Built).* Scanner output benchmarked against Prowler 3.11.3 on the same account, documented in [`docs/tool-comparison.md`](docs/tool-comparison.md).
- **Slack alerting** *(Planned).* Remediation notifications currently go to SNS email only.

---

## Checks

Control numbers are verified against the CIS AWS Foundations Benchmark **v7.0.0**. Selection and rationale are in [`docs/architecture.md`](docs/architecture.md).

| CIS Control | Check | Status | Severity | Auto-remediation |
|---|---|---|---|---|
| 3.1.4 | S3 bucket publicly accessible (policy or ACL) | **Built** | Derived per finding | Enables all four BPA flags |
| 6.3 | Security group allows `0.0.0.0/0` to admin ports (22, 3389) | **Built** | Critical | Exact admin ports only |
| 2.14 | IAM policy allowing full `*:*` admin privileges is attached | **Built** | Critical | Detect-only |
| 4.1 | CloudTrail not enabled in all regions | Planned | — | — |
| 2.10 | MFA not enabled for IAM users with a console password | Planned | — | — |
| 2.12 | Access keys not rotated within 90 days | Planned | — | — |

**3.1.4** evaluates the full Block Public Access precedence chain: account-level BPA overrides bucket-level, both override the bucket policy and ACL, and Object Ownership determines whether ACL grants have any effect at all. A bucket with `Principal: "*"` in its policy is **not** reported public if BPA blocks it.

**6.3** treats port ranges as ranges (`FromPort: 0, ToPort: 65535` covers 22) and handles `IpProtocol: "-1"`, where AWS omits the port fields entirely because every port on every protocol is open.

**2.14** identifies attached IAM policies granting `Action: "*"` on `Resource: "*"`. Service-specific wildcards such as `s3:*` do not qualify as full administrative access, and unattached policies are not reported — though they are still collected, so a future control could flag dormant admin policies.

---

## Remediation

Remediation runs separately from the normal detection scan.

A configuration-change event is delivered through CloudTrail and EventBridge to the remediation Lambda. The Lambda does **not** trust the event payload as proof that the finding still exists. It re-reads the affected AWS resource and runs the same detection implementation used by the scanner.

```text
AWS configuration change
        │
        ▼
    CloudTrail
        │
        ▼
   EventBridge
        │
        ▼
 Remediation Lambda
        │
        ▼
 Re-scan affected resource
        │
        ▼
 Does violation still exist?
        │
        ├───────────────┐
        │               │
       yes              no
        │               │
        ▼               ▼
 Threshold check       Stop
        │
        ├───────────────┐
        │               │
      safe           outside
        │           threshold
        ▼               │
   Remediate            ▼
        │              SNS
        ▼
       SNS
```

### Why the Lambda re-scans

The EventBridge event identifies the configuration change, but the resource may have changed again before the Lambda executes. Re-scanning means the remediation decision is based on the resource's current state.

It also keeps detection in one implementation. The Lambda does not maintain a second copy of the logic used to decide whether a configuration violates a control.

The trade-off is additional AWS API calls per invocation. The Lambda therefore needs read permissions as well as the write permissions required for remediation.

### Remediation handlers

Detection and remediation are separate.

Checks are pure functions over a snapshot and do not modify AWS resources. Remediation handlers run inside Lambda with write credentials and are registered by CIS control ID.

The Lambda ships the complete scanner package anyway, so separating remediation from checks does **not** reduce deployment size. The separation exists because the two operations have different execution contexts, permissions, and responsibilities.

### What each control does

| Control | Finding | Auto-remediation |
|---|---|---|
| **3.1.4** | Public S3 access | Enables all four Block Public Access flags (additive, not destructive) |
| **6.3** | `0.0.0.0/0` on TCP 22 or 3389 | Exact administrative-port rules only |
| **2.14** | Attached `*:*` IAM policy | **Detect-only** |

### 6.3 remediation threshold

Security-group remediation is intentionally narrow.

An exact administrative-port rule is eligible when TCP port **22** or **3389** is exposed to `0.0.0.0/0`.

Broad ranges generate findings but are not automatically changed. For example:

```text
FromPort: 0
ToPort: 65535
```

covers port 22, but automatically replacing or deleting the rule would require assuming that the entire range was created accidentally.

`IpProtocol: "-1"` is also **never** automatically remediated. It represents unrestricted protocol and port access, but changing such a rule automatically would make a broader assumption about the intended network configuration.

The answer to "when would auto-remediation cause an outage?" is when the scanner changes a rule that was intentionally required by an application or administrator. The threshold therefore favors a narrow, specific corrective action over automatically changing every configuration that contains an exposure.

The cost is that the two most dangerous security-group configurations are precisely the ones left for manual remediation.

### 2.14 is detect-only

CIS 2.14 detects attached IAM policies granting full `*:*` administrative privileges, but it does not automatically detach the policy.

An administrative policy may be intentional and may support a legitimate workload, deployment system, or administrator. The scanner can establish that the policy violates the benchmark, but it cannot establish from the finding alone that removing the policy is operationally safe.

A remediation that causes an outage is worse than leaving the finding for manual review. IAM 2.14 therefore remains detect-only.

### Remediation timing

**Time from misconfiguration to remediation: ~8 seconds**

- CloudTrail → EventBridge → Lambda invocation: ~6s
- Lambda execution (re-scan, revoke, notify): ~2s

This is one measurement; delivery latency varies.

### Sample SNS notification

```json
{
  "message": "CSPM remediation attempted",
  "resource": "sg-07dfce1d80df89537",
  "control_id": "6.3",
  "event": {
    "eventName": "AuthorizeSecurityGroupIngress",
    "eventSource": "ec2.amazonaws.com",
    "eventTime": "2026-09-11T05:31:30Z",
    "region": "us-east-1"
  },
  "triggered_by": {
    "type": "IAMUser",
    "arn": "arn:aws:iam::ACCOUNT:user/terraform-deploy",
    "userName": "terraform-deploy"
  },
  "remediation": { "status": "ok", "revoked_rules": 1 }
}
```

`triggered_by` names the identity that made the change, not the Lambda that reverted it — which is also how the EventBridge loop guard is verified.

---

## Findings platform

Findings are persisted to Postgres, served by FastAPI, and displayed in a Next.js dashboard.

### Data model

Four tables, split by lifetime:

| Table | Key | Holds |
|---|---|---|
| `scans` | `scan_id` | One row per scan: status, regions, timing |
| `findings` | `(scan_id, finding_id)` | One row per finding per scan, so history is preserved |
| `finding_state` | `finding_id` | Lifecycle state that must outlive any single scan |
| `uneval_targets` | auto | What each scan could not evaluate, and why |

`finding_state` deliberately has **no** foreign key to `findings`. A suppression must survive the finding disappearing from later scans, old scan rows being pruned, or the resource being deleted — a foreign key would cascade it away at exactly the wrong moment. The cost is that referential integrity is not enforced for that table.

### Suppression

Suppression is the one feature that makes a security finding disappear, so it carries guardrails enforced in the schema rather than suggested in documentation:

- **Who** — `suppressed_by` must be supplied
- **Why** — `justification` must be supplied
- **For how long** — `expires_at` must be supplied

A request missing any of them is rejected with a 422. The dashboard surfaces suppressed counts explicitly rather than quietly excluding them, so a tile reads *2 critical, 1 suppressed* rather than *2 critical*.

`suppressed_by` records a supplied value; it does not prove identity. The API has no authentication yet — see [Known gaps](#known-gaps).

### Status is computed, not stored

An expiry that nothing enforces is a permanent suppression with extra steps.

Rather than running a background job to sweep expired suppressions, status is computed when findings are read. The stored row keeps `SUPPRESSED` along with who and why — that is the historical record — while the API reports what is true now.

The database records what happened. The API reports what is true now. Those deliberately differ for an expired suppression.

### Endpoints

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/findings` | Latest scan's findings, filterable by severity, region, control |
| `GET` | `/findings/{id}` | One finding with its evidence |
| `GET` | `/summary` | Counts by severity and control, plus suppressed count |
| `GET` | `/scans` | Scan history |
| `PATCH` | `/findings/{id}/state` | Acknowledge, suppress, or restore a finding |

Interactive docs at `/docs` when the service is running.

---

## Severity model

One factor, three levels, computed per finding from the capability the exposure grants:

| Level | Meaning | Severity | Example |
|---|---|---|---|
| 1 | Read-only access to data | Medium | Bucket policy allowing `s3:GetObject` to `*` |
| 2 | Modify, delete, or re-permission a resource | High | Bucket policy allowing `s3:*`, or an ACL granting `FULL_CONTROL` |
| 3 | Shell or interactive control of a host | Critical | Port 22 or 3389 open to `0.0.0.0/0` |

`LOW` is deliberately unused. Every finding the scanner currently emits is an unintended public exposure; none of them are safe to defer. `LOW` is reserved for controls like access-key age and missing MFA, which are non-compliant but not directly exploitable.

The action allow-list is inverted on purpose: the scanner enumerates the actions it can prove are read-only and scores everything else as level 2. It cannot reliably decide whether an unfamiliar action is dangerous, but it can decide whether one is known-safe. The cost is over-scoring benign actions like `s3:GetBucketLocation` until they are explicitly listed.

The model is a documented heuristic, not a validated one. Full rationale, including why CVSS was not used and what validating it would require, is in [`docs/architecture.md`](docs/architecture.md) and [`docs/interview-notes.md`](docs/interview-notes.md).

---

## Performance

Measured against a lab account, 4 regions scanned, `us-east-1` client.

| Buckets | Sequential | 10 workers | Speedup |
|---|---:|---:|---:|
| 3 | 2.10s | 2.36s | none |
| 53 | 11.41s | 4.02s | 2.8× |

At small bucket counts concurrency does not help: roughly seven API calls are sequential regardless of bucket count (`sts:GetCallerIdentity`, `s3:ListBuckets`, account-level BPA, and one `ec2:DescribeSecurityGroups` per region), and thread-pool setup costs more than it saves. The per-bucket work — five calls each — is what scales, and that is what the thread pool parallelizes.

The 2.8× figure rather than 10× reflects that fixed overhead: with 53 buckets, most of the ~272 total calls are parallelizable, but the remaining seven still run in series.

This is wall-clock measurement, not profiling.

---

## Testing

53 tests running in GitHub Actions on every push and pull request.

Three layers, each covering what the others cannot:

| Layer | Covers | Blind to |
|---|---|---|
| Snapshot fixtures | Check logic, precedence rules, severity derivation | Real AWS response shapes |
| `botocore.stub.Stubber` | Collector error handling and response parsing | Whether error codes match reality |
| Live account runs | Real response shapes, error codes, permission boundaries | Branches the account cannot produce |

Scanner and collector tests need no AWS credentials — checks are pure functions over a snapshot dictionary and never call boto3, so there is nothing to authenticate against. CI on a runner with no AWS configuration is what verifies that claim.

Persistence and API tests do need a database. CI runs a Postgres service container for them, and each test executes inside a transaction that is rolled back afterwards.

Two collector branches are tested despite being unreachable in a modern account: `NoSuchPublicAccessBlockConfiguration` at the bucket level and `OwnershipControlsNotFoundError`. AWS configures both on every bucket created since 2023, so only legacy resources can trigger them — which is exactly where old misconfigurations live.

---

## Tech stack

| Layer | Technology | Status |
|---|---|---|
| Infrastructure (target lab) | Terraform, AWS | Built |
| Collection | Python, boto3 | Built |
| Detection | Pure functions over a snapshot | Built |
| Event pipeline | CloudTrail, EventBridge, Lambda | Built |
| Remediation | Python handlers keyed by CIS control | Built |
| Persistence | PostgreSQL, SQLAlchemy | Built |
| API | FastAPI, Pydantic | Built |
| Dashboard | Next.js, TypeScript, Tailwind CSS | Built |
| Tests | pytest, botocore Stubber | Built |
| CI | GitHub Actions | Built |
| Alerting | SNS | Built |
| Alerting | Slack webhook | Planned |

---

## Getting started

### Prerequisites

- A **dedicated** AWS account you are willing to deploy deliberately insecure resources into — see [Safety](#safety)
- Terraform >= 1.6
- Python >= 3.11
- Docker, for the local Postgres instance
- Node 18+, for the dashboard
- Two AWS profiles: one read-only for scanning, one with write access for Terraform

### 1. Set up credentials

The scanner and the lab deployer are deliberately separate identities. The scanner cannot modify what it scans.

```bash
# Read-only scanner identity — attach the AWS-managed SecurityAudit policy
aws configure

# Lab deployer — needs PowerUserAccess + IAMFullAccess
aws configure --profile terraform
```

### 2. Deploy the vulnerable lab

```bash
cd terraform/
terraform init
terraform apply
```

Optionally deploy the remediation stack:

```bash
cd remediation/
terraform init
terraform apply -var="notification_email=you@example.com"
```

### 3. Start the database

```bash
docker compose up -d
python -m api.db.init
```

`.env` needs `POSTGRES_PASSWORD` set. Avoid `@`, `$`, and `:` in the value — all three break either the connection URL or Compose's variable interpolation.

### 4. Run a scan and persist it

```python
from scanner.collector import collect_snapshot
from scanner.runner import run_scan
from api.db.session import SessionLocal
from api.db.writer import write_scan_results

snapshot = collect_snapshot()
result = run_scan(snapshot)

with SessionLocal() as session:
    write_scan_results(session, result)
    session.commit()
```

A CLI entrypoint (`python -m scanner`) is not yet implemented.

### 5. Start the API and dashboard

```bash
python -m uvicorn api.main:app --reload
```

```bash
cd frontend/
npm install
npm run dev
```

Dashboard at `localhost:3000`, API docs at `localhost:8000/docs`.

### 6. Run the tests

```bash
python -m pytest scanner/ -q
```

Requires Postgres running; no AWS credentials needed.

### 7. Tear everything down

```bash
cd terraform/
terraform destroy
```

**Always run `terraform destroy` when finished.** Leaving this environment running exposes real, internet-reachable insecure resources under your account.

---

## Sample output

Against the deployed lab, scanning four regions:

```text
ScanStatus.COMPLETED
3.1.4 CheckStatus.VIOLATIONS 1
6.3   CheckStatus.VIOLATIONS 1
2.14  CheckStatus.VIOLATIONS 1
us-east-1 ok 2
us-east-2 ok 1
us-west-1 ok 1
us-west-2 ok 1
```

The same scan run under an identity lacking `s3:GetBucketPolicy`:

```text
ScanStatus.INCOMPLETE
3.1.4 CheckStatus.CANT_EVALUATE 0
6.3   CheckStatus.VIOLATIONS 1
2.14  CheckStatus.VIOLATIONS 1
```

Zero S3 findings — and the status says so, rather than reporting a clean environment. The security group and IAM checks are unaffected because their permissions were intact, so visibility degrades per check rather than all at once.

---

## Repository structure

```text
.
├── terraform/              # Vulnerable lab environment
│   └── remediation/        # EventBridge rules, Lambda, SNS topic
├── scanner/
│   ├── collector.py        # boto3 collection → snapshot
│   ├── models.py           # Finding, Severity
│   ├── registry.py         # BaseCheck, CheckResult, check registry
│   ├── runner.py           # Scan orchestration, requires gating
│   ├── scoring.py          # Capability-based severity model
│   ├── fixtures.py         # Snapshot fixtures for tests
│   ├── checks/             # One module per CIS control
│   └── tests/              # pytest suite
├── lambda_functions/       # Remediation handlers and event handler
├── api/
│   ├── main.py             # FastAPI endpoints
│   ├── schemas.py          # Pydantic response models
│   └── db/                 # SQLAlchemy models, session, writer
├── frontend/               # Next.js dashboard
├── docs/                   # Architecture notes, comparison, interview notes
├── docker-compose.yml      # Local Postgres
└── .github/workflows/      # CI
```

---

## Design decisions

[`docs/architecture.md`](docs/architecture.md) records sixteen design decisions with their reasoning, rejected alternatives, and costs. [`docs/interview-notes.md`](docs/interview-notes.md) answers the defense questions behind them. The ones that shape everything else:

- **Collect-then-evaluate.** Checks are pure functions over a snapshot and never call boto3. The test suite hands them dictionaries; no credentials, no mocking library.
- **Per-value retrieval status.** Every collected value carries its own status. A bucket with no policy and a bucket whose policy returned `AccessDenied` both have `document: None`; only the status distinguishes them, and conflating them produces a silent false negative.
- **Explicit incompleteness.** `CheckResult` has a `PARTIAL` status and an `unevaluated` list. Incompleteness lives in the field every consumer already reads, not in optional metadata one might forget to check.
- **Deterministic finding IDs.** A SHA-256 digest of account, region, control, resource, and sub-resource — so a suppression made today still matches the same finding tomorrow.
- **Separate remediation handlers.** Detection checks stay pure; remediation runs in the Lambda execution context with handlers selected by control ID. The scanner package ships to Lambda whole, so the separation is about execution boundaries rather than deployment size.
- **Re-scan before remediation.** The Lambda reads the affected resource again and runs the same detection implementation before modifying it. Costs extra API calls and read permissions; avoids trusting stale event data.
- **Threshold-based auto-remediation.** Automatic changes are limited to exact TCP 22 and 3389 exposures. Broad ranges and `IpProtocol: "-1"` generate findings but are never changed automatically.
- **2.14 is detect-only.** Detaching an administrative IAM policy could break a legitimate workload. A remediation that causes an outage is worse than a finding left for manual review.
- **Suppression requires accountability and expiry.** Enforced in the schema, not suggested in documentation.
- **Status is computed at read time.** No background job, no stale state, and the audit trail of who suppressed what survives intact.

---

## Known gaps

Stated rather than hidden:

- **The API has no authentication.** Anyone who can reach it can suppress any finding under any name. `suppressed_by` is accountability metadata, not proof of identity.
- **IPv6 is not checked.** A security group rule opening `::/0` on port 22 is equally public and is currently missed.
- **`NotAction` is not handled.** A policy statement with `NotAction: ["iam:*"]` and `Resource: "*"` grants everything except IAM — effectively admin, and check 2.14 misses it.
- **Default security groups are not flagged.** Prowler reports them under CIS 4.3; this scanner ignores them because their ingress references the group itself. That is a gap, not a difference of opinion — see [`docs/tool-comparison.md`](docs/tool-comparison.md).
- **Regions are hardcoded** to four US regions in the collector. Resources elsewhere are silently unscanned.
- **The severity model is unvalidated.** It is a documented heuristic; no reference set or inter-rater comparison has been run against it.
- **No configured backoff.** The scanner inherits boto3's default retry behavior, which has not been tuned or tested under throttling.
- **No integration test.** The collector and the checks are each tested; the seam between them is not.
- **No coverage measurement.** The paths believed to be covered and the paths that actually execute are not guaranteed to be the same set.
- **No CLI.** Scans run from Python, not a command line.
- **The trend view has one data point.** The schema supports history; nothing has generated it over time yet.
- **`api/db` imports from `scanner`.** Works, but the boundary needs rethinking if the findings platform ever deploys independently.
- **Three of six planned checks are built.**

---

## Safety

This repository provisions **intentionally insecure AWS infrastructure**. Read before running:

- Deploy only into an isolated sandbox account with no production data and no shared credentials.
- Public S3 buckets and `0.0.0.0/0` security groups are reachable by anyone on the internet, including automated scanners, within minutes of creation.
- Set an AWS Budget alert before applying. Some resources fall outside the free tier.
- Never commit `.tfstate`, `.tfvars`, `credentials`, or `.env` files. See `.gitignore`.
- Destroy the environment as soon as you finish testing.

---

## Roadmap

- [x] Dedicated sandbox account, IAM setup, budget guardrails (Unit 0)
- [x] Threat model and CIS control selection (Unit 1)
- [x] Reproducible vulnerable lab in Terraform (Unit 2)
- [x] Finding model and check registry (Unit 3)
- [x] First checks: S3 public access, open admin ports (Unit 4)
- [x] Capability-based severity model (Unit 5)
- [x] Live collection, multi-region scanning, concurrency (Unit 6)
- [x] IAM wildcard policy check — CIS 2.14 (Unit 6)
- [x] Test suite and CI (Unit 7)
- [x] EventBridge → Lambda remediation with SNS notifications (Unit 8)
- [x] Prowler coverage comparison (Unit 9)
- [x] Postgres persistence, FastAPI, Next.js dashboard (Unit 10)
- [x] Documentation and portfolio packaging (Unit 11)
- [ ] Remaining three checks — CIS 4.1, 2.10, 2.12
- [ ] API authentication
- [ ] Scheduled scans, so the trend view has data
- [ ] *Stretch:* multi-account via AWS Organizations, Security Hub (ASFF) export

---

## License

MIT — see [LICENSE](LICENSE).