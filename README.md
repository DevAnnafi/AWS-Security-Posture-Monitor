# AWS Security Posture Monitor

A cloud security posture management (CSPM) pipeline that detects AWS misconfigurations against the CIS AWS Foundations Benchmark, prioritizes findings by severity, and automatically remediates a defined subset in near real time.

> **Status:** In active development. See [Roadmap](#roadmap) for what is implemented today.

---

## Why this exists

Most cloud breaches trace back to configuration, not exotic exploits — a bucket left public, an IAM role with `Action: "*"`, a security group open to the internet on 22. Commercial CSPM tools (Wiz, Prowler, ScoutSuite) solve this well; this project reimplements the core detection-and-response loop from scratch to demonstrate the underlying mechanics: how findings are gathered from cloud APIs, mapped to a control framework, scored, and driven to closure automatically.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────┐
│  Terraform: deliberately vulnerable AWS environment (lab)    │
│  public S3 · wildcard IAM · open SG · unencrypted EBS/RDS    │
└────────────────────────────┬─────────────────────────────────┘
                             │
          ┌──────────────────┴──────────────────┐
          │                                     │
   SCHEDULED SCAN                        EVENT-DRIVEN
          │                                     │
┌─────────▼──────────┐              ┌───────────▼────────────┐
│  Scanner (Python + │              │  CloudTrail → Event-   │
│  boto3)            │              │  Bridge rule           │
│  · CIS-mapped      │              │  · fires on risky      │
│    checks          │              │    config change       │
│  · severity scoring│              └───────────┬────────────┘
└─────────┬──────────┘                          │
          │                            ┌────────▼────────┐
          │                            │ Remediation     │
          │                            │ Lambda          │
          │                            │ · reverts change│
          │                            └────────┬────────┘
          │                                     │
┌─────────▼─────────────────────────────────────▼────────────┐
│  Findings store  →  FastAPI  →  Next.js dashboard          │
│                  →  SNS / Slack alert                      │
└────────────────────────────────────────────────────────────┘
```

<!-- TODO: replace this ASCII diagram with a rendered architecture image (draw.io / Excalidraw) before sharing the repo publicly. Recruiters skim images. -->

---

## Features

- **Framework-mapped detection.** Every check cites the CIS AWS Foundations Benchmark control it enforces, so findings are auditable rather than ad hoc.
- **Severity scoring.** Findings are ranked (Critical / High / Medium / Low) based on exposure and blast radius, not just check type.
- **Automated remediation.** A subset of finding types are reverted automatically via EventBridge → Lambda, closing the loop between detection and response.
- **Reproducible vulnerable lab.** The insecure target environment is defined in Terraform, so results are reproducible by anyone cloning the repo.
- **Tooling comparison.** Scanner output is benchmarked against Prowler and ScoutSuite to document coverage gaps honestly. See [`docs/tool-comparison.md`](docs/tool-comparison.md).

---

## Checks implemented

| CIS Control | Check | Severity | Auto-remediated |
|---|---|---|---|
| 2.1.1 | S3 bucket server-side encryption disabled | High | Yes |
| 2.1.5 | S3 bucket publicly accessible | Critical | Yes |
| 5.2 | Security group allows `0.0.0.0/0` on port 22 | Critical | Yes |
| 1.16 | IAM policy with `Action: "*"` on `Resource: "*"` | High | No |
| 3.1 | CloudTrail not enabled in all regions | High | No |
| 2.2.1 | EBS volume unencrypted | Medium | No |

<!-- TODO: keep this table in sync as you add checks. Do not list a check here until it actually runs. -->

---

## Tech stack

| Layer | Technology |
|---|---|
| Infrastructure (target lab) | Terraform, AWS |
| Detection | Python 3.11, boto3 |
| Event pipeline | CloudTrail, EventBridge, Lambda |
| Alerting | SNS, Slack webhook |
| API | FastAPI |
| Dashboard | Next.js, TypeScript, Tailwind CSS |
| CI | GitHub Actions (lint, `terraform validate`, unit tests) |

---

## Getting started

### Prerequisites

- An AWS account you are willing to deploy deliberately insecure resources into — see [Safety](#safety)
- AWS CLI configured with credentials (`aws configure`)
- Terraform >= 1.6
- Python >= 3.11

### 1. Deploy the vulnerable lab

```bash
cd terraform/
terraform init
terraform plan
terraform apply
```

### 2. Run a scan

```bash
cd scanner/
pip install -r requirements.txt
python -m scanner --region us-east-1 --output findings.json
```

### 3. Deploy the remediation pipeline

```bash
cd terraform/remediation/
terraform apply
```

### 4. Run the dashboard (optional)

```bash
cd api/ && uvicorn main:app --reload
cd dashboard/ && npm install && npm run dev
```

### 5. Tear everything down

```bash
terraform destroy
```

**Always run `terraform destroy` when finished.** Leaving this environment running exposes real, internet-reachable insecure resources under your account.

---

## Sample output

```
<!-- TODO: paste real scanner output here once the first checks pass. -->
```

---

## Repository structure

```
.
├── terraform/          # Vulnerable lab environment + remediation infra
│   └── remediation/    # EventBridge rules, Lambda, SNS topic
├── scanner/            # Python detection engine
│   ├── checks/         # One module per CIS control
│   └── scoring.py      # Severity model
├── lambda/             # Remediation handlers
├── api/                # FastAPI findings service
├── dashboard/          # Next.js findings UI
├── docs/               # Architecture notes, tool comparison
└── .github/workflows/  # CI
```

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

- [ ] Core scanner with the six checks above
- [ ] Severity scoring model
- [ ] Auto-remediation for S3 public access and open SSH
- [ ] Prowler / ScoutSuite coverage comparison
- [ ] FastAPI findings API
- [ ] Next.js dashboard
- [ ] Multi-account support via AWS Organizations
- [ ] Findings export to Security Hub (ASFF format)

---

## License

MIT — see [LICENSE](LICENSE).#
