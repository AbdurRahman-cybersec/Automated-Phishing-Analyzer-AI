# Automated Phishing Analyzer — AWS Deployment Plan

## Goal

Deploy the phishing analyzer in AWS so URL scans can run remotely, reports can be stored centrally, and users can interact through a web UI, API, Discord bot, or scheduled jobs.

The current project is a local Python/Tkinter desktop app. Tkinter is not a good fit for AWS-hosted production use because it expects a local graphical desktop. The best AWS path is to separate the project into:

- **Analysis backend**: Python scanning engine from `url_scraper.py`
- **Job runner**: isolated workers that run scans and screenshots
- **Frontend/API**: web UI, REST API, or Discord bot
- **Storage**: reports, screenshots, reputation DB, scan history
- **Security boundary**: container or VM isolation for risky URL visits

## Deployment Options

## Option 1 — Simple EC2 Deployment

Best for early testing and demos.

### Architecture

```text
User / Admin
  -> EC2 instance
      -> Python analyzer
      -> Local Chromium screenshot capture
      -> Local SQLite/reports folder
```

### AWS Services

- EC2 Ubuntu instance
- EBS volume for reports
- Security Group with SSH restricted to your IP
- Optional: S3 backup bucket
- Optional: CloudWatch Agent for logs

### Pros

- Fastest to deploy.
- Minimal code changes.
- Good for personal use and demos.

### Cons

- Not multi-user friendly.
- Risky URL browsing happens on the EC2 host.
- Tkinter GUI still requires remote desktop/VNC if you want the desktop interface.
- Scaling is manual.

### Steps

1. Launch Ubuntu EC2 instance.
2. Restrict SSH to your IP.
3. Install dependencies:

```bash
sudo apt update
sudo apt install -y python3 python3-pip nodejs npm chromium-browser
pip3 install -r requirements.txt
npm install
```

4. Set browser path:

```bash
export BROWSER_PATH=/usr/bin/chromium-browser
```

5. Add secrets through environment variables or `.env`.
6. Run CLI/backend scan manually.
7. Sync reports to S3:

```bash
aws s3 sync scraped_sites/ s3://YOUR-BUCKET/scraped_sites/
```

## Option 2 — EC2 With Web API

Best near-term path without fully redesigning the app.

### Architecture

```text
Browser / Discord Bot / API Client
  -> FastAPI service on EC2
      -> url_scraper.py
      -> Chromium screenshot capture
      -> SQLite or PostgreSQL
      -> S3 report storage
```

### Required Code Changes

- Add a FastAPI app:
  - `POST /scan`
  - `GET /scan/{scan_id}`
  - `GET /report/{scan_id}`
  - `GET /screenshot/{scan_id}`
- Move long-running scans into background jobs.
- Save scan output under a scan ID.
- Add API authentication.

### AWS Services

- EC2
- S3 for reports/screenshots
- Secrets Manager or SSM Parameter Store for API keys
- CloudWatch Logs
- Optional: Application Load Balancer
- Optional: ACM certificate for HTTPS

### Pros

- Reuses most Python code.
- Easier to connect the Discord bot.
- Can build a web frontend later.

### Cons

- Still runs browser captures on one EC2 host.
- Needs background job management.
- Scaling requires more work.

## Option 3 — Production Container Architecture

Best long-term architecture.

### Architecture

```text
User / Web UI / Discord Bot
  -> API Gateway or ALB
  -> API service
  -> SQS scan queue
  -> ECS/Fargate worker containers
      -> Python analyzer
      -> Headless Chromium
      -> Temporary container filesystem
  -> S3 reports/screenshots
  -> DynamoDB or RDS scan metadata
  -> CloudWatch logs/metrics
```

### AWS Services

- ECS Fargate for scan workers
- ECR for container images
- SQS for scan queue
- S3 for reports and screenshots
- DynamoDB or RDS/PostgreSQL for scan metadata
- Secrets Manager for API keys
- CloudWatch Logs and metrics
- EventBridge for scheduled scans
- API Gateway or Application Load Balancer
- Cognito if user login is needed

### Pros

- Better isolation than a shared EC2 process.
- Scans can scale horizontally.
- Failed scans do not poison the whole service.
- Cleaner production architecture.
- Easier to add Discord, web UI, and scheduled scans.

### Cons

- Requires containerization.
- More AWS setup.
- Browser-in-container needs careful tuning.
- Fargate runtime cost can grow with scan volume.

## Recommended Production Architecture

Use this target design:

```text
Frontend
  -> React/Next.js or static UI hosted on S3 + CloudFront

API
  -> FastAPI container on ECS Fargate
  -> receives scan requests
  -> validates/authenticates users
  -> writes scan job to SQS

Workers
  -> ECS Fargate task
  -> consumes SQS job
  -> runs analyzer
  -> launches Chromium in the container
  -> uploads JSON report and screenshot to S3
  -> writes status/result metadata to DynamoDB or RDS

Storage
  -> S3: HTML, screenshots, extracted JSON, analysis JSON
  -> DynamoDB/RDS: scan records, verdicts, status, timestamps
  -> Secrets Manager: API keys

Observability
  -> CloudWatch logs
  -> CloudWatch alarms
  -> optional SNS notifications
```

## Suggested AWS Resource Layout

## S3 Buckets

```text
phishing-analyzer-reports-prod
phishing-analyzer-artifacts-prod
```

Store:

- `reports/{scan_id}/analysis.json`
- `reports/{scan_id}/extracted_data.json`
- `reports/{scan_id}/page_preview.png`
- `reports/{scan_id}/page.html`

Use lifecycle policies:

- Delete raw HTML after 30-90 days.
- Keep final JSON reports longer.
- Optionally archive old reports to S3 Glacier classes.

## DynamoDB Tables

### `ScanJobs`

Fields:

- `scan_id`
- `url`
- `domain`
- `status`
- `created_at`
- `updated_at`
- `final_verdict`
- `risk_score`
- `confidence`
- `s3_report_prefix`
- `error`

### `DomainReputation`

Fields:

- `domain`
- `scan_count`
- `avg_risk`
- `last_verdict`
- `first_seen`
- `last_seen`

## SQS Queues

- `phishing-scan-queue`
- `phishing-scan-dlq`

Use the dead-letter queue for jobs that repeatedly fail.

## Secrets

Store these in AWS Secrets Manager or SSM Parameter Store:

- `OPENROUTER_API_KEY`
- `DEEPSEEK_API_KEY`
- `VIRUSTOTAL_API_KEY`
- `PHISHTANK_API_KEY`
- Discord bot token if deployed

Do not store secrets in `.env` on production hosts.

## Containerization Plan

Create a Docker image for the analyzer worker.

### Example Dockerfile Direction

```dockerfile
FROM python:3.12-slim

RUN apt-get update && apt-get install -y \
    nodejs npm chromium \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt package.json package-lock.json ./
RUN pip install --no-cache-dir -r requirements.txt
RUN npm ci --omit=dev

COPY . .

ENV BROWSER_PATH=/usr/bin/chromium

CMD ["python3", "worker.py"]
```

Notes:

- Do not run browser captures as root if avoidable.
- Use temporary directories for browser profiles.
- Avoid mounting host filesystems.
- Limit memory/CPU per worker.
- Set scan timeouts.

## API Design

## `POST /scan`

Request:

```json
{
  "url": "https://example.com",
  "options": {
    "capture_screenshot": true,
    "use_ai": true
  }
}
```

Response:

```json
{
  "scan_id": "uuid",
  "status": "queued"
}
```

## `GET /scan/{scan_id}`

Response:

```json
{
  "scan_id": "uuid",
  "status": "complete",
  "verdict": "PHISHING",
  "risk_score": 85,
  "confidence": 95,
  "report_url": "s3-or-signed-url"
}
```

## `GET /scan/{scan_id}/report`

Returns final report JSON.

## `GET /scan/{scan_id}/screenshot`

Returns a signed URL or streams the screenshot.

## Worker Flow

```text
1. Poll SQS for job.
2. Mark scan as running.
3. Normalize URL.
4. Download page.
5. Extract fields.
6. Download assets.
7. Analyze JS/CSS.
8. Capture screenshot in container Chromium.
9. Check VirusTotal / PhishTank.
10. Run heuristic analysis.
11. Run AI analysis.
12. Calibrate final verdict.
13. Upload report artifacts to S3.
14. Update scan metadata.
15. Delete temporary files.
```

## Security Controls

## Network

- Run workers in private subnets if possible.
- Use NAT Gateway or controlled outbound access.
- Block inbound access to worker tasks.
- API service is the only public entry point.

## URL Safety

- Block private/internal IP ranges:
  - `127.0.0.0/8`
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
  - link-local and metadata IPs
- Block AWS metadata endpoint:
  - `169.254.169.254`
- Resolve DNS before scanning and reject private IP targets.
- Limit redirects and re-check every redirect destination.
- Set per-scan timeouts.

## Browser Isolation

- Use a fresh temporary browser profile per scan.
- Disable extensions.
- Do not mount secrets into browser profile directories.
- Delete all temporary browser data after scan.
- Consider one worker task per scan for stronger isolation.

## Secrets

- Use task roles and Secrets Manager.
- Never log API keys.
- Scrub secrets from errors.

## IAM

Use least privilege:

- API task can write SQS jobs and read scan metadata.
- Worker task can read SQS jobs, write S3 reports, update metadata, and read secrets.
- Frontend should not access secrets.

## Observability

CloudWatch logs:

- API request logs
- worker scan logs
- screenshot capture errors
- API provider failures

Metrics:

- scans queued
- scans completed
- scans failed
- average scan time
- screenshot failure rate
- AI failure rate
- VirusTotal failure rate
- phishing/suspicious/safe counts

Alarms:

- queue depth too high
- worker failures
- high screenshot failure rate
- high API error rate

## Discord Bot Deployment

The current `bot.js` can evolve into a frontend client for the AWS API.

Recommended flow:

```text
User DMs Discord bot URL
  -> bot calls POST /scan
  -> bot replies with queued scan ID
  -> bot polls GET /scan/{scan_id}
  -> bot posts final verdict and report link
```

Deployment options:

- ECS Fargate long-running Discord bot container
- EC2 process with systemd
- Avoid Lambda for always-connected Discord gateway bots unless using interaction webhooks instead of gateway sessions

## Migration Roadmap

## Phase 1 — Backend Extraction

- Refactor `url_scraper.py` so scan results are easy to call from API/worker code.
- Add stable scan result schema.
- Add CLI command:

```bash
python3 url_scraper.py scan https://example.com --json
```

## Phase 2 — FastAPI Service

- Add FastAPI app.
- Add `/scan` and `/scan/{scan_id}`.
- Initially run scans in local background thread/process.
- Store reports locally or in S3.

## Phase 3 — S3 + DynamoDB

- Upload reports/screenshots to S3.
- Store scan metadata in DynamoDB.
- Add signed URLs for screenshots/reports.

## Phase 4 — SQS Worker Queue

- Add SQS.
- Move scanning into worker process.
- API only queues jobs and reads status.

## Phase 5 — ECS Fargate

- Containerize API and worker.
- Push images to ECR.
- Deploy ECS services/tasks.
- Add CloudWatch logs.

## Phase 6 — Web UI

- Build a React/Next.js frontend.
- Host on S3 + CloudFront or deploy to Amplify.
- Add authentication if needed.

## Phase 7 — Safer Isolation

- Use one worker task per scan for risky URLs.
- Add private IP blocking.
- Add stricter redirect validation.
- Add Docker/browser hardening.

## Phase 8 — Production Hardening

- Add WAF.
- Add rate limiting.
- Add audit logs.
- Add lifecycle policies.
- Add cost alarms.
- Add tests and CI/CD.

## Minimum Viable AWS Deployment

If the goal is to deploy quickly:

1. Launch EC2 Ubuntu.
2. Install Python, Node, Chromium, dependencies.
3. Run analyzer through CLI or simple FastAPI wrapper.
4. Store reports on EBS.
5. Sync reports to S3.
6. Restrict SSH and never expose raw desktop services publicly.

## Best Long-Term AWS Deployment

Use:

- FastAPI API service
- SQS job queue
- ECS Fargate worker containers
- S3 report storage
- DynamoDB scan metadata
- Secrets Manager
- CloudWatch
- React/Next.js web frontend

This architecture keeps scans asynchronous, scalable, auditable, and much safer than running every scan inside one long-lived host process.
