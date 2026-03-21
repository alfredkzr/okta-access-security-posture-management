# AWS Terraform Deployment Design

## Context

Deploy the Okta ASPM platform to AWS with the lowest possible cost, using Terraform for infrastructure provisioning. The platform is an internal security tool used by 1-5 people, running 24/7 to support scheduled scans.

## Constraints

- Budget: under $20/mo target (realistic minimum ~$20-22/mo)
- Users: 1-5 (internal team)
- Availability: 24/7 (scheduled scans run overnight)
- Domain required for Okta OIDC login (HTTPS required for OAuth2 redirect URIs)
- No high-availability requirement (single point of failure acceptable)

## Architecture

Single EC2 instance running the existing docker-compose stack. All 6 containers (PostgreSQL, Redis, FastAPI backend, SAQ worker, frontend/nginx, Caddy) run on one machine.

### AWS Resources

| Resource | Details | Monthly Cost |
|----------|---------|--------------|
| EC2 t4g.small | ARM64, 2 vCPU, 2GB RAM, Amazon Linux 2023 | ~$12.26 |
| Public IPv4 address | $0.005/hr (since Feb 2024 pricing) | ~$3.60 |
| EBS gp3 30GB | Root volume, encrypted | ~$2.40 |
| Security Group | Ports 22 (SSH, restricted IP), 80, 443 (restricted IP) | $0 |
| S3 Bucket | DB backups, encrypted, 7-day lifecycle | ~$0.02 |
| IAM Role + Instance Profile | EC2 to S3 access for backups | $0 |
| Key Pair | SSH access via user's public key | $0 |
| CloudWatch Alarm | StatusCheckFailed alarm + SNS email | $0 (free tier) |
| **Total** | | **~$18-19/mo** |

**Cost reduction option:** 1-year reserved instance (no upfront) drops EC2 to ~$7.50/mo, total ~$14/mo.

### Required: docker-compose.prod.yml Resource Limit Changes

The current `docker-compose.prod.yml` has resource reservations totaling 2,024MB — the entire 2GB of a t4g.small. A `docker-compose.aws.yml` override will reduce limits for the constrained environment:

| Container | Current Limit/Reserve | AWS Override Limit/Reserve |
|-----------|----------------------|---------------------------|
| PostgreSQL | 2G / 1G | 512M / 256M |
| Backend | 1G / 512M | 512M / 256M |
| Worker | 512M / 256M | 384M / 128M |
| Redis | 512M / 128M | 256M / 64M |
| Caddy | 256M / — | 128M / — |
| Frontend | 256M / 128M | 128M / 64M |
| **Total** | 4.5G / 2G | 1.9G / 768M |

Additionally:
- Backend: 2 uvicorn workers instead of 4
- PostgreSQL: `shared_buffers=64MB`, `work_mem=2MB`
- 2GB swap file configured in cloud-init as safety net

The compose command becomes:
```bash
docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.aws.yml up -d --build
```

### Network

- **Default VPC** — no custom VPC, no NAT gateway (saves ~$30/mo)
- **Security group inbound rules:**
  - Port 22 (SSH): restricted to operator's IP (`allowed_ssh_cidr`)
  - Port 80 (HTTP): restricted to operator's IP (`allowed_web_cidr`) — redirects to HTTPS
  - Port 443 (HTTPS): restricted to operator's IP (`allowed_web_cidr`)
- **Security group outbound:** all traffic (Okta API calls, Docker Hub, package installs)
- **Domain required:** Okta OIDC requires HTTPS redirect URIs. A domain is needed from day one for Caddy to auto-provision TLS via Let's Encrypt. Even a cheap domain ($3-12/yr) works. The `DOMAIN` Terraform variable is required (not optional).

### Instance Bootstrap (cloud-init)

The EC2 user data script (templated by Terraform) performs:

1. Install Docker and Docker Compose plugin via `dnf` (Amazon Linux 2023)
2. Enable and start Docker service
3. Configure 2GB swap file (`fallocate`, `mkswap`, `swapon`, persist in `/etc/fstab`)
4. Clone the GitHub repository to `/opt/aspm` (using deploy key or GitHub token for private repos)
5. Write `.env` file from Terraform variables to `/opt/aspm/.env` (chmod 600, owned by root)
6. Build images and start the stack with AWS override
7. Install daily cron for PostgreSQL backup to S3
8. Enable Docker to start on boot (systemd)

**Image strategy:** Build on the instance from source. No container registry needed. First boot takes 10-20 minutes on ARM for image builds. Subsequent reboots use cached images.

**ARM64 consideration:** The t4g instance is ARM-based. The Dockerfile uses `python:3.13-slim` and `node:22-alpine` which both have ARM64 variants. No changes needed to the existing Dockerfiles.

**Private repo access:** A `github_deploy_key` Terraform variable (sensitive) provides SSH access for `git clone`. Cloud-init writes the key to `/root/.ssh/id_ed25519` and adds GitHub to `known_hosts`. If the repo is public, this variable can be left empty and HTTPS clone is used instead.

### Secrets Management

Secrets stored as Terraform variables in `terraform.tfvars` (gitignored). Cloud-init writes them to `/opt/aspm/.env` on the instance.

Secrets managed:
- `OKTA_API_TOKEN`
- `OKTA_ORG`
- `OKTA_ORG_TYPE`
- `OKTA_CLIENT_ID`
- `OKTA_CLIENT_SECRET`
- `OKTA_ISSUER`
- `ENCRYPTION_KEY`
- `SECRET_KEY`
- `POSTGRES_PASSWORD`

**Terraform state backend:** S3 bucket with encryption + DynamoDB lock table for state. This prevents secrets from sitting in a local plaintext file and enables state locking. Cost: effectively $0 at this scale.

### Backup & Recovery

**Daily PostgreSQL backup:**
- Cron job at 2:00 AM UTC via script at `/opt/aspm/backup.sh`
- Script validates pg_dump exit code before uploading (no zero-byte uploads)
- Gzip and upload to S3 bucket via AWS CLI (pre-installed on Amazon Linux 2023)
- Logs to `/var/log/aspm-backup.log`
- S3 lifecycle policy: delete objects older than 7 days
- S3 bucket has versioning enabled and AES-256 server-side encryption

**Reports directory:**
- Lives on EBS at `/opt/aspm/data/reports`
- Persists across container restarts and reboots
- Included in daily backup tar to S3

**Redis:**
- No backup. Redis is ephemeral (job queue, health cache). App rebuilds state on restart.

**Recovery procedure:**
1. SSH into instance
2. Download backup: `aws s3 cp s3://<bucket>/backup-YYYY-MM-DD.sql.gz .`
3. Gunzip and restore: `gunzip backup.sql.gz && docker exec -i aspm-db psql -U aspm < backup.sql`

**Disaster recovery (full instance loss):**
1. `terraform apply` — provisions new instance
2. Cloud-init rebuilds the stack
3. Restore latest backup from S3

### Monitoring

- **CloudWatch basic monitoring** (free): CPU, network, disk at 5-min intervals
- **CloudWatch alarm:** `StatusCheckFailed` triggers SNS email notification (free tier: 10 alarms)
- **SNS topic:** email subscription for backup failures and instance health
- **On-instance:** `docker stats` for container-level monitoring via SSH

### Terraform File Structure

```
terraform/
├── main.tf              # AWS provider, terraform settings, S3 backend
├── variables.tf         # All input variables with descriptions
├── outputs.tf           # Public IP, S3 bucket name, SSH command, domain URL
├── ec2.tf               # Instance, key pair, elastic IP, EIP association
├── security_group.tf    # Ingress/egress rules
├── s3.tf                # Backup bucket, lifecycle policy, encryption
├── iam.tf               # IAM role, policy, instance profile (EC2 → S3)
├── monitoring.tf        # CloudWatch alarm, SNS topic
├── user_data.sh         # cloud-init script (templatefile with variables)
├── docker-compose.aws.yml  # Resource limit overrides for t4g.small
├── backup.sh            # pg_dump backup script (templated)
├── terraform.tfvars.example # Example variables file
├── terraform.tfvars     # Secrets and config (GITIGNORED)
└── .gitignore           # terraform.tfvars, *.tfstate, *.tfstate.backup, .terraform/
```

### Terraform Variables

```hcl
# AWS
variable "aws_region"       {}  # e.g., "us-west-2"
variable "ssh_public_key"   {}  # Public key content
variable "allowed_ssh_cidr" {}  # Your IP, e.g., "1.2.3.4/32"
variable "allowed_web_cidr" {}  # Your IP/range for web access, e.g., "1.2.3.4/32"

# Domain (required for Okta OIDC)
variable "domain"           {}  # e.g., "aspm.example.com"

# GitHub
variable "github_repo_url"    { default = "https://github.com/<user>/okta-access-security-posture-management.git" }
variable "github_deploy_key"  { default = ""; sensitive = true }  # SSH key for private repos

# App secrets
variable "okta_api_token"     { sensitive = true }
variable "okta_org"           {}
variable "okta_org_type"      { default = "okta" }
variable "okta_client_id"     {}
variable "okta_client_secret" { sensitive = true }
variable "okta_issuer"        {}
variable "encryption_key"     { sensitive = true }
variable "secret_key"         { sensitive = true }
variable "postgres_password"  { sensitive = true }

# Monitoring
variable "alert_email"        {}  # Email for CloudWatch alarm notifications
```

### AMI Selection

Use a Terraform data source for the latest Amazon Linux 2023 ARM64 AMI rather than hardcoding an AMI ID:

```hcl
data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  owners      = ["amazon"]
  filter {
    name   = "name"
    values = ["al2023-ami-*-arm64"]
  }
}
```

### Deployment Workflow

```bash
# First time
cd terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your values
terraform init
terraform plan
terraform apply
# Output: elastic_ip, ssh_command, app_url

# Point your domain DNS (A record) to the elastic_ip output
# Caddy auto-provisions TLS once DNS propagates

# App updates (no Terraform needed)
ssh -i ~/.ssh/key ec2-user@<elastic-ip>
cd /opt/aspm
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml -f docker-compose.aws.yml up -d --build

# Infrastructure changes
terraform plan
terraform apply
```

### Cost Optimization Notes

- **t4g (ARM)** is 20% cheaper than t3 (x86) for equivalent specs
- **No NAT gateway** — uses default VPC with public subnet ($30/mo savings)
- **No ALB/NLB** — Caddy on the instance handles reverse proxy ($16/mo savings)
- **No RDS** — PostgreSQL runs in Docker ($12+/mo savings)
- **No ElastiCache** — Redis runs in Docker ($9+/mo savings)
- **No ECR** — build images on instance ($1/mo savings)
- **Reserved instance** (1yr, no upfront) would drop EC2 to ~$7.50/mo, total ~$14/mo

### Limitations

- **Single point of failure:** instance failure = full downtime until Terraform re-provisions
- **2GB RAM is constrained:** reduced resource limits + swap mitigate this, but batch scans of very large Okta tenants (5000+ users) may be slow or require increased `max_workers` caution
- **No auto-scaling:** fixed capacity, but sufficient for 1-5 users
- **Manual app deploys:** SSH + git pull + docker compose up. No CI/CD pipeline.
- **Backup RPO:** 24 hours (daily pg_dump). Data between backups is lost on disk failure.
- **EIP cost when stopped:** if instance is stopped (e.g., for resize), EIP costs $0.005/hr (~$3.60/mo). Minimize stop duration.
