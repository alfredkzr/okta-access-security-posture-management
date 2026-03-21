# AWS Terraform Deployment Design

## Context

Deploy the Okta ASPM platform to AWS with the lowest possible cost (~$14/mo), using Terraform for infrastructure provisioning. The platform is an internal security tool used by 1-5 people, running 24/7 to support scheduled scans.

## Constraints

- Budget: under $20/mo
- Users: 1-5 (internal team)
- Availability: 24/7 (scheduled scans run overnight)
- No domain initially (HTTP via Elastic IP, TLS added when domain acquired)
- No high-availability requirement (single point of failure acceptable)

## Architecture

Single EC2 instance running the existing docker-compose stack. All 6 containers (PostgreSQL, Redis, FastAPI backend, SAQ worker, frontend/nginx, Caddy) run on one machine.

### AWS Resources

| Resource | Details | Monthly Cost |
|----------|---------|--------------|
| EC2 t4g.small | ARM64, 2 vCPU, 2GB RAM, Amazon Linux 2023 | ~$12.26 |
| EBS gp3 20GB | Root volume, encrypted | ~$1.60 |
| Elastic IP | Static public IP (free when attached to running instance) | $0 |
| Security Group | Ports 22 (SSH, restricted IP), 80, 443 | $0 |
| S3 Bucket | DB backups, encrypted, 7-day lifecycle | ~$0.02 |
| IAM Role + Instance Profile | EC2 to S3 access for backups | $0 |
| Key Pair | SSH access via user's public key | $0 |
| **Total** | | **~$14/mo** |

### Network

- **Default VPC** — no custom VPC, no NAT gateway (saves ~$30/mo)
- **Security group inbound rules:**
  - Port 22 (SSH): restricted to operator's IP (Terraform variable)
  - Port 80 (HTTP): 0.0.0.0/0
  - Port 443 (HTTPS): 0.0.0.0/0
- **Security group outbound:** all traffic (Okta API calls, Docker Hub, package installs)
- **No domain initially:** access via `http://<elastic-ip>`. When a domain is configured, update `DOMAIN` env var and Caddy auto-provisions TLS via Let's Encrypt.

### Instance Bootstrap (cloud-init)

The EC2 user data script (templated by Terraform) performs:

1. Install Docker and Docker Compose plugin via `dnf` (Amazon Linux 2023)
2. Enable and start Docker service
3. Clone the GitHub repository to `/opt/aspm`
4. Write `.env` file from Terraform variables to `/opt/aspm/.env` (chmod 600)
5. Build images and start the stack: `docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build`
6. Install daily cron for PostgreSQL backup to S3
7. Enable Docker to start on boot (systemd)

**Image strategy:** Build on the instance from source. No container registry needed. First boot takes 5-10 minutes for image builds. Subsequent reboots use cached images.

**ARM64 consideration:** The t4g instance is ARM-based. The Dockerfile uses `python:3.13-slim` and `node:22-alpine` which both have ARM64 variants. No changes needed to the existing Dockerfiles.

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

Terraform state contains secrets in plaintext. Acceptable for a single-operator internal tool. State file is gitignored.

### Backup & Recovery

**Daily PostgreSQL backup:**
- Cron job at 2:00 AM UTC
- `docker exec` into PostgreSQL container, run `pg_dump`
- Gzip and upload to S3 bucket via AWS CLI (pre-installed on Amazon Linux 2023)
- S3 lifecycle policy: delete objects older than 7 days
- S3 bucket has versioning enabled and AES-256 server-side encryption

**Reports directory:**
- Lives on EBS at `/opt/aspm/data/reports`
- Persists across container restarts and reboots
- Optionally included in daily backup tar to S3

**Redis:**
- No backup. Redis is ephemeral (job queue, health cache). App rebuilds state on restart.

**Recovery procedure:**
1. SSH into instance
2. Download backup: `aws s3 cp s3://<bucket>/backup-YYYY-MM-DD.sql.gz .`
3. Gunzip and restore: `docker exec -i aspm-db psql -U aspm < backup.sql`

**Disaster recovery (full instance loss):**
1. `terraform apply` — provisions new instance
2. Cloud-init rebuilds the stack
3. Restore latest backup from S3

### Terraform File Structure

```
terraform/
├── main.tf              # AWS provider, terraform settings
├── variables.tf         # All input variables with descriptions
├── outputs.tf           # Public IP, S3 bucket name, SSH command
├── ec2.tf               # Instance, key pair, elastic IP
├── security_group.tf    # Ingress/egress rules
├── s3.tf                # Backup bucket, lifecycle policy, encryption
├── iam.tf               # IAM role, policy, instance profile (EC2 → S3)
├── user_data.sh         # cloud-init script (templatefile with variables)
├── terraform.tfvars     # Secrets and config (GITIGNORED)
└── .gitignore           # terraform.tfvars, *.tfstate, *.tfstate.backup, .terraform/
```

### Terraform Variables

```hcl
# AWS
variable "aws_region"       {}  # e.g., "us-west-2"
variable "ssh_public_key"   {}  # Public key content
variable "allowed_ssh_cidr" {}  # Your IP, e.g., "1.2.3.4/32"

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

# App config
variable "github_repo_url"   { default = "https://github.com/<user>/okta-access-security-posture-management.git" }
variable "domain"             { default = "" }  # Empty = HTTP only, set for TLS
variable "allowed_origins"    { default = "" }   # Set to domain when available
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
# Output: elastic_ip, ssh_command

# App updates (no Terraform needed)
ssh -i ~/.ssh/key ec2-user@<elastic-ip>
cd /opt/aspm
git pull
docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

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
- **Reserved instance** (1yr, no upfront) would drop EC2 to ~$7.50/mo if committed

### Limitations

- **Single point of failure:** instance failure = full downtime until Terraform re-provisions
- **2GB RAM is tight:** PostgreSQL (256MB shared_buffers) + Redis (256MB max) + FastAPI + Worker + nginx + Caddy. Monitor with `docker stats`.
- **No auto-scaling:** fixed capacity, but sufficient for 1-5 users
- **Manual app deploys:** SSH + git pull + docker compose up. No CI/CD pipeline.
- **Backup RPO:** 24 hours (daily pg_dump). Data between backups is lost on disk failure.
