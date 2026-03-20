"""Initial schema — all tables from v0.1.0.

Revision ID: 001
Revises: None
Create Date: 2026-03-20
"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # --- Enums ---
    vulnerabilitycategory = postgresql.ENUM(
        "auth_policy_violation", "inactive_app_users",
        name="vulnerabilitycategory", create_type=False,
    )
    severity = postgresql.ENUM("CRITICAL", "HIGH", "MEDIUM", "LOW", name="severity", create_type=False)
    vulnerabilitystatus = postgresql.ENUM(
        "ACTIVE", "CLOSED", "REMEDIATED", "ACKNOWLEDGED",
        name="vulnerabilitystatus", create_type=False,
    )
    impactstatus = postgresql.ENUM("ACTIVE", "RESOLVED", name="impactstatus", create_type=False)
    accessdecision = postgresql.ENUM("ALLOW", "DENY", "NO_MATCH", name="accessdecision", create_type=False)
    risklevel = postgresql.ENUM("LOW", "MEDIUM", "HIGH", "CRITICAL", name="risklevel", create_type=False)
    deviceplatform = postgresql.ENUM(
        "WINDOWS", "MACOS", "CHROMEOS", "ANDROID", "IOS", "DESKTOP_OTHER", "MOBILE_OTHER",
        name="deviceplatform", create_type=False,
    )
    scanstatus = postgresql.ENUM(
        "pending", "running", "completed", "completed_with_errors", "failed",
        name="scanstatus", create_type=False,
    )
    scheduletype = postgresql.ENUM("cron", "interval", "once", name="scheduletype", create_type=False)
    checkcategory = postgresql.ENUM(
        "admin_security", "mfa_posture", "api_token_hygiene", "app_config",
        "network_zones", "device_trust", "idp_config", "security_events",
        name="checkcategory", create_type=False,
    )
    findingstatus = postgresql.ENUM(
        "OPEN", "RESOLVED", "ACKNOWLEDGED", "FALSE_POSITIVE",
        name="findingstatus", create_type=False,
    )
    reporttype = postgresql.ENUM(
        "csv_full", "csv_violations", "csv_inactive", "csv_posture", "pdf", "json",
        name="reporttype", create_type=False,
    )

    # Create all enums
    for e in [
        vulnerabilitycategory, severity, vulnerabilitystatus, impactstatus,
        accessdecision, risklevel, deviceplatform, scanstatus, scheduletype,
        checkcategory, findingstatus, reporttype,
    ]:
        e.create(op.get_bind(), checkfirst=True)

    # --- scenarios ---
    op.create_table(
        "scenarios",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), default=True, nullable=False),
        sa.Column("risk_level", risklevel, nullable=True),
        sa.Column("device_platform", deviceplatform, nullable=False),
        sa.Column("device_registered", sa.Boolean(), nullable=False),
        sa.Column("device_managed", sa.Boolean(), nullable=True),
        sa.Column("device_assurance_id", sa.String(255), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=True),
        sa.Column("zone_ids", postgresql.JSONB(), nullable=True),
    )
    op.create_index("ix_scenarios_is_active", "scenarios", ["is_active"])
    op.create_index("ix_scenarios_risk_level", "scenarios", ["risk_level"])

    # --- scans ---
    op.create_table(
        "scans",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("job_id", sa.UUID(), nullable=True),
        sa.Column("job_name", sa.String(255), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("status", scanstatus, nullable=False),
        sa.Column("total_users", sa.Integer(), default=0, nullable=False),
        sa.Column("successful_users", sa.Integer(), default=0, nullable=False),
        sa.Column("failed_users", sa.Integer(), default=0, nullable=False),
        sa.Column("failed_user_details", postgresql.JSONB(), nullable=True),
        sa.Column("posture_findings_count", sa.Integer(), default=0, nullable=False),
        sa.Column("last_processed_user_index", sa.Integer(), default=0, nullable=False),
        sa.Column("progress_pct", sa.Float(), nullable=True),
        sa.Column("duration_seconds", sa.Float(), nullable=True),
        sa.Column("error_message", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_scans_status", "scans", ["status"])
    op.create_index("ix_scans_started_at", "scans", ["started_at"])
    op.create_index("ix_scans_job_id", "scans", ["job_id"])

    # --- vulnerabilities ---
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("category", vulnerabilitycategory, nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("status", vulnerabilitystatus, nullable=False),
        sa.Column("risk_score", sa.Integer(), default=0, nullable=False),
        sa.Column("risk_factors", postgresql.JSONB(), nullable=False),
        sa.Column("compliance_mappings", postgresql.JSONB(), nullable=True),
        sa.Column("policy_name", sa.String(255), nullable=True),
        sa.Column("policy_id", sa.String(255), nullable=True),
        sa.Column("rule_name", sa.String(255), nullable=True),
        sa.Column("rule_id", sa.String(255), nullable=True),
        sa.Column("app_name", sa.String(255), nullable=True),
        sa.Column("app_id", sa.String(255), nullable=True),
        sa.Column("active_impact_count", sa.Integer(), default=0, nullable=False),
        sa.Column("first_detected", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_detected", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("remediated_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("acknowledged_by", sa.String(255), nullable=True),
    )
    op.create_index("ix_vulnerabilities_status", "vulnerabilities", ["status"])
    op.create_index("ix_vulnerabilities_severity", "vulnerabilities", ["severity"])
    op.create_index("ix_vulnerabilities_category", "vulnerabilities", ["category"])
    op.create_index("ix_vulnerabilities_category_status", "vulnerabilities", ["category", "status"])
    op.create_index("ix_vulnerabilities_rule_id", "vulnerabilities", ["rule_id"])
    op.create_index("ix_vulnerabilities_app_id", "vulnerabilities", ["app_id"])

    # --- vulnerability_impacts ---
    op.create_table(
        "vulnerability_impacts",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("vulnerability_id", sa.UUID(), sa.ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False),
        sa.Column("scan_id", sa.UUID(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(255), nullable=False),
        sa.Column("user_email", sa.String(255), nullable=False),
        sa.Column("user_name", sa.String(255), nullable=False),
        sa.Column("app_name", sa.String(255), nullable=True),
        sa.Column("app_id", sa.String(255), nullable=True),
        sa.Column("scenario_name", sa.String(255), nullable=True),
        sa.Column("status", impactstatus, nullable=False),
        sa.Column("first_detected", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_detected", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_vulnerability_impacts_vulnerability_id", "vulnerability_impacts", ["vulnerability_id"])
    op.create_index("ix_vulnerability_impacts_scan_id", "vulnerability_impacts", ["scan_id"])
    op.create_index("ix_vulnerability_impacts_user_email", "vulnerability_impacts", ["user_email"])
    op.create_index("ix_vulnerability_impacts_status", "vulnerability_impacts", ["status"])
    op.create_index("ix_vulnerability_impacts_vuln_status", "vulnerability_impacts", ["vulnerability_id", "status"])

    # --- assessment_results ---
    op.create_table(
        "assessment_results",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("scan_id", sa.UUID(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("user_id", sa.String(255), nullable=False),
        sa.Column("user_email", sa.String(255), nullable=False),
        sa.Column("app_id", sa.String(255), nullable=False),
        sa.Column("app_name", sa.String(255), nullable=False),
        sa.Column("scenario_id", sa.UUID(), sa.ForeignKey("scenarios.id", ondelete="SET NULL"), nullable=True),
        sa.Column("scenario_name", sa.String(255), nullable=False),
        sa.Column("policy_id", sa.String(255), nullable=True),
        sa.Column("policy_name", sa.String(255), nullable=True),
        sa.Column("rule_id", sa.String(255), nullable=True),
        sa.Column("rule_name", sa.String(255), nullable=True),
        sa.Column("access_decision", accessdecision, nullable=False),
        sa.Column("factor_mode", sa.String(50), nullable=True),
        sa.Column("reauthenticate_in", sa.String(50), nullable=True),
        sa.Column("phishing_resistant", sa.Boolean(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_assessment_results_scan_id", "assessment_results", ["scan_id"])
    op.create_index("ix_assessment_results_user_email", "assessment_results", ["user_email"])
    op.create_index("ix_assessment_results_app_id", "assessment_results", ["app_id"])
    op.create_index("ix_assessment_results_access_decision", "assessment_results", ["access_decision"])
    op.create_index("ix_assessment_results_scan_user", "assessment_results", ["scan_id", "user_id"])
    op.create_index("ix_assessment_results_created_at", "assessment_results", ["created_at"])
    op.create_index("ix_assessment_results_user_email_created_at", "assessment_results", ["user_email", "created_at"])

    # --- posture_findings ---
    op.create_table(
        "posture_findings",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("scan_id", sa.UUID(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("check_category", checkcategory, nullable=False),
        sa.Column("check_name", sa.String(255), nullable=False),
        sa.Column("severity", severity, nullable=False),
        sa.Column("status", findingstatus, nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("description", sa.Text(), nullable=False),
        sa.Column("affected_resources", postgresql.JSONB(), nullable=False),
        sa.Column("remediation_steps", sa.Text(), nullable=False),
        sa.Column("compliance_mappings", postgresql.JSONB(), nullable=True),
        sa.Column("risk_score", sa.Integer(), default=0, nullable=False),
        sa.Column("first_detected", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("last_detected", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("resolved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_posture_findings_scan_id", "posture_findings", ["scan_id"])
    op.create_index("ix_posture_findings_check_category", "posture_findings", ["check_category"])
    op.create_index("ix_posture_findings_severity", "posture_findings", ["severity"])
    op.create_index("ix_posture_findings_status", "posture_findings", ["status"])
    op.create_index("ix_posture_findings_category_status", "posture_findings", ["check_category", "status"])

    # --- jobs ---
    op.create_table(
        "jobs",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("description", sa.Text(), nullable=True),
        sa.Column("is_active", sa.Boolean(), default=True, nullable=False),
        sa.Column("schedule_type", scheduletype, nullable=False),
        sa.Column("cron_expression", sa.String(100), nullable=True),
        sa.Column("interval_seconds", sa.Integer(), nullable=True),
        sa.Column("run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("scan_config", postgresql.JSONB(), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("next_run_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_jobs_is_active", "jobs", ["is_active"])
    op.create_index("ix_jobs_next_run_at", "jobs", ["next_run_at"])
    op.create_index("ix_jobs_schedule_type", "jobs", ["schedule_type"])

    # --- reports ---
    op.create_table(
        "reports",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("scan_id", sa.UUID(), sa.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False),
        sa.Column("report_type", reporttype, nullable=False),
        sa.Column("file_path", sa.String(500), nullable=True),
        sa.Column("content", sa.Text(), nullable=True),
        sa.Column("generated_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_reports_scan_id", "reports", ["scan_id"])
    op.create_index("ix_reports_report_type", "reports", ["report_type"])

    # --- audit_logs ---
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("actor_email", sa.String(255), nullable=False),
        sa.Column("actor_role", sa.String(100), nullable=False),
        sa.Column("action", sa.String(255), nullable=False),
        sa.Column("resource_type", sa.String(100), nullable=False),
        sa.Column("resource_id", sa.String(255), nullable=False),
        sa.Column("details", postgresql.JSONB(), nullable=True),
        sa.Column("ip_address", sa.String(45), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now()),
    )
    op.create_index("ix_audit_logs_actor_email", "audit_logs", ["actor_email"])
    op.create_index("ix_audit_logs_action", "audit_logs", ["action"])
    op.create_index("ix_audit_logs_resource_type", "audit_logs", ["resource_type"])
    op.create_index("ix_audit_logs_created_at", "audit_logs", ["created_at"])

    # --- notification_channels ---
    op.create_table(
        "notification_channels",
        sa.Column("id", sa.UUID(), primary_key=True),
        sa.Column("created_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.func.now(), nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("channel_type", sa.String(50), nullable=False),
        sa.Column("config", postgresql.JSONB(), nullable=False),
        sa.Column("events", postgresql.JSONB(), nullable=False),
        sa.Column("is_active", sa.Boolean(), default=True, nullable=False),
    )


def downgrade() -> None:
    op.drop_table("notification_channels")
    op.drop_table("audit_logs")
    op.drop_table("reports")
    op.drop_table("jobs")
    op.drop_table("posture_findings")
    op.drop_table("assessment_results")
    op.drop_table("vulnerability_impacts")
    op.drop_table("vulnerabilities")
    op.drop_table("scans")
    op.drop_table("scenarios")

    for name in [
        "reporttype", "findingstatus", "checkcategory", "scheduletype",
        "scanstatus", "deviceplatform", "risklevel", "accessdecision",
        "impactstatus", "vulnerabilitystatus", "severity", "vulnerabilitycategory",
    ]:
        postgresql.ENUM(name=name).drop(op.get_bind(), checkfirst=True)
