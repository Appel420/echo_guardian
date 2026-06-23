import json
from pathlib import Path

import pytest

from echo_guardian_core.audit import AuditEntryInput, AuditLog
from echo_guardian_core.baseline import BaselineProfile
from echo_guardian_core.crypto import blake3_hex
from echo_guardian_core.export import ExportPackageBuilder, ExportPolicyViolation, ExportRequest, validate_export_manifest_schema
from echo_guardian_core.policy import ProductionPolicy
from echo_guardian_core.storage import LocalEncryptedStore, LocalStoragePaths


def _policy() -> ProductionPolicy:
    data = {
        "schema_version": "0.2",
        "policy_id": "production-local-v0.2-test",
        "policy_version": "0.2",
        "deployment_mode": "personal",
        "issuing_authority": "user",
        "monitoring_enabled": True,
        "private_space_monitoring_enabled": False,
        "bathroom_monitoring_enabled": False,
        "bedroom_monitoring_enabled": False,
        "real_sensor_ingestion_enabled": True,
        "local_baseline_learning_enabled": True,
        "local_audit_logging_enabled": True,
        "real_contact_notification_enabled": False,
        "requires_contact_test_before_live_alerts": True,
        "authorized_contacts_configured": False,
        "successful_test_alert_completed": False,
        "emergency_services_enabled": False,
        "cloud_dependency_for_core_loop": False,
        "silent_telemetry_enabled": False,
        "diagnostic_upload_enabled": False,
        "raw_sensor_retention": "not_retained",
        "export_requires_explicit_confirmation": True,
        "export_permissions": {"user_export": True, "automatic_export": False},
        "user_visible_labels": {"policy_summary": "Test policy", "monitoring_summary": "Test monitoring"},
    }
    return ProductionPolicy(data)


def _audit(path: Path) -> AuditLog:
    log = AuditLog.open(path)
    log.append(AuditEntryInput(
        event_type="policy_loaded",
        severity="normal",
        authority_context="system_internal",
        public_context={"space_id": "system", "private_space": False, "signal_types": [], "plain_language": "Policy loaded."},
    ))
    log.append(AuditEntryInput(
        event_type="status_checked",
        severity="normal",
        authority_context="user_controlled",
        public_context={"space_id": "interface", "private_space": False, "signal_types": [], "plain_language": "Status checked."},
    ))
    return log


def test_storage_paths_are_separate(tmp_path):
    paths = LocalStoragePaths.create(tmp_path / "store")
    paths.assert_separate()
    assert paths.operational.exists()
    assert paths.audit.exists()
    assert paths.export.exists()


def test_encrypted_store_roundtrip_and_not_plaintext(tmp_path):
    store = LocalEncryptedStore(store_dir=tmp_path / "operational", key_path=tmp_path / "keys" / "store.key")
    source = {"schema_version": "0.2", "plain_language": "secret local operational state"}
    path = store.put_json("state.enc.json", source)
    text = path.read_text()
    assert "secret local operational state" not in text
    assert LocalEncryptedStore.is_encrypted_file(path)
    assert store.get_json("state.enc.json") == source


def test_export_requires_user_confirmation(tmp_path):
    policy = _policy()
    log = _audit(tmp_path / "audit.jsonl")
    builder = ExportPackageBuilder(policy=policy, audit_log=log)
    with pytest.raises(ExportPolicyViolation):
        builder.create_export(
            request=ExportRequest(export_type="audit_log", user_confirmed=False),
            export_dir=tmp_path / "export",
            audit_chain_path=tmp_path / "audit.jsonl",
        )
    assert any(e["event_type"] == "export_request_denied" for e in log.entries)
    assert any(e["event_type"] == "export_failed" for e in log.entries)


def test_export_package_manifest_and_hashes(tmp_path):
    policy = _policy()
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy.data, sort_keys=True), encoding="utf-8")
    baseline_path = tmp_path / "baseline.json"
    baseline = BaselineProfile.create().to_summary()
    baseline_path.write_text(json.dumps(baseline, sort_keys=True), encoding="utf-8")
    status_path = tmp_path / "status.json"
    status_path.write_text(json.dumps({"schema_version": "0.2", "status": "ok"}, sort_keys=True), encoding="utf-8")

    log = _audit(tmp_path / "audit.jsonl")
    builder = ExportPackageBuilder(policy=policy, audit_log=log)
    manifest = builder.create_export(
        request=ExportRequest(export_type="full_export", user_confirmed=True, encrypted=False),
        export_dir=tmp_path / "export",
        audit_chain_path=tmp_path / "audit.jsonl",
        policy_path=policy_path,
        baseline_path=baseline_path,
        status_path=status_path,
        schema_path=Path("schemas/export-manifest.schema.json"),
    )
    validate_export_manifest_schema(manifest, Path("schemas/export-manifest.schema.json"))
    assert manifest["automatic_export"] is False
    assert manifest["user_confirmed"] is True
    assert any(e["event_type"] == "export_requested" for e in log.entries)
    assert any(e["event_type"] == "export_generated" for e in log.entries)
    for item in manifest["included_files"]:
        exported = tmp_path / "export" / item["path"]
        assert exported.exists()
        assert blake3_hex(exported.read_bytes()) == item["hash"]
    assert (tmp_path / "export" / "export_manifest.json").exists()


def test_export_fails_for_missing_audit_chain_and_audits_failure(tmp_path):
    policy = _policy()
    log = AuditLog.open(tmp_path / "audit.jsonl")
    builder = ExportPackageBuilder(policy=policy, audit_log=log)
    with pytest.raises(ExportPolicyViolation):
        builder.create_export(
            request=ExportRequest(export_type="audit_log", user_confirmed=True),
            export_dir=tmp_path / "export",
            audit_chain_path=tmp_path / "missing.jsonl",
        )
    assert any(e["event_type"] == "export_failed" for e in log.entries)
