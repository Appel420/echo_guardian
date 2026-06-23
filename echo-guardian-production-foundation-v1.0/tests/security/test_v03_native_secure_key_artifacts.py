from pathlib import Path

from echo_guardian_core.delivery.provider_adapter import LocalOutboxDeliveryProvider, MinimalDisclosureAlert
from echo_guardian_core.platform.native_sensor_adapters import android_adapter_plan, ios_adapter_plan
from echo_guardian_core.security.device_keys import recommended_device_key_capability
from echo_guardian_core.security.release_artifacts import missing_required_artifacts


def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


def test_v03_required_artifacts_exist():
    assert missing_required_artifacts(repo_root()) == []


def test_native_sensor_adapter_plans_preserve_product_laws():
    for plan in (ios_adapter_plan(), android_adapter_plan()):
        assert plan.production_laws["no_raw_sensor_retention_by_default"] is True
        assert plan.production_laws["no_private_space_by_default"] is True
        assert plan.production_laws["permission_changes_are_audited"] is True
        for capability in plan.capabilities:
            assert capability.raw_retention_allowed is False
            assert capability.private_space_allowed_by_default is False


def test_device_key_profiles_do_not_overclaim_secure_enclave_for_all_primitives():
    ios = recommended_device_key_capability("ios")
    assert "actually supported" in ios.notes
    assert ios.protection in {"keychain", "secure_enclave"}
    assert "ml_kem" in ios.pqc_profile
    portable = recommended_device_key_capability("portable")
    assert portable.protection == "software_protected"


def test_delivery_provider_blocks_emergency_services_by_default():
    provider = LocalOutboxDeliveryProvider()
    result = provider.send(
        {"display_name": "Test Contact"},
        MinimalDisclosureAlert(
            severity="severe",
            reason="No response after confirmation prompt.",
            location_context="Home - living room",
            recommended_action="Please check on the user.",
            emergency_services_used=True,
        ),
    )
    assert result.status == "blocked"
    assert result.audit_required is True


def test_delivery_provider_keeps_payload_minimal():
    provider = LocalOutboxDeliveryProvider()
    alert = MinimalDisclosureAlert(
        severity="severe",
        reason="No response after confirmation prompt.",
        location_context="Home - living room",
        recommended_action="Please check on the user.",
    )
    result = provider.send({"display_name": "Test Contact", "authorized": "true"}, alert)
    assert result.status == "attempted"
    assert alert.sensitive_details_included is False
    assert alert.emergency_services_used is False
