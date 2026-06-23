from echo_guardian_core.audit import AuditEntryInput, AuditLog


def test_audit_append_and_verify(tmp_path):
    log = AuditLog.open(tmp_path / "audit.jsonl")
    log.append(AuditEntryInput(
        event_type="policy_loaded",
        severity="normal",
        authority_context="system_internal",
        public_context={
            "space_id": "system",
            "private_space": False,
            "signal_types": [],
            "plain_language": "Echo Guardian loaded the local production policy."
        },
    ))
    log.append(AuditEntryInput(
        event_type="monitoring_started",
        severity="normal",
        authority_context="user_controlled",
        public_context={
            "space_id": "living_room",
            "private_space": False,
            "signal_types": ["motion"],
            "plain_language": "Echo Guardian started monitoring the living room."
        },
    ))
    assert log.verify() == []


def test_audit_tamper_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog.open(path)
    log.append(AuditEntryInput(
        event_type="policy_loaded",
        severity="normal",
        authority_context="system_internal",
        public_context={"space_id": "system", "private_space": False, "signal_types": [], "plain_language": "Policy loaded."},
    ))
    text = path.read_text()
    path.write_text(text.replace("Policy loaded.", "Policy changed."))
    tampered = AuditLog.open(path)
    assert tampered.verify()


def test_audit_truncation_detected_by_checkpoint(tmp_path):
    from echo_guardian_core.signing import Ed25519KeyPair

    path = tmp_path / "audit.jsonl"
    log = AuditLog.open(path)
    for i in range(3):
        log.append(AuditEntryInput(
            event_type="baseline_updated",
            severity="normal",
            authority_context="system_internal",
            public_context={
                "space_id": "living_room",
                "private_space": False,
                "signal_types": ["motion"],
                "plain_language": f"Baseline update {i}."
            },
        ))
    checkpoint = log.create_checkpoint(Ed25519KeyPair.generate())
    assert AuditLog.verify_checkpoint(checkpoint) == []

    truncated_lines = path.read_text().splitlines()[:-1]
    path.write_text("\n".join(truncated_lines) + "\n")
    truncated = AuditLog.open(path)
    assert truncated.verify() == []  # internally coherent but older state
    assert checkpoint["latest_sequence_number"] != len(truncated.entries)
    assert checkpoint["latest_entry_hash"] != truncated.entries[-1]["current_entry_hash"]


def test_checkpoint_signature_tamper_detected(tmp_path):
    from echo_guardian_core.signing import Ed25519KeyPair

    log = AuditLog.open(tmp_path / "audit.jsonl")
    log.append(AuditEntryInput(
        event_type="monitoring_started",
        severity="normal",
        authority_context="user_controlled",
        public_context={"space_id": "living_room", "private_space": False, "signal_types": ["motion"], "plain_language": "Monitoring started."},
    ))
    checkpoint = log.create_checkpoint(Ed25519KeyPair.generate())
    assert AuditLog.verify_checkpoint(checkpoint) == []
    checkpoint["latest_sequence_number"] = 999
    assert AuditLog.verify_checkpoint(checkpoint)


def test_reordered_entries_detected(tmp_path):
    path = tmp_path / "audit.jsonl"
    log = AuditLog.open(path)
    for event_type in ["policy_loaded", "monitoring_started"]:
        log.append(AuditEntryInput(
            event_type=event_type,
            severity="normal",
            authority_context="system_internal",
            public_context={"space_id": "system", "private_space": False, "signal_types": [], "plain_language": event_type},
        ))
    lines = path.read_text().splitlines()
    path.write_text(lines[1] + "\n" + lines[0] + "\n")
    reordered = AuditLog.open(path)
    assert reordered.verify()
