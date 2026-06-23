from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4
import json
import shutil

from jsonschema import Draft202012Validator

from .audit import AuditEntryInput, AuditLog, utc_now_iso
from .crypto import blake3_hex
from .policy import ProductionPolicy, PolicyViolation

ExportType = Literal["audit_log", "baseline_summary", "full_export"]


class ExportPolicyViolation(PolicyViolation):
    """Raised when an export violates Echo Guardian production rules."""


class ExportSchemaError(ValueError):
    """Raised when an export manifest fails schema validation."""


@dataclass(frozen=True)
class ExportRequest:
    export_type: ExportType
    user_confirmed: bool
    requested_by_authority: Literal["user"] = "user"
    redactions_applied: bool = False
    encrypted: bool = False
    recipient: str | None = None


class ExportPackageBuilder:
    """Explicit, user-confirmed local export package builder.

    Exports are never automatic. Every request, successful generation, and failure
    is written to the audit log. The builder copies only known local artifacts and
    records BLAKE3 hashes for every exported file.
    """

    def __init__(self, *, policy: ProductionPolicy, audit_log: AuditLog):
        policy.validate()
        self.policy = policy
        self.audit_log = audit_log

    def create_export(
        self,
        *,
        request: ExportRequest,
        export_dir: str | Path,
        audit_chain_path: str | Path,
        policy_path: str | Path | None = None,
        baseline_path: str | Path | None = None,
        status_path: str | Path | None = None,
        schema_path: str | Path | None = None,
    ) -> dict[str, Any]:
        request_entry = self._record_request(request)
        try:
            self._validate_request(request)
            output_dir = Path(export_dir)
            output_dir.mkdir(parents=True, exist_ok=True)
            included: list[dict[str, Any]] = []

            audit_src = Path(audit_chain_path)
            if not audit_src.exists():
                raise ExportPolicyViolation("audit chain path does not exist")
            included.append(self._copy_and_hash(audit_src, output_dir / "audit_chain.jsonl", "application/jsonl"))

            if policy_path is not None:
                included.append(self._copy_and_hash(Path(policy_path), output_dir / "policy_snapshot.json", "application/json"))
            if baseline_path is not None:
                included.append(self._copy_and_hash(Path(baseline_path), output_dir / "baseline_summary.json", "application/json"))
            if status_path is not None:
                included.append(self._copy_and_hash(Path(status_path), output_dir / "local_status_report.json", "application/json"))

            human_summary = output_dir / "human_readable_summary.md"
            human_summary.write_text(self._human_summary(request, included), encoding="utf-8")
            included.append(self._hash_existing(human_summary, "text/markdown"))

            verification = output_dir / "verification_instructions.md"
            verification.write_text(self._verification_instructions(), encoding="utf-8")
            included.append(self._hash_existing(verification, "text/markdown"))

            range_start, range_end = self._audit_range(audit_src)
            generation_entry = self.audit_log.append(
                AuditEntryInput(
                    event_type="export_generated",
                    severity="normal",
                    authority_context="user_controlled",
                    policy_id=self.policy.policy_id,
                    policy_version=self.policy.policy_version,
                    public_context={
                        "space_id": "export",
                        "private_space": False,
                        "signal_types": [],
                        "plain_language": "Echo Guardian generated a user-confirmed local export package with verification hashes.",
                        "export_type": request.export_type,
                        "automatic_export": False,
                    },
                )
            )
            manifest = {
                "schema_version": "0.2",
                "export_id": str(uuid4()),
                "created_at": utc_now_iso(),
                "created_by_authority": "user",
                "export_type": request.export_type,
                "range_start_sequence": range_start,
                "range_end_sequence": range_end,
                "included_files": included,
                "redactions_applied": request.redactions_applied,
                "encrypted": request.encrypted,
                "user_confirmed": True,
                "automatic_export": False,
                "device_signature": None,
                "audit_ref": generation_entry["audit_entry_id"],
                "request_audit_ref": request_entry["audit_entry_id"],
                "recipient": request.recipient,
            }
            if schema_path is not None:
                validate_export_manifest_schema(manifest, schema_path)
            (output_dir / "export_manifest.json").write_text(
                json.dumps(manifest, sort_keys=True, separators=(",", ":"), ensure_ascii=False), encoding="utf-8"
            )
            return manifest
        except Exception as exc:
            self.audit_log.append(
                AuditEntryInput(
                    event_type="export_failed",
                    severity="concerning",
                    authority_context="user_controlled",
                    policy_id=self.policy.policy_id,
                    policy_version=self.policy.policy_version,
                    public_context={
                        "space_id": "export",
                        "private_space": False,
                        "signal_types": [],
                        "plain_language": "Echo Guardian could not complete the requested local export.",
                        "reason": str(exc),
                        "automatic_export": False,
                    },
                )
            )
            raise

    def _validate_request(self, request: ExportRequest) -> None:
        if request.requested_by_authority != "user":
            raise ExportPolicyViolation("v0.2 exports must be requested by the user")
        if request.user_confirmed is not True:
            raise ExportPolicyViolation("export requires explicit user confirmation")
        export_permissions = self.policy.data.get("export_permissions", {})
        if export_permissions and export_permissions.get("automatic_export") is not False:
            raise ExportPolicyViolation("automatic export must be disabled")
        if self.policy.data.get("export_requires_explicit_confirmation") is not True:
            raise ExportPolicyViolation("policy must require explicit export confirmation")

    def _record_request(self, request: ExportRequest) -> dict[str, Any]:
        if request.user_confirmed is not True:
            # Denied requests are still auditable.
            return self.audit_log.append(
                AuditEntryInput(
                    event_type="export_request_denied",
                    severity="concerning",
                    authority_context="user_controlled",
                    policy_id=self.policy.policy_id,
                    policy_version=self.policy.policy_version,
                    public_context={
                        "space_id": "export",
                        "private_space": False,
                        "signal_types": [],
                        "plain_language": "Echo Guardian blocked an export because the user did not explicitly confirm it.",
                        "automatic_export": False,
                    },
                )
            )
        return self.audit_log.append(
            AuditEntryInput(
                event_type="export_requested",
                severity="normal",
                authority_context="user_controlled",
                policy_id=self.policy.policy_id,
                policy_version=self.policy.policy_version,
                public_context={
                    "space_id": "export",
                    "private_space": False,
                    "signal_types": [],
                    "plain_language": "The user explicitly requested a local Echo Guardian export package.",
                    "export_type": request.export_type,
                    "automatic_export": False,
                },
            )
        )

    @staticmethod
    def _copy_and_hash(src: Path, dst: Path, content_type: str) -> dict[str, str]:
        if not src.exists():
            raise ExportPolicyViolation(f"export source does not exist: {src}")
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(src, dst)
        return ExportPackageBuilder._hash_existing(dst, content_type)

    @staticmethod
    def _hash_existing(path: Path, content_type: str) -> dict[str, str]:
        return {
            "path": path.name,
            "content_type": content_type,
            "hash": blake3_hex(path.read_bytes()),
        }

    @staticmethod
    def _audit_range(path: Path) -> tuple[int, int]:
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if not lines:
            return (0, 0)
        return (int(lines[0]["sequence_number"]), int(lines[-1]["sequence_number"]))

    @staticmethod
    def _human_summary(request: ExportRequest, included: list[dict[str, Any]]) -> str:
        names = ", ".join(item["path"] for item in included)
        return (
            "# Echo Guardian Local Export\n\n"
            "This export was explicitly requested by the user. No automatic export was used.\n\n"
            f"Export type: {request.export_type}\n\n"
            f"Included files: {names}\n"
        )

    @staticmethod
    def _verification_instructions() -> str:
        return (
            "# Verification Instructions\n\n"
            "1. Read export_manifest.json.\n"
            "2. Recompute BLAKE3 for each included file.\n"
            "3. Compare each digest with the manifest.\n"
            "4. Verify audit_chain.jsonl with tools/verify_audit.py.\n"
            "5. Treat any mismatch as a failed integrity check.\n"
        )


def validate_export_manifest_schema(data: dict[str, Any], schema_path: str | Path) -> None:
    schema = json.loads(Path(schema_path).read_text(encoding="utf-8"))
    validator = Draft202012Validator(schema)
    errors = sorted(validator.iter_errors(data), key=lambda e: list(e.path))
    if errors:
        first = errors[0]
        path = "/".join(str(p) for p in first.path) or "<root>"
        raise ExportSchemaError(f"export manifest schema validation failed at {path}: {first.message}")
