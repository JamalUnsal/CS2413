#Owner: Jamal Unsal
import json

from auth_system.audit import AuditLog


def test_audit_log_writes_json_lines(tmp_path):
    log_path = tmp_path / "logs" / "audit.log"
    clock = lambda: 1700000000.0

    audit = AuditLog(log_path, clock=clock)
    audit.record("login_success", "alice", {"mfa": True})
    audit.record("login_failure", "alice", {"reason": "bad_password"})

    lines = log_path.read_text(encoding="utf-8").splitlines()

    assert len(lines) == 2

    first = json.loads(lines[0])
    second = json.loads(lines[1])

    assert first["event"] == "login_success"
    assert first["username"] == "alice"
    assert first["recorded_at"] == 1700000000.0
    assert second["event"] == "login_failure"


def test_audit_log_redacts_sensitive_fields(tmp_path):
    audit = AuditLog(tmp_path / "audit.log")

    audit.record(
        "login_failure",
        "alice",
        {
            "password": "secret-password",
            "otp_code": "123456",
            "session_token": "secret-token",
            "reason": "bad_password",
        },
    )

    content = (tmp_path / "audit.log").read_text(encoding="utf-8")

    assert "secret-password" not in content
    assert "123456" not in content
    assert "secret-token" not in content
    assert "bad_password" in content


def test_audit_log_does_not_raise_when_write_fails(tmp_path):
    # A directory cannot be opened as an append-mode file.
    audit = AuditLog(tmp_path)

    audit.record("login_success", "alice")
