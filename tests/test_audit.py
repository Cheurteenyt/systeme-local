import hashlib
import json
from pathlib import Path

from systeme_local_gateway.audit import append_audit


def _expected_hash(record: dict) -> str:
    unsigned = {key: value for key, value in record.items() if key != "sha256"}
    encoded = json.dumps(
        unsigned,
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def test_append_audit_writes_verifiable_json_lines(tmp_path: Path) -> None:
    log_path = tmp_path / "audit.jsonl"

    first_id = append_audit(
        log_path,
        {"task_id": "task-12345678", "status": "completed"},
    )
    second_id = append_audit(
        log_path,
        {"task_id": "task-87654321", "status": "denied"},
    )

    records = [
        json.loads(line)
        for line in log_path.read_text(encoding="utf-8").splitlines()
    ]

    assert len(records) == 2
    assert records[0]["audit_id"] == first_id
    assert records[1]["audit_id"] == second_id
    assert first_id != second_id
