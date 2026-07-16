import hashlib
import json
import threading
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

_LOCK = threading.Lock()


def append_audit(log_path: Path, event: dict) -> str:
    audit_id = str(uuid4())
    record = {
        "audit_id": audit_id,
        "timestamp": datetime.now(UTC).isoformat(),
        **event,
    }
    encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)
    record["sha256"] = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with _LOCK, log_path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
    return audit_id
