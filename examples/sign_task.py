import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

secret = os.environ.get("SLG_SHARED_SECRET", "replace-with-at-least-32-random-characters")
now = datetime.now(UTC)
task = {
    "version": "1",
    "task_id": str(uuid4()),
    "issued_at": now.isoformat(),
    "expires_at": (now + timedelta(minutes=5)).isoformat(),
    "agent": {"provider": "z.ai", "model": "glm", "session_id": "demo"},
    "capability": "workspace.list",
    "arguments": {"path": "."},
    "nonce": secrets.token_urlsafe(24),
}
payload = json.dumps(task, sort_keys=True, separators=(",", ":")).encode("utf-8")
digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
task["signature"] = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
print(json.dumps(task, indent=2))
