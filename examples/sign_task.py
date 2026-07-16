import base64
import hashlib
import hmac
import json
import os
import secrets
from datetime import UTC, datetime, timedelta
from uuid import uuid4

from systeme_local_gateway.auth import canonical_payload
from systeme_local_gateway.models import AgentIdentity, TaskEnvelope

secret = os.environ.get("SLG_SHARED_SECRET", "replace-with-at-least-32-random-characters")
now = datetime.now(UTC)
task = TaskEnvelope(
    version="1",
    task_id=os.environ.get("SLG_TASK_ID", str(uuid4())),
    issued_at=now,
    expires_at=now + timedelta(minutes=5),
    agent=AgentIdentity(provider="z.ai", model="glm", session_id="demo"),
    capability=os.environ.get("SLG_TASK_CAPABILITY", "workspace.list"),
    arguments=json.loads(os.environ.get("SLG_TASK_ARGUMENTS_JSON", '{"path":"."}')),
    approval_id=os.environ.get("SLG_APPROVAL_ID"),
    nonce=secrets.token_urlsafe(24),
    signature="x" * 43,
)
payload = canonical_payload(task)
digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).digest()
task.signature = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")

output = json.loads(payload)
output["signature"] = task.signature
print(json.dumps(output, indent=2))
