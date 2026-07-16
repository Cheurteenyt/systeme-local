import base64
import hashlib
import hmac
import json
import threading
from collections import deque
from datetime import UTC, datetime

from .models import TaskEnvelope


def canonical_payload(task: TaskEnvelope) -> bytes:
    data = task.model_dump(mode="json", exclude={"signature"})
    return json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")


class ReplayGuard:
    """Bounded in-memory nonce cache for the prototype.

    Production deployments should persist this state or use a transactional relay store.
    """

    def __init__(self, max_entries: int = 10_000):
        self._seen: set[str] = set()
        self._order: deque[str] = deque()
        self._max_entries = max_entries
        self._lock = threading.Lock()

    def check_and_mark(self, nonce: str) -> None:
        with self._lock:
            if nonce in self._seen:
                raise ValueError("replayed task nonce")
            self._seen.add(nonce)
            self._order.append(nonce)
            while len(self._order) > self._max_entries:
                oldest = self._order.popleft()
                self._seen.discard(oldest)


def verify_task(
    task: TaskEnvelope,
    secret: str,
    *,
    replay_guard: ReplayGuard | None = None,
    max_clock_skew_seconds: int = 60,
) -> None:
    now = datetime.now(UTC)
    if task.expires_at <= now:
        raise ValueError("task expired")
    if task.issued_at.timestamp() - now.timestamp() > max_clock_skew_seconds:
        raise ValueError("task issued in the future")

    digest = hmac.new(secret.encode("utf-8"), canonical_payload(task), hashlib.sha256).digest()
    expected = base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")
    if not hmac.compare_digest(expected, task.signature):
        raise ValueError("invalid task signature")

    if replay_guard is not None:
        replay_guard.check_and_mark(task.nonce)
