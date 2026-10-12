"""Short-lived server-side state: pending logins, codes, refresh tokens.

In memory, per process. A restart forgets every outstanding code and refresh
token, which is the safe direction to fail in. Keycloak replaces all of this at
step 18, so nothing here is built to survive a restart or run as two replicas.

`take` and `peek` are separate methods on purpose. `take` is single use: the
entry is gone after the first read. `peek` leaves it in place. Whether a value
can be redeemed twice is therefore visible at the call site, not buried in
the store's configuration.
"""

from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta


def utc_now() -> datetime:
    return datetime.now(UTC)


@dataclass
class _Entry[V]:
    value: V
    expires_at: datetime


class ExpiringStore[V]:
    def __init__(self, ttl: timedelta, clock: Callable[[], datetime] = utc_now) -> None:
        self._ttl = ttl
        self._clock = clock
        self._entries: dict[str, _Entry[V]] = {}

    def put(self, key: str, value: V) -> None:
        self._purge()
        self._entries[key] = _Entry(value, self._clock() + self._ttl)

    def take(self, key: str) -> V | None:
        """Remove and return the entry. A second call for the same key gets None."""
        entry = self._entries.pop(key, None)
        if entry is None or entry.expires_at <= self._clock():
            return None
        return entry.value

    def peek(self, key: str) -> V | None:
        """Return the entry and leave it in place."""
        entry = self._entries.get(key)
        if entry is None or entry.expires_at <= self._clock():
            return None
        return entry.value

    def discard(self, key: str) -> None:
        self._entries.pop(key, None)

    def _purge(self) -> None:
        now = self._clock()
        for key in [k for k, e in self._entries.items() if e.expires_at <= now]:
            del self._entries[key]
