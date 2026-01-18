import uuid
import time
from typing import Optional
import hashlib


class ResponseCache:
    """
    Session-scoped in-memory cache for LLM responses.

    - Cache is isolated per instance via UUID session ID
    - Entries expire after TTL (default 1 hour)
    - Cache is OFF by default in scanner — opt in with enable_cache=True
    - Use only within a single scan session, never persist across scans
    """

    def __init__(self, ttl_seconds: int = 3600):
        self._cache: dict = {}
        self._timestamps: dict = {}
        self.ttl = ttl_seconds
        # UUID ensures no collision even when two instances are created
        # in the same millisecond (unlike int(time.time() * 1000))
        self.session_id = str(uuid.uuid4())

    def _generate_key(self, prompt: str, model: str) -> str:
        content = f"{self.session_id}:{model}:{prompt}"
        return hashlib.md5(content.encode()).hexdigest()

    def get(self, prompt: str, model: str) -> Optional[str]:
        key = self._generate_key(prompt, model)
        if key in self._timestamps:
            if time.time() - self._timestamps[key] > self.ttl:
                del self._cache[key]
                del self._timestamps[key]
                return None
        return self._cache.get(key)

    def set(self, prompt: str, model: str, response: str):
        key = self._generate_key(prompt, model)
        self._cache[key] = response
        self._timestamps[key] = time.time()

    def clear(self):
        self._cache.clear()
        self._timestamps.clear()

    def size(self) -> int:
        return len(self._cache)
