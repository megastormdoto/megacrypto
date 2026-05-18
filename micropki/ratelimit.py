from __future__ import annotations

import math
import threading
import time
from typing import Callable

from fastapi import Request, Response
from fastapi.responses import JSONResponse


class _Bucket:
    
    __slots__ = ("tokens", "max_tokens", "refill_rate", "last_refill")

    def __init__(self, rate: float, burst: int):
        self.max_tokens = burst
        self.tokens = float(burst)
        self.refill_rate = rate  # tokens per second
        self.last_refill = time.monotonic()

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.max_tokens, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now

    def allow(self) -> bool:
        self._refill()
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def retry_after(self) -> float:
        self._refill()
        if self.tokens >= 1.0:
            return 0.0
        deficit = 1.0 - self.tokens
        return math.ceil(deficit / self.refill_rate) if self.refill_rate > 0 else 1.0


class RateLimiter:
    
    def __init__(self, rate: float, burst: int = 10):
        self.rate = rate
        self.burst = burst
        self._buckets: dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def allow(self, client_ip: str) -> bool:
        with self._lock:
            bucket = self._buckets.get(client_ip)
            if bucket is None:
                bucket = _Bucket(self.rate, self.burst)
                self._buckets[client_ip] = bucket
            return bucket.allow()

    def get_retry_after(self, client_ip: str) -> float:
        with self._lock:
            bucket = self._buckets.get(client_ip)
            if bucket is None:
                return 0.0
            return bucket.retry_after()


def create_rate_limit_middleware(rate: float, burst: int = 10) -> Callable:
    limiter = RateLimiter(rate, burst)

    async def rate_limit_middleware(request: Request, call_next) -> Response:
        client_ip = request.client.host if request.client else "unknown"
        if not limiter.allow(client_ip):
            retry_after = limiter.get_retry_after(client_ip)
            return JSONResponse(
                status_code=429,
                content={"detail": "Too Many Requests"},
                headers={"Retry-After": str(int(retry_after))},
            )
        return await call_next(request)

    return rate_limit_middleware
