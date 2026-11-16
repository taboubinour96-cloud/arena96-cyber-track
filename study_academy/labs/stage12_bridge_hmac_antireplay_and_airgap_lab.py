"""
Stage 12 Defensive Lab — Algorithmic Bridge Security, Constant-Time HMAC Anti-Replay & Demo/Live Air-Gap
========================================================================================================
1. ConstantTimeBridgeWebhookGuard:
   - Defends bridge webhook receivers using HMAC-SHA256 + +-30s timestamp freshness + bounded nonce cache.
   - Uses hmac.compare_digest to eliminate timing side-channels.
2. DemoOnlyAirGapGuard:
   - Hard startup/runtime enforcement ensuring zero connection to live trading domains and zero withdrawal surface.
3. IdempotentSignalCircuitBreaker:
   - Prevents duplicate signal processing (SHA-256 idempotency) and halts runaway echo loops via sliding-window breaker.
"""

from __future__ import annotations

import hashlib
import hmac
from collections import deque
from typing import Deque, Dict, Set, Tuple
from urllib.parse import urlparse


class ConstantTimeBridgeWebhookGuard:
    def __init__(self, shared_secret: bytes, max_skew_seconds: int = 30, max_nonce_cache: int = 2048):
        if not shared_secret or len(shared_secret) < 16:
            raise ValueError("Bridge secret must be >= 16 bytes from secure runtime env")
        self._secret = bytes(shared_secret)
        self.max_skew_seconds = max_skew_seconds
        self.max_nonce_cache = max_nonce_cache
        self._seen_nonces: Set[str] = set()
        self._nonce_order: Deque[str] = deque()

    def sign_payload(self, timestamp: int, nonce: str, raw_body: str) -> str:
        msg = f"{timestamp}.{nonce}.{raw_body}".encode("utf-8")
        return hmac.new(self._secret, msg, hashlib.sha256).hexdigest()

    def verify_request(self, timestamp: int, nonce: str, raw_body: str, provided_sig: str, now_ts: int) -> Tuple[bool, str]:
        if abs(now_ts - timestamp) > self.max_skew_seconds:
            return False, "EXPIRED_TIMESTAMP_WINDOW"
        if not nonce or nonce in self._seen_nonces:
            return False, "REPLAY_NONCE_DETECTED"
        expected_sig = self.sign_payload(timestamp, nonce, raw_body)
        if not hmac.compare_digest(expected_sig, provided_sig):
            return False, "INVALID_HMAC_SIGNATURE"

        if len(self._nonce_order) >= self.max_nonce_cache:
            oldest = self._nonce_order.popleft()
            self._seen_nonces.discard(oldest)
        self._nonce_order.append(nonce)
        self._seen_nonces.add(nonce)
        return True, "VERIFIED_OK"


class DemoOnlyAirGapGuard:
    ALLOWED_DEMO_HOSTS = {
        "testnet.binance.vision",
        "testnet.binancefuture.com",
        "api-testnet.bybit.com",
        "demo.tradovateapi.com",
        "localhost",
        "127.0.0.1",
    }
    FORBIDDEN_PATH_TOKENS = ("withdraw", "capital/withdraw", "asset/transfer", "sub-account/transfer", "kyc")

    @classmethod
    def validate_demo_endpoint(cls, url: str) -> Dict[str, object]:
        parsed = urlparse(url)
        host = (parsed.hostname or "").lower()
        path_lower = (parsed.path or "").lower()

        if any(tok in path_lower for tok in cls.FORBIDDEN_PATH_TOKENS):
            raise PermissionError(f"RULE4_WITHDRAWAL_PROHIBITED: المسار '{parsed.path}' محظور قطعياً")
        if host not in cls.ALLOWED_DEMO_HOSTS:
            raise PermissionError(f"RULE4_LIVE_ENDPOINT_PROHIBITED: النطاق '{host}' خارج قائمة بيئات الديمو المسموحة")
        return {"allowed": True, "host": host, "mode": "DEMO_SANDBOX_ONLY"}


class IdempotentSignalCircuitBreaker:
    def __init__(self, max_signals_per_window: int = 5, window_seconds: int = 60):
        self.max_signals_per_window = max_signals_per_window
        self.window_seconds = window_seconds
        self._processed_ids: Set[str] = set()
        self._recent_timestamps: Deque[int] = deque()
        self.tripped: bool = False

    def accept_signal(self, signal_id: str, symbol: str, now_ts: int) -> Tuple[bool, str]:
        if self.tripped:
            return False, "CIRCUIT_BREAKER_OPEN"
        idem_key = hashlib.sha256(f"{signal_id}:{symbol}".encode("utf-8")).hexdigest()
        if idem_key in self._processed_ids:
            return False, "DUPLICATE_SIGNAL_IDEMPOTENT_SKIP"

        while self._recent_timestamps and (now_ts - self._recent_timestamps[0]) > self.window_seconds:
            self._recent_timestamps.popleft()

        if len(self._recent_timestamps) >= self.max_signals_per_window:
            self.tripped = True
            return False, "CIRCUIT_BREAKER_TRIPPED_RUNAWAY_LOOP"

        self._recent_timestamps.append(now_ts)
        self._processed_ids.add(idem_key)
        return True, "ACCEPTED_DEMO_SIGNAL"
