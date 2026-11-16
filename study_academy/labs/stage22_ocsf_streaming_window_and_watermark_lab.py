"""
Stage 22 Defensive Lab — Telemetry Normalization, Streaming Windows & Watermarks
==================================================================================
1. TelemetryNormalizerOCSF:
   - Maps heterogeneous raw cloud/endpoint events into one OCSF-style unified
     schema; unknown/missing mappings are rejected (schema-first, fail-closed).
2. StreamingWindowDetector:
   - Event-time tumbling windows with exactly-once deduplication by event_id,
     a watermark that drops (and counts) excessively late events, and
     threshold alerting per window/principal (e.g. brute-force burst).
"""

from __future__ import annotations

import hashlib
import json
from typing import Dict, List, Tuple


class DataEngineeringViolation(Exception):
    """Raised when a telemetry data-engineering rule is violated."""


class TelemetryNormalizerOCSF:
    _ACTION_MAP = {
        ("cloud", "DescribeInstances"): ("api_activity", "read"),
        ("cloud", "SetPublic"): ("storage_activity", "expose"),
        ("endpoint", "ProcessCreate"): ("process_activity", "launch"),
        ("endpoint", "NetworkConnect"): ("network_activity", "connect"),
    }

    def normalize(self, raw: Dict[str, object]) -> Dict[str, object]:
        source = str(raw.get("source", ""))
        action = str(raw.get("action", ""))
        mapped = self._ACTION_MAP.get((source, action))
        if mapped is None:
            raise DataEngineeringViolation(f"UNMAPPED_EVENT_NO_SCHEMA_{source}_{action}")
        for field in ("ts", "principal", "resource"):
            if field not in raw:
                raise DataEngineeringViolation(f"MISSING_REQUIRED_FIELD_{field.upper()}")
        category, activity = mapped
        event = {
            "category": category,
            "activity": activity,
            "time": int(raw["ts"]),  # type: ignore[arg-type]
            "actor": str(raw["principal"]),
            "resource": str(raw["resource"]),
            "severity": str(raw.get("severity", "informational")),
            "source": source,
        }
        event["event_id"] = str(raw.get("event_id") or hashlib.sha256(
            json.dumps(event, sort_keys=True).encode()
        ).hexdigest()[:24])
        return event


class StreamingWindowDetector:
    def __init__(self, window_seconds: int = 60, lateness_seconds: int = 30, threshold: int = 5) -> None:
        self.window = window_seconds
        self.lateness = lateness_seconds
        self.threshold = threshold
        self._seen_ids: set = set()
        self._max_event_time = -1
        self.dropped_late = 0
        self.duplicates = 0
        self._buckets: Dict[Tuple[int, str, str], int] = {}

    def ingest(self, event: Dict[str, object]) -> str:
        eid = str(event["event_id"])
        if eid in self._seen_ids:
            self.duplicates += 1
            return "DUPLICATE_DROPPED_EXACTLY_ONCE"
        self._seen_ids.add(eid)
        ts = int(event["time"])  # type: ignore[arg-type]
        watermark = self._max_event_time - self.lateness
        if self._max_event_time >= 0 and ts < watermark:
            self.dropped_late += 1
            return "LATE_EVENT_DROPPED_BY_WATERMARK"
        self._max_event_time = max(self._max_event_time, ts)
        bucket = (ts // self.window, str(event["actor"]), str(event["category"]))
        self._buckets[bucket] = self._buckets.get(bucket, 0) + 1
        return "INGESTED"

    def alerts(self) -> List[Dict[str, object]]:
        out = []
        for (window_start, actor, category), count in sorted(self._buckets.items()):
            if count >= self.threshold:
                out.append({
                    "window_start_ts": window_start * self.window,
                    "actor": actor,
                    "category": category,
                    "count": count,
                    "rule": "WINDOW_THRESHOLD_EXCEEDED",
                })
        return out

    def stats(self) -> Dict[str, object]:
        return {
            "unique_events": len(self._seen_ids),
            "duplicates_dropped": self.duplicates,
            "late_dropped": self.dropped_late,
            "watermark_ts": self._max_event_time - self.lateness if self._max_event_time >= 0 else None,
        }
