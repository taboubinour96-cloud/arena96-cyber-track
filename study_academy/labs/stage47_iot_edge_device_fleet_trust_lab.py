"""
Stage 47 Defensive Lab — IoT/Edge Fleet Trust: Identity, Firmware Floor & Quarantine
=======================================================================================
1. DeviceRegistry: a device joins the fleet only with a registered identity
   fingerprint; unknown hardware is quarantined by default.
2. FleetHealthPolicy: firmware below the security floor or stale heartbeats
   move a device out of production trust until remediated.
"""

from __future__ import annotations

from typing import Dict, Tuple


class FleetViolation(Exception):
    """Raised when a fleet-trust rule is violated."""


def _vtuple(text: str) -> Tuple[int, ...]:
    return tuple(int(p) for p in text.split(".") if p.isdigit())


class IoTDeviceFleet:
    def __init__(self, min_firmware: str) -> None:
        self._min_fw = min_firmware
        self._devices: Dict[str, Dict[str, object]] = {}

    def enroll(self, device_id: str, identity_fingerprint: str, firmware: str) -> Dict[str, object]:
        self._devices[device_id] = {"fingerprint": identity_fingerprint, "firmware": firmware}
        return {"enrolled": True, "state": "DEVICE_ENROLLED", "device_id": device_id}

    def admit(self, device_id: str, identity_fingerprint: str, firmware: str, heartbeat_age_seconds: int) -> Tuple[bool, str]:
        record = self._devices.get(device_id)
        if record is None or record["fingerprint"] != identity_fingerprint:
            return False, "DEVICE_QUARANTINED_UNKNOWN_IDENTITY"
        if _vtuple(firmware) < _vtuple(self._min_fw):
            return False, "DEVICE_QUARANTINED_FIRMWARE_BELOW_FLOOR"
        if heartbeat_age_seconds > 3600:
            return False, "DEVICE_QUARANTINED_STALE_HEARTBEAT"
        return True, "DEVICE_ADMITTED_TO_FLEET"
