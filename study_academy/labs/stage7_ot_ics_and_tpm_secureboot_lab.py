"""
مختبر المرحلة 7: أمن الأنظمة الصناعية (OT Modbus TCP DPI) والمحاكاة التشفيرية لشريحة TPM 2.0
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from typing import Any, Dict, List, Set

MODBUS_READ_CODES = {0x01, 0x02, 0x03, 0x04}
MODBUS_WRITE_CODES = {0x05, 0x06, 0x0F, 0x10}


class ModbusTCPDeepPacketGuard:
    """Inspects binary Modbus TCP MBAP + PDU frames (IEC 62443 Conduit Firewall)."""

    def __init__(self, authorized_engineering_ips: Set[str], maintenance_window_open: bool = False):
        self.authorized_engineering_ips = set(authorized_engineering_ips)
        self.maintenance_window_open = maintenance_window_open

    def inspect_frame(self, src_ip: str, frame: bytes) -> Dict[str, Any]:
        # MBAP Header (7 bytes): TransactionID(2), ProtocolID(2 == 0), Length(2), UnitID(1) + FunctionCode(1)
        if len(frame) < 8:
            return {"allowed": False, "reason": "MALFORMED_MBAP_HEADER"}
        tx_id, proto_id, length, unit_id, func_code = struct.unpack(">HHHBB", frame[:8])
        if proto_id != 0:
            return {"allowed": False, "reason": "INVALID_MODBUS_PROTOCOL_ID"}

        if func_code in MODBUS_READ_CODES:
            return {"allowed": True, "action": "READ_PERMITTED", "function_code": func_code, "unit_id": unit_id}

        if func_code in MODBUS_WRITE_CODES:
            if not self.maintenance_window_open:
                return {"allowed": False, "reason": "WRITE_BLOCKED_OUTSIDE_MAINTENANCE_WINDOW", "function_code": func_code}
            if src_ip not in self.authorized_engineering_ips:
                return {"allowed": False, "reason": "UNAUTHORIZED_SOURCE_FOR_PLC_WRITE", "function_code": func_code}
            return {"allowed": True, "action": "AUTHORIZED_MAINTENANCE_WRITE", "function_code": func_code}

        return {"allowed": False, "reason": "DISALLOWED_DIAGNOSTIC_OR_UNKNOWN_FC", "function_code": func_code}


class TPM2MeasuredBootSimulator:
    """Models TPM 2.0 PCR_Extend (`SHA256(old_pcr || SHA256(measurement))`) and signed remote attestation."""

    def __init__(self, attestation_key: bytes):
        self._ak = attestation_key
        self.pcrs: Dict[int, bytes] = {idx: b"\x00" * 32 for idx in range(24)}

    def pcr_extend(self, pcr_index: int, component_bytes: bytes) -> str:
        if pcr_index not in self.pcrs:
            raise ValueError("Invalid PCR index")
        comp_hash = hashlib.sha256(component_bytes).digest()
        self.pcrs[pcr_index] = hashlib.sha256(self.pcrs[pcr_index] + comp_hash).digest()
        return self.pcrs[pcr_index].hex()

    def generate_quote(self, pcr_indices: List[int], nonce: bytes) -> Dict[str, str]:
        concat = b"".join(self.pcrs[i] for i in sorted(pcr_indices))
        pcr_digest = hashlib.sha256(concat).hexdigest()
        payload = f"{pcr_digest}:{nonce.hex()}".encode("utf-8")
        sig = hmac.new(self._ak, payload, hashlib.sha256).hexdigest()
        return {"pcr_digest": pcr_digest, "nonce_hex": nonce.hex(), "signature": sig}

    def verify_quote(self, quote: Dict[str, str], expected_pcr_digest: str, expected_nonce: bytes) -> bool:
        if quote.get("nonce_hex") != expected_nonce.hex():
            return False
        if not hmac.compare_digest(quote.get("pcr_digest", ""), expected_pcr_digest):
            return False
        payload = f"{quote['pcr_digest']}:{quote['nonce_hex']}".encode("utf-8")
        expected_sig = hmac.new(self._ak, payload, hashlib.sha256).hexdigest()
        return hmac.compare_digest(quote.get("signature", ""), expected_sig)
