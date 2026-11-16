"""
Stage 13 Defensive Lab — Shadow-Memory ASan Simulator, CFI/PAC Guard & Capability Wasm Sandbox
==============================================================================================
1. MiniASanShadowAllocator:
   - Models AddressSanitizer 1:8 shadow memory with left/right redzones (0xFA) and freed quarantine (0xFD).
   - Deterministically catches Heap-Buffer-Overflow, Use-After-Free (UAF), and Double-Free.
2. ShadowStackAndPACGuard:
   - Enforces backward-edge Intel CET Shadow Stack (defeating ROP return-address overwrites)
     and forward-edge ARM PAC pointer authentication with context discriminators.
3. CapabilityWasmSandbox:
   - Models WebAssembly linear memory bounds checking + WASI explicit directory capabilities
     (zero ambient authority; blocks .env / credential access and path traversal).
"""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Dict, List, Optional, Set, Tuple


SHADOW_VALID = 0x00
SHADOW_REDZONE = 0xFA
SHADOW_QUARANTINE_FREED = 0xFD


class MemorySafetyViolation(RuntimeError):
    """Raised immediately when Mini-ASan, Shadow Stack, PAC, or Wasm bounds detect corruption."""


@dataclass
class AllocationRecord:
    base_addr: int
    user_size: int
    aligned_size: int
    left_rz: int
    right_rz: int
    freed: bool = False


class MiniASanShadowAllocator:
    GRANULARITY = 8
    REDZONE_BYTES = 16

    def __init__(self, total_bytes: int = 4096) -> None:
        if total_bytes % self.GRANULARITY != 0:
            raise ValueError("total_bytes must be a multiple of 8")
        self.total_bytes = total_bytes
        self.mem = bytearray(total_bytes)
        self.shadow = bytearray([SHADOW_REDZONE] * (total_bytes // self.GRANULARITY))
        self._cursor = 0
        self._allocs: Dict[int, AllocationRecord] = {}

    def _set_shadow_range(self, start: int, length: int, tag: int) -> None:
        for offset in range(start, start + length, self.GRANULARITY):
            self.shadow[offset // self.GRANULARITY] = tag

    def malloc(self, size: int) -> int:
        if size <= 0:
            raise ValueError("Allocation size must be positive")
        aligned = ((size + self.GRANULARITY - 1) // self.GRANULARITY) * self.GRANULARITY
        total_needed = self.REDZONE_BYTES + aligned + self.REDZONE_BYTES
        if self._cursor + total_needed > self.total_bytes:
            raise MemoryError("Out of simulated heap space")

        left_rz = self._cursor
        user_base = left_rz + self.REDZONE_BYTES
        right_rz = user_base + aligned
        self._cursor += total_needed

        self._set_shadow_range(left_rz, self.REDZONE_BYTES, SHADOW_REDZONE)
        self._set_shadow_range(user_base, aligned, SHADOW_VALID)
        self._set_shadow_range(right_rz, self.REDZONE_BYTES, SHADOW_REDZONE)

        self._allocs[user_base] = AllocationRecord(
            base_addr=user_base,
            user_size=size,
            aligned_size=aligned,
            left_rz=left_rz,
            right_rz=right_rz,
            freed=False,
        )
        return user_base

    def free(self, ptr: int) -> None:
        rec = self._allocs.get(ptr)
        if rec is None:
            raise MemorySafetyViolation("INVALID_FREE: pointer was never allocated")
        if rec.freed:
            raise MemorySafetyViolation("DOUBLE_FREE_DETECTED: chunk already in quarantine")
        rec.freed = True
        self._set_shadow_range(rec.base_addr, rec.aligned_size, SHADOW_QUARANTINE_FREED)

    def _check_access(self, addr: int, length: int) -> None:
        if addr < 0 or addr + length > self.total_bytes:
            raise MemorySafetyViolation("OUT_OF_HEAP_BOUNDS")
        # Exact byte-precision check against active allocation + shadow state
        for b in range(addr, addr + length):
            sb = self.shadow[b // self.GRANULARITY]
            if sb == SHADOW_QUARANTINE_FREED:
                raise MemorySafetyViolation(f"USE_AFTER_FREE at 0x{b:04x}")
            if sb == SHADOW_REDZONE:
                raise MemorySafetyViolation(f"HEAP_BUFFER_OVERFLOW (Redzone hit) at 0x{b:04x}")
        # Check exact unaligned tail inside last 8-byte granule
        for base, rec in self._allocs.items():
            if not rec.freed and base <= addr < base + rec.aligned_size:
                if addr + length > base + rec.user_size:
                    raise MemorySafetyViolation("HEAP_BUFFER_OVERFLOW (Intra-granule tail overflow)")
                return

    def write(self, addr: int, data: bytes) -> None:
        self._check_access(addr, len(data))
        self.mem[addr : addr + len(data)] = data

    def read(self, addr: int, length: int) -> bytes:
        self._check_access(addr, length)
        return bytes(self.mem[addr : addr + length])


class ShadowStackAndPACGuard:
    def __init__(self, pac_key: bytes) -> None:
        if len(pac_key) < 16:
            raise ValueError("PAC key must be >= 16 bytes")
        self._pac_key = bytes(pac_key)
        self._normal_stack: List[int] = []
        self._shadow_stack: List[int] = []

    def call_function(self, return_addr: int) -> None:
        self._normal_stack.append(return_addr)
        self._shadow_stack.append(return_addr)

    def simulate_stack_smash_overwrite(self, forged_rop_gadget: int) -> None:
        if not self._normal_stack:
            raise RuntimeError("Empty call stack")
        self._normal_stack[-1] = forged_rop_gadget

    def ret_function(self) -> int:
        if not self._normal_stack or not self._shadow_stack:
            raise MemorySafetyViolation("STACK_UNDERFLOW")
        normal_ret = self._normal_stack.pop()
        shadow_ret = self._shadow_stack.pop()
        if normal_ret != shadow_ret:
            raise MemorySafetyViolation(
                f"CET_SHADOW_STACK_MISMATCH: normal=0x{normal_ret:x} != shadow=0x{shadow_ret:x} (ROP blocked)"
            )
        return shadow_ret

    def sign_pointer(self, raw_ptr: int, context_discriminator: str) -> Tuple[int, str]:
        msg = f"{raw_ptr:#018x}:{context_discriminator}".encode("utf-8")
        pac = hmac.new(self._pac_key, msg, hashlib.sha256).hexdigest()[:16]
        return raw_ptr, pac

    def auth_pointer(self, signed_ptr: Tuple[int, str], expected_context: str) -> int:
        raw_ptr, provided_pac = signed_ptr
        _, expected_pac = self.sign_pointer(raw_ptr, expected_context)
        if not hmac.compare_digest(provided_pac, expected_pac):
            raise MemorySafetyViolation("PAC_AUTHENTICATION_FAILED: forged or cross-context vtable pointer")
        return raw_ptr


class CapabilityWasmSandbox:
    SENSITIVE_BASENAMES = {".env", "id_rsa", "id_ed25519", "credentials.json", "bybit_demo.env"}

    def __init__(self, linear_pages: int = 1, preopened_dirs: Optional[Set[str]] = None) -> None:
        self.page_size = 65536
        self.max_linear_bytes = linear_pages * self.page_size
        self.preopened_dirs = {self._norm(d) for d in (preopened_dirs or set())}

    @staticmethod
    def _norm(path: str) -> str:
        p = PurePosixPath(path)
        parts: List[str] = []
        for token in p.parts:
            if token in ("", ".", "/"):
                continue
            if token == "..":
                raise MemorySafetyViolation("WASI_PATH_ESCAPE_BLOCKED: '..' traversal forbidden")
            parts.append(token)
        return "/" + "/".join(parts)

    def check_linear_memory_access(self, offset: int, length: int) -> bool:
        if offset < 0 or length < 0 or offset + length > self.max_linear_bytes:
            raise MemorySafetyViolation("WASM_LINEAR_MEMORY_TRAP: out-of-bounds access")
        return True

    def open_file_capability(self, requested_path: str) -> str:
        clean = self._norm(requested_path)
        name = PurePosixPath(clean).name
        if name in self.SENSITIVE_BASENAMES or name.endswith((".pem", ".key")):
            raise MemorySafetyViolation(f"WASI_SECRET_DENIED: sensitive file '{name}' blocked")
        if not any(clean == cap or clean.startswith(cap + "/") for cap in self.preopened_dirs):
            raise MemorySafetyViolation(f"WASI_NO_CAPABILITY: '{clean}' outside preopened descriptors")
        return clean
