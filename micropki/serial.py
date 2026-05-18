from __future__ import annotations
import os
import time
def generate_serial() -> int:
    timestamp_part = int(time.time()) & 0xFFFFFFFF
    random_part = int.from_bytes(os.urandom(4), "big")
    serial = (timestamp_part << 32) | random_part
    return serial
def serial_to_hex(serial: int) -> str:
    return f"{serial:x}".upper()
generate_serial_candidate = generate_serial
