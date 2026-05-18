from __future__ import annotations
import logging
import sys
from datetime import datetime, timezone
from pathlib import Path
class _UtcFormatter(logging.Formatter):
    def formatTime(self, record, datefmt=None):
        dt = datetime.fromtimestamp(record.created, tz=timezone.utc)
        ms = getattr(record, "msecs", 0)
        return dt.strftime("%Y-%m-%dT%H:%M:%S") + f".{int(ms):03d}Z"
_FMT = "%(asctime)s %(levelname)s %(message)s"
_current_log_file: str | None = object()
def setup_logging(log_file: str | None = None) -> logging.Logger:
    global _current_log_file
    root = logging.getLogger("micropki")
    root.setLevel(logging.DEBUG)
    for h in list(root.handlers):
        root.removeHandler(h)
        h.close()
    formatter = _UtcFormatter(_FMT)
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(logging.DEBUG)
    handler.setFormatter(formatter)
    root.addHandler(handler)
    _current_log_file = log_file
    return root
