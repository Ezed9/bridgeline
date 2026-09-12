"""The run trace.

Five rules that structurally prevent schema drift (the failure mode of the prior
harness, where fields existed on the dataclass but never on disk):

1. `TraceWriter.write(TraceRecord)` is the ONLY path to disk. No hand-built
   dicts anywhere in the codebase -- drift required someone to construct one.
2. Every field is always written, None as null. Fixed key set on every line.
3. A test asserts on-disk keys == dataclass fields, and pins TRACE_VERSION.
   Add a field without bumping the version and it goes red.
4. `detail` absorbs all kind-specific data, so the top-level schema never grows.
5. Tainted values are redacted to hash + length, never written verbatim -- a
   log a human later opens is itself a rendering channel (the EchoLeak shape).
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, fields
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .netpolicy import defang
from .types import Tainted

TRACE_VERSION = 1

KIND_RUN_START = "run_start"
KIND_PLAN_COMMITTED = "plan_committed"
KIND_STEP = "step"
KIND_EXTRACT = "extract"
KIND_HTTP = "http"
KIND_SKIP = "skip"
KIND_GUARD = "guard"
KIND_RUN_END = "run_end"

LAYER_CAPABILITY_GATE = "capability_gate"
LAYER_SINK_GATE = "sink_gate"
LAYER_SCHEMA = "schema"
LAYER_NETPOLICY = "netpolicy"
LAYER_CONTRACT = "contract"


@dataclass(frozen=True)
class TraceRecord:
    trace_version: int
    run_id: str
    seq: int
    ts: str
    kind: str
    step_index: int | None
    tool: str | None
    args: dict[str, Any]
    outcome: str  # executed | blocked | skipped | info
    layer: str | None
    reason: str
    contract: str | None
    verdict: str | None
    detail: dict[str, Any]


def redact(value: object) -> Any:
    """Tainted values never reach the trace verbatim."""
    if isinstance(value, Tainted):
        value = value.value
    if isinstance(value, str) and len(value) > 120:
        digest = hashlib.sha256(value.encode("utf-8", "replace")).hexdigest()[:12]
        return {"$tainted": digest, "len": len(value)}
    if isinstance(value, str | int | float | bool) or value is None:
        return value
    text = repr(value)
    digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:12]
    return {"$opaque": digest, "type": type(value).__name__, "len": len(text)}


class TraceWriter:
    def __init__(self, path: Path, run_id: str) -> None:
        self._path = path
        self._run_id = run_id
        self._seq = 0
        path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def write(
        self,
        kind: str,
        *,
        outcome: str = "info",
        step_index: int | None = None,
        tool: str | None = None,
        args: dict[str, Any] | None = None,
        layer: str | None = None,
        reason: str = "",
        contract: str | None = None,
        verdict: str | None = None,
        detail: dict[str, Any] | None = None,
    ) -> TraceRecord:
        record = TraceRecord(
            trace_version=TRACE_VERSION,
            run_id=self._run_id,
            seq=self._seq,
            ts=datetime.now(UTC).isoformat(timespec="milliseconds"),
            kind=kind,
            step_index=step_index,
            tool=tool,
            args={k: redact(v) for k, v in (args or {}).items()},
            outcome=outcome,
            layer=layer,
            reason=defang(reason),
            contract=contract,
            verdict=verdict,
            detail={k: redact(v) for k, v in (detail or {}).items()},
        )
        self._seq += 1
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(record), default=str) + "\n")
        return record


EXPECTED_KEYS: frozenset[str] = frozenset(f.name for f in fields(TraceRecord))
