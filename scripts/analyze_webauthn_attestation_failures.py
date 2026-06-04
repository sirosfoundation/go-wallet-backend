#!/usr/bin/env python3
"""Cluster WebAuthn verification failures from NDJSON logs.

This tool is designed for backend logs emitted by internal/service/webauthn.go.
It groups intermittent registration and login failures by stable fingerprint
fields so operators can quickly see if failures share the same signature input
tuple.
"""

from __future__ import annotations

import argparse
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any


TARGET_MSGS = {"Failed to verify registration", "Failed to verify login"}


@dataclass
class Event:
    ts: float | None
    error: str
    phase: str  # "registration" or "login"
    attestation_format: str
    signature_input_sha256: str
    signature_sha256: str
    signature_len: int | None
    signature_normalized_changed: str
    x5c_leaf_sha256: str
    auth_data_sha256: str
    client_data_json_sha256: str
    credential_id: str
    sign_count: int | None
    source: str


def read_ndjson(path: Path) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as handle:
        for i, line in enumerate(handle, 1):
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                row["_line"] = i
                rows.append(row)
    return rows


def as_event(row: dict[str, Any], source: str) -> Event | None:
    msg = str(row.get("msg", ""))
    if msg not in TARGET_MSGS:
        return None

    phase = "login" if "login" in msg.lower() else "registration"

    return Event(
        ts=row.get("ts") if isinstance(row.get("ts"), (int, float)) else None,
        error=str(row.get("error", "")),
        phase=phase,
        attestation_format=str(row.get("attestation_format", "")),
        signature_input_sha256=str(row.get("signature_input_sha256", "")),
        signature_sha256=str(row.get("signature_sha256", "")),
        signature_len=row.get("signature_len") if isinstance(row.get("signature_len"), int) else None,
        signature_normalized_changed=str(row.get("signature_normalized_changed", "")),
        x5c_leaf_sha256=str(row.get("x5c_leaf_sha256", "")),
        auth_data_sha256=str(row.get("auth_data_sha256", "")),
        client_data_json_sha256=str(row.get("client_data_json_sha256", "")),
        credential_id=str(row.get("credential_id", "")),
        sign_count=row.get("sign_count") if isinstance(row.get("sign_count"), int) else None,
        source=source,
    )


def cluster_key(event: Event) -> tuple[str, ...]:
    # Always include phase to separate registration vs login failures.
    # Prefer tuple that represents the signed input and signer identity.
    if event.signature_input_sha256 and event.signature_sha256 and event.x5c_leaf_sha256:
        return (
            event.phase,
            event.attestation_format,
            event.error,
            event.signature_input_sha256,
            event.signature_sha256,
            event.x5c_leaf_sha256,
            event.signature_normalized_changed,
        )

    # Fallback for old logs or login events without x5c.
    return (
        event.phase,
        event.attestation_format,
        event.error,
        event.auth_data_sha256,
        event.client_data_json_sha256,
        event.signature_sha256,
        event.x5c_leaf_sha256,
    )


def short(value: str, n: int = 12) -> str:
    if not value:
        return "-"
    if len(value) <= n:
        return value
    return value[:n]


def print_cluster_report(events: list[Event], max_examples: int) -> None:
    grouped: dict[tuple[str, ...], list[Event]] = defaultdict(list)
    for event in events:
        grouped[cluster_key(event)].append(event)

    clusters = sorted(grouped.items(), key=lambda item: len(item[1]), reverse=True)

    print(f"events: {len(events)}")
    print(f"clusters: {len(clusters)}")
    print()

    for idx, (key, members) in enumerate(clusters, 1):
        sample = members[0]
        print(f"[{idx}] count={len(members)} phase={sample.phase}")
        print(f"  error: {sample.error or '-'}")
        print(f"  format: {sample.attestation_format or '-'}")
        print(f"  sig_input: {short(sample.signature_input_sha256)}")
        print(f"  sig: {short(sample.signature_sha256)} len={sample.signature_len if sample.signature_len is not None else '-'}")
        print(f"  x5c_leaf: {short(sample.x5c_leaf_sha256)}")
        print(f"  normalized_changed: {sample.signature_normalized_changed or '-'}")

        # Surface timestamp spread to detect bursty races.
        ts_values = [e.ts for e in members if e.ts is not None]
        if ts_values:
            print(f"  ts_range: {min(ts_values):.3f} .. {max(ts_values):.3f}")

        for example in members[:max_examples]:
            line = f"    - src={example.source}"
            if example.ts is not None:
                line += f" ts={example.ts:.3f}"
            print(line)
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description="Cluster WebAuthn verification failures (registration and login) from NDJSON logs")
    parser.add_argument("files", nargs="+", help="One or more NDJSON log files")
    parser.add_argument("--examples", type=int, default=2, help="Example rows per cluster (default: 2)")
    args = parser.parse_args()

    events: list[Event] = []
    for file_name in args.files:
        path = Path(file_name).expanduser().resolve()
        if not path.exists():
            print(f"warning: missing file: {path}")
            continue
        rows = read_ndjson(path)
        for row in rows:
            event = as_event(row, source=f"{path.name}:L{row.get('_line', '?')}")
            if event is not None:
                events.append(event)

    if not events:
        print("No matching verification failures found.")
        return 1

    print_cluster_report(events, max_examples=max(1, args.examples))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
