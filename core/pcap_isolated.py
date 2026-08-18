"""Isolated PCAP analysis child process (safe to spawn from the Qt UI on Windows)."""

from __future__ import annotations

import pickle
import sys
from pathlib import Path


def _emit(summary) -> None:
    sys.stdout.buffer.write(pickle.dumps(summary, protocol=pickle.HIGHEST_PROTOCOL))
    sys.stdout.buffer.flush()


def main(argv: list[str] | None = None) -> int:
    if argv is None:
        args = list(sys.argv[1:])
    else:
        args = list(argv)
    if not args:
        print("usage: pcap_isolated <path> | pcap_isolated --batch", file=sys.stderr)
        return 2

    from core.pcap_analyzer import analyze_pcap, analyze_pcap_files

    if args[0] == "--batch":
        payload = pickle.loads(sys.stdin.buffer.read())
        paths = [str(path) for path in payload.get("paths") or [] if str(path or "").strip()]
        label = str(payload.get("label") or "")
        max_flows = int(payload.get("max_flows") or 0)
        max_evidence = int(payload.get("max_evidence") or 0)
        _emit(
            analyze_pcap_files(
                paths,
                label=label,
                max_flows=max_flows,
                max_evidence=max_evidence,
            )
        )
        return 0

    if args[0] == "--merge":
        from core.pcap_analyzer import merge_pcap_summaries

        payload = pickle.loads(sys.stdin.buffer.read())
        summaries = list(payload.get("summaries") or [])
        label = str(payload.get("label") or "")
        _emit(merge_pcap_summaries(summaries, label=label))
        return 0

    target = Path(args[0])
    max_flows = int(args[1]) if len(args) > 1 else 0
    max_evidence = int(args[2]) if len(args) > 2 else 0
    _emit(analyze_pcap(target, max_flows=max_flows, max_evidence=max_evidence))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
