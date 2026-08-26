#!/usr/bin/env python3
"""Compare the observable protocol matrix contract across platforms."""

from pathlib import Path
import sys


REQUIRED_KEYS = {
    "schema",
    "tcp_handlers",
    "udp_handlers",
    "tcp_responses",
    "udp_responses",
    "tcp_observed_responses",
    "udp_observed_responses",
    "tcp_names",
    "udp_names",
    "tcp_capture_only",
    "udp_capture_only",
}
EXPECTED_SCHEMA = "2"


def read_report(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    report = path.read_text(encoding="utf-8")
    if report.startswith("\ufeff"):
        report = report[1:]
    for line in report.splitlines():
        key, separator, value = line.partition("=")
        if not separator or not key or key in values:
            raise ValueError(f"invalid report row in {path}: {line!r}")
        values[key] = value
    missing = REQUIRED_KEYS - values.keys()
    if missing:
        raise ValueError(f"report {path} is missing keys: {', '.join(sorted(missing))}")
    return values


def main() -> int:
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <linux-report> <windows-report>", file=sys.stderr)
        return 2
    linux = read_report(Path(sys.argv[1]))
    windows = read_report(Path(sys.argv[2]))
    if linux["schema"] != EXPECTED_SCHEMA or windows["schema"] != EXPECTED_SCHEMA:
        print(
            f"unsupported protocol matrix schema: Linux={linux['schema']!r} "
            f"Windows={windows['schema']!r}; expected {EXPECTED_SCHEMA!r}",
            file=sys.stderr,
        )
        return 1
    if linux != windows:
        differing = sorted(key for key in REQUIRED_KEYS if linux[key] != windows[key])
        for key in differing:
            print(f"protocol matrix mismatch for {key}: Linux={linux[key]!r} Windows={windows[key]!r}", file=sys.stderr)
        return 1
    print("PASS: Linux and Windows protocol matrix contracts match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
