#!/usr/bin/env python3
"""Compare the observable protocol matrix contract across build targets."""

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
    "tcp_malformed_probes",
    "udp_malformed_probes",
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


def validate_observed_responses(report: dict[str, str], path: Path) -> None:
    for transport in ("tcp", "udp"):
        names = report[f"{transport}_names"].split(",")
        capture_only = {
            name for name in report[f"{transport}_capture_only"].split(",") if name
        }
        observed = [
            name for name in report[f"{transport}_observed_responses"].split(",") if name
        ]
        if len(observed) != len(set(observed)):
            raise ValueError(f"report {path} contains duplicate observed {transport} handlers")
        unknown = set(observed) - set(names)
        if unknown:
            raise ValueError(
                f"report {path} contains unknown observed {transport} handlers: "
                f"{', '.join(sorted(unknown))}"
            )
        expected = set(names) - capture_only
        if set(observed) != expected:
            missing = ", ".join(sorted(expected - set(observed))) or "none"
            unexpected = ", ".join(sorted(set(observed) - expected)) or "none"
            raise ValueError(
                f"report {path} has inconsistent {transport} observations "
                f"(missing: {missing}; unexpected: {unexpected})"
            )
        malformed_key = f"{transport}_malformed_probes"
        try:
            malformed_probes = int(report[malformed_key])
        except ValueError as error:
            raise ValueError(f"report {path} has an invalid {malformed_key} value") from error
        if malformed_probes < len(names):
            raise ValueError(
                f"report {path} exercised only {malformed_probes} malformed {transport} probes; "
                f"expected at least {len(names)}"
            )


def main() -> int:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} <report> <report> [<report> ...]", file=sys.stderr)
        return 2
    paths = [Path(value) for value in sys.argv[1:]]
    reports = [read_report(path) for path in paths]
    for report, path in zip(reports, paths):
        validate_observed_responses(report, path)
        if report["schema"] != EXPECTED_SCHEMA:
            print(
                f"unsupported protocol matrix schema in {path}: {report['schema']!r}; "
                f"expected {EXPECTED_SCHEMA!r}",
                file=sys.stderr,
            )
            return 1
    baseline = reports[0]
    for path, report in zip(paths[1:], reports[1:]):
        if baseline != report:
            differing = sorted(key for key in REQUIRED_KEYS if baseline[key] != report[key])
            for key in differing:
                print(
                    f"protocol matrix mismatch for {key}: "
                    f"{paths[0]}={baseline[key]!r} {path}={report[key]!r}",
                    file=sys.stderr,
                )
            return 1
    print(f"PASS: {len(reports)} build-target protocol matrix contracts match")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
