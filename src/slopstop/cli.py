"""Command line interface.

Subcommands:

  check    vet a single package name
  scan     vet every dependency in a manifest file
  monitor  re check every absent name in the corpus and report flips

The interface deliberately avoids multi word flags. Exit codes are meaningful
so the tool composes inside a CI step or an agent hook: a nonzero exit means at
least one blocking verdict was found.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import scanner
from .advisories import AdvisoryLog
from .cache import VerdictCache
from .calibration import load_cases, run_calibration
from .checker import Checker, load_popular
from .config import load_settings
from .corpus import Corpus
from .models import Ecosystem, RiskAssessment, Verdict
from .registries import RegistryClient

_DATA_FILE = Path(__file__).resolve().parent.parent.parent / "data" / "seed_popular.json"

_LABELS = {
    Verdict.SAFE: "SAFE",
    Verdict.UNKNOWN: "UNKNOWN",
    Verdict.SUSPICIOUS: "SUSPICIOUS",
    Verdict.HALLUCINATED: "HALLUCINATED",
}


def _build_checker(record: bool = True) -> Checker:
    settings = load_settings()
    client = RegistryClient(
        user_agent=settings.user_agent,
        timeout=settings.http_timeout,
    )
    popular = load_popular(_DATA_FILE)
    corpus = Corpus(settings.db_path) if record else None
    return Checker(client, popular=popular, corpus=corpus, cache=VerdictCache())


def _print_assessment(a: RiskAssessment) -> None:
    label = _LABELS[a.verdict]
    print(f"[{label}] {a.ecosystem.value}:{a.name}  risk={a.score}")
    for reason in a.reasons:
        print(f"    - {reason}")


def _ecosystem(value: str) -> Ecosystem:
    try:
        return Ecosystem(value.lower())
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"ecosystem must be npm or pypi, got {value!r}"
        )


def cmd_check(args: argparse.Namespace) -> int:
    checker = _build_checker(record=not args.nostore)
    assessment = checker.check(args.ecosystem, args.name)
    _print_assessment(assessment)
    return 1 if assessment.is_blocking() else 0


def cmd_scan(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        print(f"file not found: {path}", file=sys.stderr)
        return 2
    pairs = scanner.scan_path(path)
    if not pairs:
        print("no dependencies found")
        return 0

    checker = _build_checker(record=not args.nostore)
    blocking = 0
    for eco, name in pairs:
        assessment = checker.check(eco, name, source="scan")
        _print_assessment(assessment)
        if assessment.is_blocking():
            blocking += 1
    print(f"\nchecked {len(pairs)} packages, {blocking} need review")
    return 1 if blocking else 0


def cmd_monitor(args: argparse.Namespace) -> int:
    settings = load_settings()
    corpus = Corpus(settings.db_path)
    checker = _build_checker(record=True)

    flips = 0
    checked = 0
    for eco_value, name in corpus.absent_names():
        eco = Ecosystem(eco_value)
        assessment = checker.check(eco, name, source="monitor", use_cache=False)
        checked += 1
        if assessment.facts and assessment.facts.existence.value == "present":
            flips += 1
            print(f"[FLIP] {eco_value}:{name} was absent and is now registered")
            _print_assessment(assessment)

    print(f"\nre checked {checked} absent names, {flips} flips detected")
    return 1 if flips else 0


def cmd_calibrate(args: argparse.Namespace) -> int:
    path = Path(args.path)
    if not path.exists():
        print(f"file not found: {path}", file=sys.stderr)
        return 2

    cases = load_cases(path)
    checker = _build_checker(record=False)
    metrics, results = run_calibration(checker, cases)

    total = len(results)
    resolved = total - metrics.unresolved
    print(f"cases: {total}   resolved: {resolved}   unresolved: {metrics.unresolved}")
    print(
        f"true positive: {metrics.true_positive}   "
        f"false negative: {metrics.false_negative}   "
        f"true negative: {metrics.true_negative}   "
        f"false positive: {metrics.false_positive}"
    )
    print(f"recall:              {metrics.recall:.1%}")
    print(f"precision:           {metrics.precision:.1%}")
    print(f"false positive rate: {metrics.false_positive_rate:.1%}")

    if metrics.misclassified:
        print("\nmisclassified:")
        for r in metrics.misclassified:
            kind = "false alarm" if r.case.label == "good" else "missed"
            print(f"    [{kind}] {r.case.ecosystem.value}:{r.case.name} -> {r.verdict.value}")

    met = metrics.gate_met(args.maxfpr, args.minrecall)
    print(
        f"\ngate (fpr <= {args.maxfpr:.0%}, recall >= {args.minrecall:.0%}): "
        f"{'MET' if met else 'NOT MET'}"
    )
    return 0 if met else 1


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        from .mcp_server import run_server
    except ImportError as exc:
        print(
            f"could not start the MCP server: {exc}\n"
            "if the mcp package is missing, install it with: "
            "pip install slopstop[mcp]",
            file=sys.stderr,
        )
        return 2
    run_server()
    return 0


def cmd_advisories(args: argparse.Namespace) -> int:
    settings = load_settings()
    log = AdvisoryLog(settings.db_path)

    installed: set[tuple[str, str]] = set()
    if args.manifest:
        manifest = Path(args.manifest)
        if not manifest.exists():
            print(f"file not found: {manifest}", file=sys.stderr)
            return 2
        for eco, name in scanner.scan_path(manifest):
            installed.add((eco.value, name.lower()))

    pairs = log.cross_reference(installed, limit=args.limit)
    if not pairs:
        print("no advisories recorded yet")
        return 0

    ignored = 0
    for row, was_ignored in pairs:
        tag = ""
        if args.manifest:
            tag = "  [IGNORED: still in manifest]" if was_ignored else "  [not installed]"
            if was_ignored:
                ignored += 1
        print(f"[{row['verdict'].upper()}] {row['ecosystem']}:{row['name']}  "
              f"risk={row['score']}  mode={row['mode']}{tag}")

    print(f"\n{len(pairs)} advisories")
    if args.manifest:
        print(f"{ignored} ignored (flagged but present in {args.manifest})")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="slopstop",
        description="Catch hallucinated and slopsquatted packages before install.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_check = sub.add_parser("check", help="vet a single package name")
    p_check.add_argument("ecosystem", type=_ecosystem, help="npm or pypi")
    p_check.add_argument("name", help="the package name to vet")
    p_check.add_argument(
        "--nostore", action="store_true",
        help="do not write the result to the local corpus",
    )
    p_check.set_defaults(func=cmd_check)

    p_scan = sub.add_parser("scan", help="vet every dependency in a manifest")
    p_scan.add_argument("path", help="path to requirements.txt or package.json")
    p_scan.add_argument(
        "--nostore", action="store_true",
        help="do not write results to the local corpus",
    )
    p_scan.set_defaults(func=cmd_scan)

    p_monitor = sub.add_parser(
        "monitor", help="re check absent names and report flips",
    )
    p_monitor.set_defaults(func=cmd_monitor)

    p_cal = sub.add_parser(
        "calibrate", help="measure recall and false positive rate on a labeled set",
    )
    p_cal.add_argument("path", help="path to a labeled set json file")
    p_cal.add_argument(
        "--maxfpr", type=float, default=0.05,
        help="gate: maximum acceptable false positive rate (default 0.05)",
    )
    p_cal.add_argument(
        "--minrecall", type=float, default=0.90,
        help="gate: minimum acceptable recall (default 0.90)",
    )
    p_cal.set_defaults(func=cmd_calibrate)

    p_serve = sub.add_parser(
        "serve", help="run the agent hook as an MCP stdio server",
    )
    p_serve.set_defaults(func=cmd_serve)

    p_adv = sub.add_parser(
        "advisories", help="list flagged packages, and which were ignored",
    )
    p_adv.add_argument(
        "--manifest", default=None,
        help="a requirements.txt or package.json to mark ignored advisories",
    )
    p_adv.add_argument(
        "--limit", type=int, default=50, help="how many advisories to show",
    )
    p_adv.set_defaults(func=cmd_advisories)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        # A downstream reader (for example head) closed the pipe early. Exit
        # quietly rather than dumping a traceback.
        return 0


if __name__ == "__main__":
    raise SystemExit(main())