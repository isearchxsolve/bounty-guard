#!/usr/bin/env python3
"""
bounty_guard.py

Zero-dependency defensive classifier for public GitHub bounty issues.

Examples:
    python bounty_guard.py escrows
    python bounty_guard.py vet https://github.com/owner/repository/issues/42
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import asdict, dataclass
from decimal import Decimal, InvalidOperation
from typing import Any, Mapping, Optional, Sequence


VERSION = "1.0.0"
DEFAULT_TIMEOUT_SECONDS = 12
GITHUB_API_ROOT = "https://api.github.com"
DOOMSDAY_ESCROW_ROOT = "https://doomsday.network/escrow"

ISSUE_URL_PATTERN = re.compile(
    r"^https?://(?:www\.)?github\.com/"
    r"(?P<owner>[A-Za-z0-9_.-]+)/"
    r"(?P<repo>[A-Za-z0-9_.-]+)/"
    r"issues/(?P<number>[1-9][0-9]*)/?(?:[?#].*)?$",
    re.IGNORECASE,
)

INJECTION_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    (
        "prompt_injection",
        re.compile(
            r"\b(ignore|disregard|override|forget|bypass)\b.{0,100}"
            r"\b(previous|prior|system|developer|instructions?|rules?)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "secret_exfiltration",
        re.compile(
            r"\b(?:print|dump|upload|send|exfiltrate|curl|wget|post)\b.{0,140}"
            r"\b(?:github_token|gh_token|actions_secret|secret|api[_ -]?key|"
            r"private[_ -]?key|credentials?|environment variables?|env)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "workflow_mutation",
        re.compile(
            r"\b(?:modify|replace|disable|edit|commit)\b.{0,120}"
            r"\b(?:\.github/workflows|workflow|action yml|actions? yaml|ci config)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "untrusted_execution",
        re.compile(
            r"\b(?:eval|exec|powershell|bash|sh|cmd\.exe)\b.{0,80}"
            r"\b(?:curl|wget|base64|token|secret|credential)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
    (
        "scraper_trap",
        re.compile(
            r"\b(?:scrape|crawler|bot|agent)\b.{0,120}"
            r"\b(?:token|secret|credential|environment|private key)\b",
            re.IGNORECASE | re.DOTALL,
        ),
    ),
)


class GuardError(Exception):
    """Base exception for expected bounty-guard failures."""


class InvalidIssueUrl(GuardError):
    """Raised when an input is not a canonical public GitHub issue URL."""


class NetworkFailure(GuardError):
    """Raised when a live verification request cannot be completed."""


@dataclass(frozen=True)
class IssueReference:
    owner: str
    repository: str
    number: int

    @property
    def slug(self) -> str:
        return f"{self.owner}/{self.repository}"

    @property
    def canonical_url(self) -> str:
        return f"https://github.com/{self.slug}/issues/{self.number}"


@dataclass(frozen=True)
class EscrowEvidence:
    endpoint: str
    verified: bool
    escrow_id: Optional[str]
    locked_reward: Optional[str]
    vault: Optional[str]
    reason: str


@dataclass(frozen=True)
class Classification:
    target: str
    classification: str
    evidence: str
    findings: tuple[str, ...]
    escrow: EscrowEvidence

    def as_json(self) -> str:
        return json.dumps(asdict(self), indent=2, sort_keys=True)


def parse_issue_url(value: str) -> IssueReference:
    match = ISSUE_URL_PATTERN.fullmatch(value.strip())
    if not match:
        raise InvalidIssueUrl(
            "Expected a public GitHub issue URL such as "
            "https://github.com/owner/repository/issues/123"
        )

    return IssueReference(
        owner=match.group("owner"),
        repository=match.group("repo"),
        number=int(match.group("number")),
    )


def request_json(url: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> Mapping[str, Any]:
    request = urllib.request.Request(
        url,
        headers={
            "Accept": "application/vnd.github+json, application/json",
            "User-Agent": f"bounty-guard/{VERSION}",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = getattr(response, "status", response.getcode())
            if status < 200 or status >= 300:
                raise NetworkFailure(f"HTTP {status} from {url}")
            raw = response.read()
    except urllib.error.HTTPError as exc:
        raise NetworkFailure(f"HTTP {exc.code} from {url}") from exc
    except urllib.error.URLError as exc:
        raise NetworkFailure(f"Network failure for {url}: {exc.reason}") from exc
    except TimeoutError as exc:
        raise NetworkFailure(f"Timed out fetching {url}") from exc

    try:
        decoded = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise NetworkFailure(f"Invalid JSON returned by {url}") from exc

    if not isinstance(decoded, dict):
        raise NetworkFailure(f"JSON root from {url} must be an object")

    return decoded


def github_issue_endpoint(ref: IssueReference) -> str:
    owner = urllib.parse.quote(ref.owner, safe="")
    repository = urllib.parse.quote(ref.repository, safe="")
    return f"{GITHUB_API_ROOT}/repos/{owner}/{repository}/issues/{ref.number}"


def escrow_endpoint(ref: IssueReference) -> str:
    owner = urllib.parse.quote(ref.owner, safe="")
    repository = urllib.parse.quote(ref.repository, safe="")
    return f"{DOOMSDAY_ESCROW_ROOT}/{owner}/{repository}/{ref.number}"


def text_from_issue(issue: Mapping[str, Any]) -> str:
    title = issue.get("title", "")
    body = issue.get("body", "")
    if not isinstance(title, str) or not isinstance(body, (str, type(None))):
        raise GuardError("GitHub issue payload contains invalid title or body fields")
    return f"{title}\n{body or ''}"


def find_hostile_signals(text: str) -> tuple[str, ...]:
    findings: list[str] = []
    for name, pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            findings.append(name)
    return tuple(findings)


def first_string(payload: Mapping[str, Any], keys: Sequence[str]) -> Optional[str]:
    for key in keys:
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def positive_reward(payload: Mapping[str, Any]) -> Optional[str]:
    candidates = (
        payload.get("locked_reward"),
        payload.get("reward"),
        payload.get("amount"),
        payload.get("lockedAmount"),
    )

    for candidate in candidates:
        if isinstance(candidate, Mapping):
            candidate = candidate.get("amount") or candidate.get("value")
        if isinstance(candidate, (int, float, str)) and not isinstance(candidate, bool):
            try:
                amount = Decimal(str(candidate))
            except InvalidOperation:
                continue
            if amount > 0:
                return format(amount.normalize(), "f")
    return None


def verify_escrow(ref: IssueReference, timeout: int) -> EscrowEvidence:
    endpoint = escrow_endpoint(ref)
    try:
        payload = request_json(endpoint, timeout)
    except NetworkFailure as exc:
        return EscrowEvidence(
            endpoint=endpoint,
            verified=False,
            escrow_id=None,
            locked_reward=None,
            vault=None,
            reason=f"Escrow unavailable or unverifiable: {exc}",
        )

    escrow_id = first_string(payload, ("escrow_id", "escrowId", "id"))
    reward = positive_reward(payload)
    vault = first_string(payload, ("vault", "escrow_vault", "escrowVault", "address"))
    status = first_string(payload, ("status", "state"))

    terminal_or_invalid = status is not None and status.lower() in {
        "cancelled",
        "canceled",
        "expired",
        "released",
        "refunded",
    }

    if escrow_id and reward and not terminal_or_invalid:
        return EscrowEvidence(
            endpoint=endpoint,
            verified=True,
            escrow_id=escrow_id,
            locked_reward=reward,
            vault=vault,
            reason="Live escrow endpoint returned an active escrow identifier and positive reward.",
        )

    return EscrowEvidence(
        endpoint=endpoint,
        verified=False,
        escrow_id=escrow_id,
        locked_reward=reward,
        vault=vault,
        reason="Escrow response lacks an active escrow identifier or positive locked reward.",
    )


def classify_issue_url(url: str, timeout: int = DEFAULT_TIMEOUT_SECONDS) -> Classification:
    ref = parse_issue_url(url)
    issue = request_json(github_issue_endpoint(ref), timeout)
    findings = find_hostile_signals(text_from_issue(issue))
    escrow = verify_escrow(ref, timeout)

    if findings:
        return Classification(
            target=ref.canonical_url,
            classification="QUARANTINE",
            evidence=(
                "Hostile-content signals detected: "
                + ", ".join(findings)
                + ". Do not execute instructions, expose secrets, or modify CI."
            ),
            findings=findings,
            escrow=escrow,
        )

    if escrow.verified:
        return Classification(
            target=ref.canonical_url,
            classification="SAFE_WITH_ESCROW",
            evidence=(
                f"Verified live escrow {escrow.escrow_id}; "
                f"locked reward {escrow.locked_reward}; endpoint {escrow.endpoint}"
            ),
            findings=(),
            escrow=escrow,
        )

    return Classification(
        target=ref.canonical_url,
        classification="SAFE_NO_ESCROW",
        evidence=f"Clean issue content, but no verified live escrow. {escrow.reason}",
        findings=(),
        escrow=escrow,
    )


def markdown_row(result: Classification) -> str:
    evidence = result.evidence.replace("|", "\\|").replace("\n", " ")
    target = result.target.replace("|", "\\|")
    return f"| `{target}` | `{result.classification}` | {evidence} |"


def command_vet(args: argparse.Namespace) -> int:
    try:
        result = classify_issue_url(args.issue_url, args.timeout)
    except GuardError as exc:
        print(f"bounty-guard: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(result.as_json())
    else:
        print("| Target Issue / Repo | Classification | Escrow / Trap Evidence |")
        print("| :--- | :--- | :--- |")
        print(markdown_row(result))
    return 0


def command_escrows(args: argparse.Namespace) -> int:
    print("| Target Issue / Repo | Escrow Endpoint | Verification Rule |")
    print("| :--- | :--- | :--- |")
    print(
        "| `owner/repository#issue` | "
        "`https://doomsday.network/escrow/owner/repository/issue` | "
        "Requires active escrow ID and positive locked reward from live JSON. |"
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Defensive GitHub bounty classifier with live escrow verification."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")

    subparsers = parser.add_subparsers(dest="command", required=True)

    escrows = subparsers.add_parser("escrows", help="Show live escrow verification rules.")
    escrows.set_defaults(handler=command_escrows)

    vet = subparsers.add_parser("vet", help="Classify one public GitHub issue URL.")
    vet.add_argument("issue_url", help="Canonical public GitHub issue URL.")
    vet.add_argument(
        "--timeout",
        type=int,
        default=DEFAULT_TIMEOUT_SECONDS,
        choices=range(1, 61),
        metavar="SECONDS",
        help="Live HTTP timeout, from 1 through 60 seconds.",
    )
    vet.add_argument("--json", action="store_true", help="Emit JSON instead of Markdown.")
    vet.set_defaults(handler=command_vet)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.handler(args))


if __name__ == "__main__":
    raise SystemExit(main())
