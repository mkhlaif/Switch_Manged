"""Discovery Profile Registry.

Before a switch's AOS generation is known, only a command that is documented, read-only and
identical on every supported generation may run. For the supported ALE OmniSwitch families this
is ``show system`` (AOS 8 CLI Reference Guide 8.10R1 p.61-56; AOS 6250/6350/6450 CLI Reference
Guide 6.7.1 p.2-31). The command itself is the allowlisted policy entry ``system_info``
(security/policy.py); this registry adds what each generation's answer must look like, which
parser reads it, the sources, the verification status and the test fixtures.

A discovery result is accepted only when the output matches one registry entry completely:
vendor signals, model family of that generation and an AOS version of that generation.
Anything else is DISCOVERY_FAILED — never guessed, never followed by another command.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass

from app.services.alcatel.profiles import BUILTIN_PROFILES, model_family


@dataclass(frozen=True)
class DiscoveryProfile:
    key: str
    vendor: str
    generation: str                   # command-profile family this entry identifies
    model_families: tuple[str, ...]   # families the generation's command profile supports
    aos_versions: tuple[str, ...]     # version prefixes of that generation
    command_key: str                  # policy.DISCOVERY_PROFILE key (the executable command)
    command: str                      # for documentation / review only
    expected_patterns: tuple[str, ...]
    parser: str
    safety: str
    sources: tuple[str, ...]
    verification: str                 # doc_example | doc_syntax (see AOS_COMMAND_VERIFICATION)
    fixtures: tuple[str, ...]

    def to_dict(self) -> dict:
        return asdict(self)


def _families(generation: str) -> tuple[str, ...]:
    return tuple(BUILTIN_PROFILES[generation].supported_models)


def _versions(generation: str) -> tuple[str, ...]:
    return tuple(BUILTIN_PROFILES[generation].version_prefixes)


DISCOVERY_PROFILES: tuple[DiscoveryProfile, ...] = (
    DiscoveryProfile(
        key="ALE_AOS8_SHOW_SYSTEM", vendor="ALE", generation="AOS8",
        model_families=_families("AOS8"), aos_versions=_versions("AOS8"),
        command_key="system_info", command="show system",
        expected_patterns=(r"(?m)^\s*Description:\s+Alcatel-Lucent(?: Enterprise)? OS\d",
                           r"(?m)^\s*Object ID:\s+1\.3\.6\.1\.4\.1\.6486\."),
        parser="parse_show_system", safety="READ_ONLY",
        sources=("[A8] OmniSwitch AOS Release 8 CLI Reference Guide 8.10R1, show system, "
                 "p.61-56",),
        verification="doc_example",
        fixtures=("tests/fixtures/aos8/show_system.txt",),
    ),
    DiscoveryProfile(
        key="ALE_AOS6_SHOW_SYSTEM", vendor="ALE", generation="AOS6",
        model_families=_families("AOS6"), aos_versions=_versions("AOS6"),
        command_key="system_info", command="show system",
        expected_patterns=(r"(?m)^\s*Description:\s+Alcatel-Lucent(?: Enterprise)? OS\d",
                           r"(?m)^\s*Object ID:\s+1\.3\.6\.1\.4\.1\.6486\."),
        parser="parse_show_system", safety="READ_ONLY",
        sources=("[A6] OmniSwitch 6250/6350/6450 AOS Release 6 CLI Reference Guide 6.7.1, "
                 "show system, p.2-31",),
        verification="doc_example",
        fixtures=("tests/fixtures/aos6/show_system.txt",),
    ),
)


# --------------------------------------------------------------------- version normalization ---
_DISCOVERED_VERSION = re.compile(
    r"^(?P<major>\d{1,2})\.(?P<minor>\d{1,2})\.(?P<build>\d{1,4})(?:\.(?P<patch>\d{1,4}))?"
    r"\.(?P<release>R\d{1,2})$")
_EXPECTED_VERSION = re.compile(r"^(?P<major>\d{1,2})\.(?P<minor>\d{1,2})(?:[.R].*)?$")


@dataclass(frozen=True)
class AosVersion:
    raw: str
    major: int
    minor: int
    build: str = ""
    release: str = ""

    @property
    def train(self) -> str:
        """major.minor — the granularity used for lab/production verification records."""
        return f"{self.major}.{self.minor}"


def normalize_discovered_version(raw: str | None) -> AosVersion | None:
    """Only the exact format printed by AOS (e.g. 8.9.221.R03, 6.7.2.191.R08) is accepted."""
    m = _DISCOVERED_VERSION.match((raw or "").strip())
    if not m:
        return None
    return AosVersion(raw=raw.strip(), major=int(m["major"]), minor=int(m["minor"]),
                      build=m["build"], release=m["release"])


def expected_train(raw: str | None) -> str | None:
    """Administrator metadata such as "8.10R1" or "6.7.1" → "8.10" / "6.7" (compared on
    major.minor only: the mapping of release names to build numbers is not guessed)."""
    m = _EXPECTED_VERSION.match((raw or "").strip().upper())
    return f"{int(m['major'])}.{int(m['minor'])}" if m else None


def match_profile(vendor: str | None, model: str | None,
                  version: AosVersion | None) -> DiscoveryProfile | None:
    """The single registry entry the discovered identity belongs to, or None."""
    family = model_family(model)
    if vendor is None or family is None or version is None:
        return None
    for entry in DISCOVERY_PROFILES:
        if entry.vendor != vendor or family not in entry.model_families:
            continue
        if any(version.raw.startswith(p) if p.endswith(".") else version.train == p
               for p in entry.aos_versions):
            return entry
    return None


def output_matches(entry: DiscoveryProfile, output: str) -> bool:
    return all(re.search(p, output) for p in entry.expected_patterns)
