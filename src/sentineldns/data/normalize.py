from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))*\.?$"
)


@dataclass(frozen=True)
class DomainRecord:
    raw_value: str
    original_domain: str
    normalized_domain: str
    etld_plus_one: str | None = None


def extract_domain(raw_value: str) -> str:
    value = (raw_value or "").strip()
    if not value:
        return ""
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
        return host
    return value


def _idna_to_ascii(domain: str) -> str:
    labels = domain.split(".")
    converted: list[str] = []
    for label in labels:
        if not label:
            continue
        try:
            converted.append(label.encode("idna").decode("ascii"))
        except UnicodeError:
            return ""
    return ".".join(converted)


def _maybe_etld1(domain: str) -> str | None:
    try:
        from publicsuffix2 import get_sld  # type: ignore

        return get_sld(domain)
    except Exception:
        return None


def normalize_domain(
    raw_value: str,
    remove_www: bool = True,
    include_etld1: bool = False,
) -> DomainRecord | None:
    extracted = extract_domain(raw_value)
    if not extracted:
        return None
    extracted = extracted.strip().lower().rstrip(".")
    if remove_www and extracted.startswith("www."):
        extracted = extracted[4:]

    ascii_domain = _idna_to_ascii(extracted)
    if not ascii_domain:
        return None
    if not DOMAIN_RE.match(ascii_domain):
        return None

    etld1 = _maybe_etld1(ascii_domain) if include_etld1 else None
    return DomainRecord(
        raw_value=raw_value,
        original_domain=extracted,
        normalized_domain=ascii_domain,
        etld_plus_one=etld1,
    )
