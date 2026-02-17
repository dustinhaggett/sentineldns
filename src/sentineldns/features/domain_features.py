from __future__ import annotations

import hashlib
import math
from collections import Counter
from typing import Any

import numpy as np
from scipy import sparse
from sklearn.feature_extraction.text import HashingVectorizer

SUSPICIOUS_WORDS = ["login", "verify", "secure", "account", "update", "bank", "wallet", "support"]
BRAND_LIST = [
    "google",
    "apple",
    "microsoft",
    "paypal",
    "amazon",
    "facebook",
    "instagram",
    "netflix",
]
VOWELS = set("aeiou")

SCALAR_FEATURE_NAMES = [
    "length",
    "num_labels",
    "tld_hash",
    "digit_ratio",
    "hyphen_count",
    "vowel_ratio",
    "entropy",
    "punycode_flag",
    "has_suspicious_words",
    "brand_edit_distance_min",
]


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    entropy = 0.0
    for count in counts.values():
        p = count / total
        entropy -= p * math.log2(p)
    return float(entropy)


def _levenshtein(a: str, b: str) -> int:
    try:
        import Levenshtein  # type: ignore

        return int(Levenshtein.distance(a, b))
    except Exception:
        if a == b:
            return 0
        if not a:
            return len(b)
        if not b:
            return len(a)
        prev = list(range(len(b) + 1))
        for i, ca in enumerate(a, 1):
            curr = [i]
            for j, cb in enumerate(b, 1):
                insert = curr[j - 1] + 1
                delete = prev[j] + 1
                replace = prev[j - 1] + (ca != cb)
                curr.append(min(insert, delete, replace))
            prev = curr
        return prev[-1]


def _tld_hash(domain: str) -> float:
    tld = domain.rsplit(".", 1)[-1] if "." in domain else domain
    digest = hashlib.md5(tld.encode("utf-8")).hexdigest()
    return float(int(digest[:8], 16) % 997)


def scalar_features(domain: str) -> dict[str, float]:
    labels = domain.split(".")
    length = len(domain)
    digit_count = sum(ch.isdigit() for ch in domain)
    hyphen_count = domain.count("-")
    alpha_chars = [ch for ch in domain if ch.isalpha()]
    vowel_count = sum(ch in VOWELS for ch in alpha_chars)
    has_punycode = any(label.startswith("xn--") for label in labels)
    has_suspicious = any(word in domain for word in SUSPICIOUS_WORDS)
    left_label = labels[0] if labels else domain
    brand_dist_min = min(_levenshtein(left_label, brand) for brand in BRAND_LIST)
    return {
        "length": float(length),
        "num_labels": float(len(labels)),
        "tld_hash": _tld_hash(domain),
        "digit_ratio": float(digit_count / max(length, 1)),
        "hyphen_count": float(hyphen_count),
        "vowel_ratio": float(vowel_count / max(len(alpha_chars), 1)),
        "entropy": shannon_entropy(domain),
        "punycode_flag": float(1 if has_punycode else 0),
        "has_suspicious_words": float(1 if has_suspicious else 0),
        "brand_edit_distance_min": float(brand_dist_min),
    }


def build_domain_feature_matrix(
    domains: list[str],
    vectorizer: HashingVectorizer | None = None,
) -> tuple[sparse.csr_matrix, HashingVectorizer, np.ndarray]:
    vectorizer = vectorizer or HashingVectorizer(
        n_features=2**15, analyzer="char", ngram_range=(3, 5), alternate_sign=False
    )
    text_matrix = vectorizer.transform(domains)
    scalars = np.array(
        [[scalar_features(domain)[name] for name in SCALAR_FEATURE_NAMES] for domain in domains],
        dtype=np.float64,
    )
    scalar_matrix = sparse.csr_matrix(scalars)
    combined = sparse.hstack([text_matrix, scalar_matrix], format="csr")
    return combined, vectorizer, scalars


def scalar_reason_tags(
    scalar_values: dict[str, float],
    coef_tail: np.ndarray | None = None,
) -> list[str]:
    tags: list[str] = []
    if scalar_values["entropy"] > 3.4:
        tags.append("high randomness in name")
    if scalar_values["brand_edit_distance_min"] <= 2:
        tags.append("looks similar to a popular brand")
    if scalar_values["punycode_flag"] >= 1:
        tags.append("uses punycode characters")
    if scalar_values["has_suspicious_words"] >= 1:
        tags.append("contains phishing-like words")
    if scalar_values["digit_ratio"] > 0.2:
        tags.append("contains many numbers")

    if coef_tail is not None and len(coef_tail) == len(SCALAR_FEATURE_NAMES):
        ranked = sorted(
            zip(SCALAR_FEATURE_NAMES, coef_tail, strict=True),
            key=lambda item: abs(item[1]),
            reverse=True,
        )
        for name, weight in ranked[:2]:
            if name == "hyphen_count" and scalar_values[name] > 2 and weight > 0:
                tags.append("unusually many hyphens")
            if name == "length" and scalar_values[name] > 28 and weight > 0:
                tags.append("rare-looking domain")
    if not tags:
        tags.append("pattern appears common")
    return tags[:5]


def feature_metadata() -> dict[str, Any]:
    return {"scalar_feature_names": SCALAR_FEATURE_NAMES, "suspicious_words": SUSPICIOUS_WORDS}
