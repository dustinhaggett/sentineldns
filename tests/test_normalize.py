from sentineldns.data.normalize import normalize_domain


def test_normalize_domain_removes_www_and_trailing_dot() -> None:
    rec = normalize_domain("WWW.Example.com.")
    assert rec is not None
    assert rec.normalized_domain == "example.com"


def test_normalize_domain_handles_idna_ascii() -> None:
    rec = normalize_domain("bücher.de")
    assert rec is not None
    assert rec.normalized_domain == "xn--bcher-kva.de"


def test_normalize_domain_rejects_invalid() -> None:
    assert normalize_domain("not a domain value") is None
