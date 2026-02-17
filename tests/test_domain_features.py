from sentineldns.features.domain_features import shannon_entropy


def test_entropy_for_repeated_characters() -> None:
    assert shannon_entropy("aaaaaa") == 0.0


def test_entropy_for_binary_distribution() -> None:
    value = shannon_entropy("abab")
    assert abs(value - 1.0) < 1e-6
