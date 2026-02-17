from __future__ import annotations

from pathlib import Path

from sentineldns.data.live_monitor import (
    purge_old_rows_csv,
    redact_domain,
    should_exclude_domain,
)


def test_should_exclude_domain_by_pattern() -> None:
    assert should_exclude_domain("secure.bank.example", ["*.bank.*"])
    assert not should_exclude_domain("github.com", ["*.bank.*"])


def test_redact_domain_hash_deterministic() -> None:
    one = redact_domain("example.com", hash_domains=True, hash_salt="abc")
    two = redact_domain("example.com", hash_domains=True, hash_salt="abc")
    assert one == two
    assert one.startswith("sha256:")


def test_purge_old_rows_csv_keeps_recent(tmp_path: Path) -> None:
    path = tmp_path / "rows.csv"
    path.write_text(
        "ts,domain\n"
        "1999-01-01T00:00:00+00:00,old.example\n"
        "2099-01-01T00:00:00+00:00,new.example\n",
        encoding="utf-8",
    )
    purge_old_rows_csv(path, timestamp_col="ts", retention_days=14)
    rows = path.read_text(encoding="utf-8")
    assert "new.example" in rows
    assert "old.example" not in rows
