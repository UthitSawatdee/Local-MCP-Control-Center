from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor


def test_policy_update_failure_leaves_history_access_disabled(broker, tmp_path, monkeypatch):
    home = tmp_path / "codex-home"
    home.mkdir()
    monkeypatch.setattr(broker, "set_tool_policy", lambda *_args, **_kwargs: {"status": "denied", "error_code": "TEST_FAILURE"})
    result = broker.configure_codex_threads(executable=sys.executable, codex_home=str(home))
    assert result["status"] == "denied"
    assert result["error_code"] == "CODEX_CONFIG_INVALID"
    assert broker.store.get_codex_thread_config() == {"enabled": False}


def test_parallel_first_access_reuses_one_reader_limit(broker):
    with ThreadPoolExecutor(max_workers=8) as executor:
        readers = list(executor.map(lambda _index: broker.codex_threads, range(32)))
    assert all(reader is readers[0] for reader in readers)
