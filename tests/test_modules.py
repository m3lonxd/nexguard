from nexguard import modules


def test_loader_skips_broken_module(env, monkeypatch, tmp_path):
    import sys
    pkg = tmp_path / "fakemods"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("")
    (pkg / "good.py").write_text(
        "from nexguard.modules import Module\nmodule = Module('g', 'Good', 'd', lambda: {'a': 1})\n")
    (pkg / "bad.py").write_text("raise RuntimeError('boom')\n")
    monkeypatch.syspath_prepend(str(tmp_path))
    monkeypatch.setattr(modules, "__path__", [str(pkg)])
    monkeypatch.setattr(modules, "__name__", "fakemods")
    found = modules.load_modules()
    assert [m.slug for m in found] == ["g"]
    sys.modules.pop("fakemods.good", None)


def test_group_events_collapses_repeats_and_localizes_time():
    from nexguard.app import group_events
    rows = [{"ts": "2026-11-02 09:07:20", "module": "core", "level": "info", "message": "Giriş: ömer ip=127.0.0.1"},
            {"ts": "2026-11-02 09:06:52", "module": "core", "level": "info", "message": "Giriş: ömer ip=127.0.0.1"},
            {"ts": "2026-11-02 08:55:35", "module": "core", "level": "warning", "message": "Başarısız giriş: ip=127.0.0.1"}]
    out = group_events(rows)
    assert [(e["count"], e["level"]) for e in out] == [(2, "info"), (1, "warning")]
    assert out[0]["ts"][2] == "." and ":" in out[0]["ts"]
