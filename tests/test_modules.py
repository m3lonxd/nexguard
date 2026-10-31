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
