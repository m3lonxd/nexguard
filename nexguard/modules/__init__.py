"""Modül yükleyici.

Her modül `nexguard/modules/<ad>.py` dosyasında `module` adlı bir `Module` örneği sunar.
Yükleyici bu dizini tarar; bozuk bir modül paneli düşürmez, hata olay günlüğüne yazılır.
"""
import importlib
import pkgutil
from dataclasses import dataclass, field
from typing import Callable

from .. import db


@dataclass
class Module:
    slug: str
    title: str
    description: str
    # collect() panelin gösterebileceği düz bir sözlük döndürür.
    collect: Callable[[], dict] = field(default=lambda: {})
    order: int = 100


def load_modules() -> list[Module]:
    found: list[Module] = []
    for info in pkgutil.iter_modules(__path__):
        try:
            mod = importlib.import_module(f"{__name__}.{info.name}")
            instance = getattr(mod, "module", None)
            if isinstance(instance, Module):
                found.append(instance)
        except Exception as exc:  # noqa: BLE001 - tek modül hatası paneli düşürmemeli
            db.log_event("core", "error", f"Modül yüklenemedi: {info.name}: {exc}")
    return sorted(found, key=lambda m: (m.order, m.slug))
