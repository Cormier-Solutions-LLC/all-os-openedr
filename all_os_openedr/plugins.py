"""Versioned registry for operator-selected, locally installed plugins."""

from dataclasses import dataclass
from typing import Callable

API_VERSION = 1


@dataclass(frozen=True)
class Plugin:
    kind: str
    api_version: int
    factory: Callable


class Registry:
    def __init__(self, plugins):
        self._plugins = dict(plugins)

    def create(self, name, kind, **settings):
        plugin = self._plugins.get(name)
        if plugin is None:
            raise ValueError(f"Unknown {kind} plugin: {name}")
        if plugin.kind != kind or plugin.api_version != API_VERSION:
            raise ValueError(f"Incompatible {kind} plugin: {name}")
        return plugin.factory(**settings)
