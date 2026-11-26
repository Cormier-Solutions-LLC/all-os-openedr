"""Versioned registry for operator-selected, locally installed plugins."""

from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, distribution
import re
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
        if plugin is None and ":" in name:
            plugin = self._installed_plugin(name)
        if plugin is None:
            raise ValueError(f"Unknown {kind} plugin: {name}")
        if (not isinstance(plugin, Plugin) or plugin.kind != kind
                or plugin.api_version != API_VERSION or not callable(plugin.factory)):
            raise ValueError(f"Incompatible {kind} plugin: {name}")
        return plugin.factory(**settings)

    @staticmethod
    def _installed_plugin(selector):
        package, name = selector.split(":", 1)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", package) or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", name):
            raise ValueError(f"Invalid plugin selector: {selector}")
        try:
            entries = distribution(package).entry_points.select(group="all_os_openedr.plugins", name=name)
            if len(entries) != 1:
                raise ValueError(f"Expected one entry point for plugin: {selector}")
            return next(iter(entries)).load()
        except (PackageNotFoundError, ImportError, AttributeError) as error:
            raise ValueError(f"Unable to load installed plugin: {selector}") from error
