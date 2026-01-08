"""Scanner registry for plugin architecture."""

from collections.abc import Iterator

from myosc.core.models import ScanTarget
from myosc.core.scanner import BaseScanner


class ScannerRegistry:
    """Registry for managing scanner plugins."""

    def __init__(self) -> None:
        self._scanners: dict[str, BaseScanner] = {}

    def register(self, scanner: BaseScanner) -> None:
        """Register a scanner."""
        self._scanners[scanner.name] = scanner

    def unregister(self, name: str) -> None:
        """Unregister a scanner by name."""
        self._scanners.pop(name, None)

    def get(self, name: str) -> BaseScanner | None:
        """Get scanner by name."""
        return self._scanners.get(name)

    def get_for_target(self, target: ScanTarget) -> list[BaseScanner]:
        """Get all scanners that support the target type."""
        return [s for s in self._scanners.values() if s.supports(target)]

    def all(self) -> list[BaseScanner]:
        """Get all registered scanners."""
        return list(self._scanners.values())

    def __iter__(self) -> Iterator[BaseScanner]:
        return iter(self._scanners.values())

    def __len__(self) -> int:
        return len(self._scanners)


# Global registry instance
default_registry = ScannerRegistry()
