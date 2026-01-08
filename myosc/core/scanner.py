"""Base scanner interface."""

from abc import ABC, abstractmethod

from myosc.core.models import Finding, ScanTarget


class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Scanner identifier."""
        ...

    @property
    @abstractmethod
    def version(self) -> str:
        """Scanner version."""
        ...

    @property
    @abstractmethod
    def supported_targets(self) -> list[str]:
        """List of supported target types."""
        ...

    @abstractmethod
    async def scan(self, target: ScanTarget) -> list[Finding]:
        """Execute scan on target.

        Args:
            target: Scan target (filesystem path, image name, etc.)

        Returns:
            List of findings
        """
        ...

    def supports(self, target: ScanTarget) -> bool:
        """Check if scanner supports the target type."""
        return target.target_type.value in self.supported_targets
