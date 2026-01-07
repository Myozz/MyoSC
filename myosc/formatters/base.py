"""Base formatter interface."""

from abc import ABC, abstractmethod
from pathlib import Path

from myosc.core.models import ScanResult


class BaseFormatter(ABC):
    """Abstract base class for output formatters."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Formatter identifier."""
        ...

    @property
    @abstractmethod
    def file_extension(self) -> str:
        """Default file extension for output."""
        ...

    @abstractmethod
    def format(self, result: ScanResult) -> str:
        """Format scan result to string.

        Args:
            result: Scan result to format

        Returns:
            Formatted string
        """
        ...

    def write(self, result: ScanResult, path: Path) -> None:
        """Write formatted result to file.

        Args:
            result: Scan result to format
            path: Output file path
        """
        content = self.format(result)
        path.write_text(content, encoding="utf-8")
