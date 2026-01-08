"""Custom exceptions."""


class MyoscError(Exception):
    """Base exception for myosc."""

    pass


class ScanError(MyoscError):
    """Error during scanning."""

    pass


class ConfigError(MyoscError):
    """Configuration error."""

    pass


class DatabaseError(MyoscError):
    """Vulnerability database error."""

    pass


class RateLimitError(DatabaseError):
    """API rate limit exceeded."""

    pass
