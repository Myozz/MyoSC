"""Custom exceptions."""


class myoscError(Exception):
    """Base exception for myosc."""

    pass


class ScanError(myoscError):
    """Error during scanning."""

    pass


class ConfigError(myoscError):
    """Configuration error."""

    pass


class DatabaseError(myoscError):
    """Vulnerability database error."""

    pass


class RateLimitError(DatabaseError):
    """API rate limit exceeded."""

    pass
