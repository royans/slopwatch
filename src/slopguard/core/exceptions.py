"""
Sentinel Exceptions.
"""


class SentinelError(Exception):
    """Base exception for all Sentinel errors."""
    pass


class ConfigurationError(SentinelError):
    """Raised when configuration is invalid or missing required keys."""
    pass


class BudgetExceededError(SentinelError):
    """Raised when LLM token usage approaches or exceeds cycle quota."""
    pass


class CRTQueryError(SentinelError):
    """Raised when crt.sh API query encounters an unrecoverable failure."""
    pass


class DNSError(SentinelError):
    """Raised when DNS resolution encounters an unexpected failure."""
    pass


class DormancyAssessmentError(SentinelError):
    """Raised when dormancy or DOM evaluation fails."""
    pass
