"""Custom exceptions for the application."""


class Khao2Error(Exception):
    """Base exception for all Khao2 errors."""
    pass


class ConfigurationError(Khao2Error):
    """Raised when configuration is missing or invalid."""
    pass


class APIError(Khao2Error):
    """Raised when API requests fail."""
    pass


class ValidationError(Khao2Error):
    """Raised when input validation fails."""
    pass


class InsufficientCreditsError(APIError):
    """Raised when user has no credits remaining."""
    pass


class UploadExpiredError(APIError):
    """Raised when presigned upload URL has expired."""
    pass
