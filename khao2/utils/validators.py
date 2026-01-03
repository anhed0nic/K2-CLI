"""Input validation utilities."""
from khao2.core.exceptions import ValidationError


def validate_token(token: str) -> None:
    """Validate API token format."""

    suffix = token[3:]
    if len(suffix) != 32 or not suffix.islower() or not suffix.isalnum():
        raise ValidationError(
            "Token suffix must be 32 lowercase alphanumeric characters"
        )


def validate_endpoint(endpoint: str) -> None:
    """Validate API endpoint format."""
    if not (endpoint.startswith('http://') or endpoint.startswith('https://')):
        raise ValidationError(
            f"Invalid endpoint URL: {endpoint}. Must start with http:// or https://"
        )
