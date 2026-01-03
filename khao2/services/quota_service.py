"""Service for quota-related operations."""
from typing import Tuple
from khao2.services.api_client import APIClient
from khao2.core.models import QuotaInfo
from khao2.core.exceptions import APIError


class QuotaService:
    """Handles quota-related operations."""

    DEFAULT_LOW_CREDIT_THRESHOLD = 5

    def __init__(self, api_client: APIClient):
        self.api_client = api_client

    def get_quota(self) -> QuotaInfo:
        """
        Retrieve current quota information.
        
        Returns:
            QuotaInfo with monthly_limit, used, remaining, period_end, tier
        """
        return self.api_client.get_quota()

    def check_can_scan(self) -> Tuple[bool, str]:
        """
        Check if user can perform a scan.
        
        Returns:
            Tuple of (can_scan, message):
            - (True, "") if user has sufficient credits
            - (True, warning_message) if user has low credits (1-5)
            - (False, error_message) if user has zero credits
        """
        try:
            quota = self.get_quota()
            
            if quota.remaining <= 0:
                return (False, "No credits remaining. Please add credits to continue.")
            
            if quota.remaining <= self.DEFAULT_LOW_CREDIT_THRESHOLD:
                return (True, f"Warning: Only {quota.remaining} credit(s) remaining.")
            
            return (True, "")
        except APIError as e:
            # Fail-open: if we can't check quota, allow the scan but warn
            return (True, f"Warning: Could not verify quota. {str(e)}")

    def is_low_credits(self, threshold: int = 5) -> bool:
        """
        Check if credits are below threshold.
        
        Args:
            threshold: Credit threshold to check against (default: 5)
            
        Returns:
            True if remaining credits are at or below threshold
        """
        try:
            quota = self.get_quota()
            return quota.remaining <= threshold
        except APIError:
            # If we can't check, assume not low to avoid false warnings
            return False
