"""Service for account-related operations (usage and audit logs)."""
from typing import Optional
from khao2.services.api_client import APIClient
from khao2.core.models import UsageData, AuditLogs


class AccountService:
    """Handles account-related operations including usage analytics and audit logs."""

    def __init__(self, api_client: APIClient):
        self.api_client = api_client

    def get_usage(self, start: Optional[str] = None, end: Optional[str] = None) -> UsageData:
        """
        Get usage analytics for date range.
        
        Args:
            start: Start date filter (optional, format: YYYY-MM-DD)
            end: End date filter (optional, format: YYYY-MM-DD)
            
        Returns:
            UsageData with usage periods containing total_scans and total_bytes_processed
        """
        return self.api_client.get_usage(start=start, end=end)

    def get_audit_logs(self, limit: int = 50, offset: int = 0) -> AuditLogs:
        """
        Get paginated audit logs.
        
        Args:
            limit: Maximum number of results (default: 50)
            offset: Number of results to skip (default: 0)
            
        Returns:
            AuditLogs with log entries containing action, resource_type, 
            resource_id, ip_address, and created_at
        """
        return self.api_client.get_audit_logs(limit=limit, offset=offset)
