"""Formatting utilities for display."""


def format_time(ms: int) -> str:
    """Format milliseconds to human-readable time."""
    seconds = ms / 1000
    if seconds < 60:
        return f"{int(seconds)}s"
    minutes = int(seconds / 60)
    secs = int(seconds % 60)
    return f"{minutes}m {secs}s"


def format_number(num: int) -> str:
    """Format large numbers with K/M/B suffixes."""
    if num >= 1_000_000_000:
        return f"{num / 1_000_000_000:.2f}B"
    elif num >= 1_000_000:
        return f"{num / 1_000_000:.2f}M"
    elif num >= 1_000:
        return f"{num / 1_000:.2f}K"
    return str(num)


def create_progress_bar(completed: int, total: int, width: int = 40) -> str:
    """Create a text-based progress bar."""
    if total == 0:
        return "░" * width

    percentage = completed / total
    filled = int(width * percentage)
    bar = "█" * filled + "░" * (width - filled)
    return bar
