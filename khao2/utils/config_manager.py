"""Configuration management utilities."""
import struct
from pathlib import Path
from typing import Dict, Optional


class ConfigManager:
    """Manages application configuration storage."""

    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path.home() / ".khao2"
        self.config_file = self.config_dir / "forensicwaffle"

    def _ensure_config_dir(self):
        """Ensure configuration directory exists."""
        self.config_dir.mkdir(exist_ok=True)

    def save(self, token: Optional[str] = None, endpoint: Optional[str] = None):
        """Save configuration to disk."""
        self._ensure_config_dir()

        current = self.load()
        if token is not None:
            current['token'] = token
        if endpoint is not None:
            current['endpoint'] = endpoint

        token_bytes = current['token'].encode('utf-8') if current['token'] else b''
        endpoint_bytes = current['endpoint'].encode('utf-8') if current['endpoint'] else b''

        with open(self.config_file, 'wb') as f:
            f.write(struct.pack('I', len(token_bytes)))
            f.write(token_bytes)
            f.write(struct.pack('I', len(endpoint_bytes)))
            f.write(endpoint_bytes)

    def load(self) -> Dict[str, Optional[str]]:
        """Load configuration from disk."""
        if not self.config_file.exists():
            return {'token': None, 'endpoint': None}

        try:
            with open(self.config_file, 'rb') as f:
                token_len = struct.unpack('I', f.read(4))[0]
                token = f.read(token_len).decode('utf-8') if token_len > 0 else None

                endpoint_len = struct.unpack('I', f.read(4))[0]
                endpoint = f.read(endpoint_len).decode('utf-8') if endpoint_len > 0 else None

            return {'token': token, 'endpoint': endpoint}
        except Exception:
            return {'token': None, 'endpoint': None}
