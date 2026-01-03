"""Keyboard input handling for watch mode."""
import sys
import os

# Platform-specific imports for non-blocking keyboard input
if os.name == 'nt':
    import msvcrt
else:
    import select
    import termios
    import tty


class KeybindHandler:
    """Handles keyboard input during watch mode polling."""
    
    KEYBIND_HINTS = "K+A: Abort scan | K+B: Exit client | Ctrl+C: Hard abort"
    
    def __init__(self, scan_id: str, api_client, is_dig_mode: bool = False):
        """
        Initialize keybind handler.
        
        Args:
            scan_id: The scan ID being watched
            api_client: APIClient instance for abort requests
            is_dig_mode: True if in dig --watch mode (Ctrl+C aborts server)
        """
        self.scan_id = scan_id
        self.api_client = api_client
        self.is_dig_mode = is_dig_mode
        self._k_pressed = False
        self._should_exit = False
        self._abort_requested = False
    
    def check_input(self) -> tuple:
        """
        Check for keyboard input (non-blocking).
        
        Returns:
            tuple: (should_exit, should_abort)
        """
        key = self._get_key()
        
        if key is None:
            return (self._should_exit, self._abort_requested)
        
        key_lower = key.lower() if isinstance(key, str) else key
        
        if self._k_pressed:
            if key_lower == 'a':
                # K+A: Abort scan on server and exit
                self._abort_requested = True
                self._should_exit = True
            elif key_lower == 'b':
                # K+B: Exit client only
                self._should_exit = True
            # Reset K state after any key following K
            self._k_pressed = False
        elif key_lower == 'k':
            self._k_pressed = True
        else:
            # Any other key resets K state
            self._k_pressed = False
        
        return (self._should_exit, self._abort_requested)
    
    def handle_interrupt(self) -> None:
        """
        Handle Ctrl+C interrupt.
        In dig mode: abort on server and exit.
        In get mode: exit client only (no server abort).
        """
        self._should_exit = True
        if self.is_dig_mode:
            self._abort_requested = True
    
    def get_keybind_hints(self) -> str:
        """Return the keybind hints string for display."""
        return self.KEYBIND_HINTS
    
    def _get_key(self) -> str:
        """
        Get a key press without blocking.
        
        Returns:
            str or None: The key pressed, or None if no key available
        """
        if os.name == 'nt':
            return self._get_key_windows()
        else:
            return self._get_key_unix()
    
    def _get_key_windows(self) -> str:
        """Get key press on Windows (non-blocking)."""
        if msvcrt.kbhit():
            return msvcrt.getch().decode('utf-8', errors='ignore')
        return None
    
    def _get_key_unix(self) -> str:
        """Get key press on Unix/Linux/Mac (non-blocking)."""
        if not sys.stdin.isatty():
            return None
        
        old_settings = termios.tcgetattr(sys.stdin)
        try:
            tty.setcbreak(sys.stdin.fileno())
            rlist, _, _ = select.select([sys.stdin], [], [], 0)
            if rlist:
                return sys.stdin.read(1)
            return None
        except Exception:
            return None
        finally:
            termios.tcsetattr(sys.stdin, termios.TCSADRAIN, old_settings)
    
    @property
    def should_exit(self) -> bool:
        """Check if exit has been requested."""
        return self._should_exit
    
    @property
    def abort_requested(self) -> bool:
        """Check if abort has been requested."""
        return self._abort_requested
