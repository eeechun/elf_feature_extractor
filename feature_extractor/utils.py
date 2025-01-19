import shutil
import subprocess
from typing import Tuple

def check_timeout_command(timeout_seconds: int, test_cmd: str = "sleep 1") -> bool:
    """
    Test if the timeout command is available and working.

    Args:
        timeout_seconds: Number of seconds for timeout
        test_cmd: Command to test timeout with

    Returns:
        bool: True if timeout command is available and working
    """
    try:
        timeout_path = shutil.which("timeout")
        if not timeout_path:
            return False

        # Test timeout command
        subprocess.run(
            ["timeout", "--kill-after=1", str(timeout_seconds), "sleep", "0.1"],
            check=True,
            capture_output=True
        )
        return True
    except (subprocess.SubprocessError, OSError):
        return False

def check_r2_availability() -> bool:
    """
    Check if radare2 is installed and accessible.

    Returns:
        bool: True if radare2 is available
    """
    try:
        subprocess.run(["r2", "-v"], check=True, capture_output=True)
        return True
    except (subprocess.SubprocessError, OSError):
        return False

def check_dependencies() -> Tuple[bool, str]:
    """
    Check if all required system dependencies are available.

    Returns:
        Tuple[bool, str]: (True if all dependencies are available, status message)
    """
    messages = []
    all_deps_available = True

    # Check timeout command
    if not check_timeout_command(1):
        messages.append("'timeout' command not found. Please install coreutils package.")
        all_deps_available = False

    # Check radare2
    if not check_r2_availability():
        messages.append("radare2 (r2) not found. Please install radare2.")
        all_deps_available = False

    status_message = "\n".join(messages) if messages else "All dependencies available"
    return all_deps_available, status_message

def check_r2_timeout(path_file: str, timeout_seconds: int) -> bool:
    """
    Check if r2pipe analysis will timeout for a given file.
    Python implementation of the shell script functionality.

    Args:
        path_file: Path to the file to check
        timeout_seconds: Timeout duration in seconds

    Returns:
        bool: True if analysis will timeout, False otherwise
    """
    try:
        # Verify timeout command availability
        if not check_timeout_command(timeout_seconds):
            raise RuntimeError("'timeout' command not available")

        # Run r2 analysis with timeout
        subprocess.run(
            [
                "timeout",
                "--kill-after=10",
                str(timeout_seconds),
                "r2",
                "-qc",
                "aaa",
                path_file
            ],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        return False  # No timeout occurred
    except subprocess.SubprocessError:
        return True  # Timeout or error occurred