"""Input and parameter validation utilities for SheXzTool."""

from __future__ import annotations
import ipaddress
import re
from pathlib import Path
from typing import List, Optional, Tuple, Union

HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


class Validator:
    """Comprehensive defensive validator for network targets, ports, and paths."""

    @staticmethod
    def is_valid_ip(address: str) -> bool:
        """Check if string is a valid IPv4 or IPv6 address."""
        if not address or not isinstance(address, str):
            return False
        try:
            ipaddress.ip_address(address.strip())
            return True
        except ValueError:
            return False

    @staticmethod
    def is_valid_hostname(hostname: str) -> bool:
        """Check if string is a valid RFC 1123 hostname."""
        if not hostname or not isinstance(hostname, str):
            return False
        hostname = hostname.strip()
        if len(hostname) > 253:
            return False
        # Disallow control characters or shell metacharacters
        if any(c in hostname for c in [";", "&", "|", "`", "$", "(", ")", "<", ">", "\n", "\r", " "]):
            return False
        return bool(HOSTNAME_REGEX.match(hostname))

    @classmethod
    def validate_target(cls, target: str) -> Tuple[bool, str]:
        """Validate an IP address or hostname. Returns (is_valid, sanitized_target)."""
        if not target:
            return False, ""
        target = target.strip()
        if cls.is_valid_ip(target):
            return True, target
        if cls.is_valid_hostname(target):
            return True, target
        return False, ""

    @staticmethod
    def is_valid_port(port: Union[int, str]) -> bool:
        """Check if a port number is in range 1-65535."""
        try:
            p = int(port)
            return 1 <= p <= 65535
        except (ValueError, TypeError):
            return False

    @classmethod
    def parse_port_specification(cls, port_spec: str, max_ports: int = 100) -> Tuple[List[int], Optional[str]]:
        """Parse comma-separated ports or ranges like '80,443,8000-8010'.

        Returns:
            Tuple of (sorted_unique_ports, error_message_if_any)
        """
        if not port_spec or not port_spec.strip():
            return [], "Port specification cannot be empty."

        ports: set[int] = set()
        parts = [p.strip() for p in port_spec.split(",") if p.strip()]

        for part in parts:
            if "-" in part:
                range_parts = part.split("-")
                if len(range_parts) != 2:
                    return [], f"Invalid port range format: '{part}'"
                try:
                    start = int(range_parts[0].strip())
                    end = int(range_parts[1].strip())
                except ValueError:
                    return [], f"Non-numeric port range: '{part}'"
                if not (1 <= start <= 65535 and 1 <= end <= 65535):
                    return [], f"Port numbers in range '{part}' must be between 1 and 65535"
                if start > end:
                    return [], f"Range start ({start}) cannot be greater than end ({end})"
                if (end - start + 1) + len(ports) > max_ports:
                    return [], f"Total ports requested exceeds safety limit of {max_ports} ports."
                for p in range(start, end + 1):
                    ports.add(p)
            else:
                try:
                    p = int(part)
                    if not (1 <= p <= 65535):
                        return [], f"Port {p} is outside valid range (1-65535)"
                    ports.add(p)
                except ValueError:
                    return [], f"Invalid port value: '{part}'"

            if len(ports) > max_ports:
                return [], f"Total ports requested exceeds safety limit of {max_ports} ports."

        if not ports:
            return [], "No valid ports specified."

        return sorted(list(ports)), None

    @staticmethod
    def validate_path_exists(path_str: str) -> Tuple[bool, Optional[Path], str]:
        """Validate if a local filesystem path exists and is accessible.

        Returns (is_valid, resolved_path, error_message).
        """
        if not path_str or not path_str.strip():
            return False, None, "Path cannot be empty."
        try:
            p = Path(path_str.strip()).resolve()
            if not p.exists():
                return False, None, f"Path does not exist: {p}"
            return True, p, ""
        except Exception as e:
            return False, None, f"Invalid path syntax: {e}"

    @staticmethod
    def sanitize_filename(filename: str) -> str:
        """Sanitize a string to be safely used as a filename."""
        sanitized = re.sub(r'[\\/*?:"<>|]', "_", filename)
        sanitized = re.sub(r"\s+", "_", sanitized)
        return sanitized.strip("._")
