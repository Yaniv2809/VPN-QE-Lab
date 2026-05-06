import shlex
import subprocess
from pathlib import Path

COMPOSE_FILE = Path(__file__).parent.parent / "docker" / "docker-compose.yml"


class VPNLab:
    """Thin wrapper around the Docker CLI for orchestrating the VPN lab."""

    SITE_A = "vpn-site-a"
    SITE_B = "vpn-site-b"

    # WAN-facing IPs (used in traffic capture filters)
    SITE_A_WAN = "172.20.0.10"
    SITE_B_WAN = "172.20.0.20"

    # LAN IPs (source addresses for cross-site pings)
    SITE_A_LAN = "10.1.0.1"
    SITE_B_LAN = "10.2.0.1"

    @staticmethod
    def exec(
        container: str,
        command: str,
        check: bool = True,
        timeout: int = 30,
    ) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", "exec", container] + shlex.split(command),
            capture_output=True,
            text=True,
            check=check,
            timeout=timeout,
        )

    @staticmethod
    def compose(*args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
            capture_output=True,
            text=True,
            check=True,
        )
