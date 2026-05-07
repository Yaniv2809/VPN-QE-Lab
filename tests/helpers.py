import shlex
import subprocess
from pathlib import Path

COMPOSE_FILE = Path(__file__).parent.parent / "docker" / "docker-compose.yml"


class VPNLab:
    """Thin wrapper around the Docker CLI for orchestrating the VPN lab."""

    SITE_A = "vpn-site-a"
    SITE_B = "vpn-site-b"

    SITE_A_WAN = "192.168.200.10"
    SITE_B_WAN = "192.168.200.20"

    SITE_A_LAN = "192.168.201.1"
    SITE_B_LAN = "192.168.202.1"

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
    def compose(*args: str) -> None:
        """Run a docker compose command, printing output directly to stdout/stderr
        so CI logs capture the full Docker output on failure."""
        subprocess.run(
            ["docker", "compose", "-f", str(COMPOSE_FILE), *args],
            check=True,
        )
