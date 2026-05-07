import subprocess
import time

import pytest

from tests.helpers import VPNLab

TUNNEL_TIMEOUT = 90


@pytest.fixture(scope="session")
def lab() -> VPNLab:
    return VPNLab()


@pytest.fixture(scope="session", autouse=True)
def vpn_lab_session(lab: VPNLab) -> None:
    lab.compose("up", "-d", "--build")
    try:
        _await_tunnel(lab, timeout=TUNNEL_TIMEOUT)
        yield
    finally:
        lab.compose("down", "-v")


def _await_tunnel(lab: VPNLab, timeout: int) -> None:
    # Give strongSwan time to fully initialize, then trigger explicitly
    # in case auto=start did not fire inside the container.
    time.sleep(8)
    lab.exec(VPNLab.SITE_A, "ipsec up site-to-site", check=False, timeout=30)

    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            result = lab.exec(VPNLab.SITE_A, "ipsec status", check=False, timeout=10)
            if result.returncode == 0 and "ESTABLISHED" in result.stdout:
                _install_cross_site_routes(lab)
                return
        except (subprocess.SubprocessError, OSError):
            pass
        time.sleep(3)

    status = ""
    try:
        status = lab.exec(VPNLab.SITE_A, "ipsec statusall", check=False, timeout=10).stdout
    except (subprocess.SubprocessError, OSError):
        pass

    raise RuntimeError(
        f"VPN tunnel did not establish within {timeout}s.\n\nLast status:\n{status}"
    )


def _install_cross_site_routes(lab: VPNLab) -> None:
    """
    Ensures cross-site routes have the correct source IP set.
    strongSwan installs the routes, but we override src to match
    the leftsubnet/rightsubnet policy and avoid plaintext fallback.
    """
    lab.exec(
        VPNLab.SITE_A,
        f"ip route replace 100.64.2.0/24 via {VPNLab.SITE_B_WAN} src {VPNLab.SITE_A_LAN}",
        check=False,
    )
    lab.exec(
        VPNLab.SITE_B,
        f"ip route replace 100.64.1.0/24 via {VPNLab.SITE_A_WAN} src {VPNLab.SITE_B_LAN}",
        check=False,
    )
