import time

import pytest

from tests.helpers import VPNLab

TUNNEL_TIMEOUT = 60


@pytest.fixture(scope="session")
def lab() -> VPNLab:
    return VPNLab()


@pytest.fixture(scope="session", autouse=True)
def vpn_lab_session(lab: VPNLab) -> None:
    lab.compose("up", "-d", "--build")
    _await_tunnel(lab, timeout=TUNNEL_TIMEOUT)
    yield
    lab.compose("down", "-v")


def _await_tunnel(lab: VPNLab, timeout: int) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        result = lab.exec(VPNLab.SITE_A, "ipsec status", check=False)
        if result.returncode == 0 and "ESTABLISHED" in result.stdout:
            _install_cross_site_routes(lab)
            return
        time.sleep(3)

    status = lab.exec(VPNLab.SITE_A, "ipsec statusall", check=False).stdout
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
        f"ip route replace 10.2.0.0/24 via {VPNLab.SITE_B_WAN} src {VPNLab.SITE_A_LAN}",
        check=False,
    )
    lab.exec(
        VPNLab.SITE_B,
        f"ip route replace 10.1.0.0/24 via {VPNLab.SITE_A_WAN} src {VPNLab.SITE_B_LAN}",
        check=False,
    )
