import allure
import pytest

from tests.helpers import VPNLab


@pytest.mark.vpn
@allure.epic("VPN Quality Gate")
@allure.feature("End-to-End Routing and NAT Traversal")
class TestRoutingAndNAT:

    @allure.title("Ping Site A LAN → Site B LAN (0% packet loss)")
    @allure.description(
        "Sends 4 ICMP echo requests from Site A's LAN IP (192.168.201.1) to Site B's LAN IP "
        "(192.168.202.1) through the VPN tunnel. Source is pinned to 192.168.201.1 via -I to "
        "match the leftsubnet policy and trigger XFRM encryption."
    )
    @allure.severity(allure.severity_level.CRITICAL)
    def test_ping_site_a_to_b(self, lab: VPNLab) -> None:
        with allure.step(f"Ping {VPNLab.SITE_B_LAN} from {VPNLab.SITE_A_LAN}"):
            result = lab.exec(
                VPNLab.SITE_A,
                f"ping -c 4 -W 2 -I {VPNLab.SITE_A_LAN} {VPNLab.SITE_B_LAN}",
                timeout=20,
            )

        with allure.step("Assert 0% packet loss"):
            allure.attach(result.stdout, name="ping output", attachment_type=allure.attachment_type.TEXT)
            assert result.returncode == 0, f"Ping failed with exit code {result.returncode}"
            assert "0% packet loss" in result.stdout

    @allure.title("Ping Site B LAN → Site A LAN (bidirectional validation)")
    @allure.description(
        "Validates the reverse direction: 4 ICMP echo requests from Site B's LAN IP "
        "(192.168.202.1) to Site A's LAN IP (192.168.201.1). A one-directional pass is insufficient "
        "evidence of a healthy tunnel — both directions must work."
    )
    @allure.severity(allure.severity_level.CRITICAL)
    def test_ping_site_b_to_a(self, lab: VPNLab) -> None:
        with allure.step(f"Ping {VPNLab.SITE_A_LAN} from {VPNLab.SITE_B_LAN}"):
            result = lab.exec(
                VPNLab.SITE_B,
                f"ping -c 4 -W 2 -I {VPNLab.SITE_B_LAN} {VPNLab.SITE_A_LAN}",
                timeout=20,
            )

        with allure.step("Assert 0% packet loss"):
            allure.attach(result.stdout, name="ping output", attachment_type=allure.attachment_type.TEXT)
            assert result.returncode == 0, f"Ping failed with exit code {result.returncode}"
            assert "0% packet loss" in result.stdout

    @allure.title("NAT-T: Tunnel Negotiated Over UDP Port 4500")
    @allure.description(
        "Asserts that the IKE SA is using UDP port 4500 encapsulation (NAT Traversal), "
        "as forced by forceencaps=yes in ipsec.conf. This simulates a real-world SD-WAN "
        "deployment where sites are behind NAT and ESP (protocol 50) is blocked."
    )
    @allure.severity(allure.severity_level.NORMAL)
    def test_nat_traversal_port_4500_active(self, lab: VPNLab) -> None:
        with allure.step("Run 'ipsec statusall' on Site A"):
            result = lab.exec(VPNLab.SITE_A, "ipsec statusall")

        with allure.step("Assert UDP port 4500 is referenced in the SA"):
            allure.attach(result.stdout, name="ipsec statusall", attachment_type=allure.attachment_type.TEXT)
            assert "4500" in result.stdout, (
                "Port 4500 (NAT-T) not found in tunnel status. "
                "forceencaps=yes may not have taken effect."
            )
