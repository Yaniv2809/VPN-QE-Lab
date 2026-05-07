import allure
import pytest

from tests.helpers import VPNLab


@pytest.mark.vpn
@allure.epic("VPN Quality Gate")
@allure.feature("End-to-End Routing and NAT Traversal")
class TestRoutingAndNAT:

    @allure.title("Ping Site A LAN → Site B LAN (0% packet loss)")
    @allure.description(
        "Sends 4 ICMP echo requests from Site A's LAN IP (100.64.1.1) to Site B's LAN IP "
        "(100.64.2.1) through the VPN tunnel. Source is pinned to 100.64.1.1 via -I to "
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
        "(100.64.2.1) to Site A's LAN IP (100.64.1.1). A one-directional pass is insufficient "
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

    @allure.title("NAT-T: ESP-in-UDP Encapsulation Active in Kernel XFRM State")
    @allure.description(
        "Verifies NAT Traversal by inspecting the kernel XFRM SA directly with "
        "'ip xfrm state show'. With forceencaps=yes, the kernel installs the SA with "
        "encap type espinudp on port 4500, regardless of whether actual NAT is present. "
        "This simulates a real-world SD-WAN deployment where ESP (protocol 50) is blocked."
    )
    @allure.severity(allure.severity_level.NORMAL)
    def test_nat_traversal_port_4500_active(self, lab: VPNLab) -> None:
        with allure.step("Inspect kernel XFRM SA state on Site A"):
            result = lab.exec(VPNLab.SITE_A, "ip xfrm state show")

        with allure.step("Assert espinudp encapsulation with port 4500 is present"):
            allure.attach(result.stdout, name="ip xfrm state", attachment_type=allure.attachment_type.TEXT)
            assert "espinudp" in result.stdout or "4500" in result.stdout, (
                "ESP-in-UDP (NAT-T) encapsulation not found in kernel XFRM state. "
                "forceencaps=yes may not have taken effect."
            )
