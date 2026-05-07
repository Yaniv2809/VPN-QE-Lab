import allure
import pytest

from tests.helpers import VPNLab


@pytest.mark.vpn
@allure.epic("VPN Quality Gate")
@allure.feature("Tunnel Establishment — IKE Phase 1 & 2")
class TestVPNEstablishment:

    @allure.title("IKE Phase 1 — SA Reaches ESTABLISHED State")
    @allure.description(
        "Queries 'ipsec statusall' on Site A and asserts the IKE SA completed "
        "the two-message IKEv2 exchange (IKE_SA_INIT + IKE_AUTH) and reached ESTABLISHED."
    )
    @allure.severity(allure.severity_level.BLOCKER)
    def test_ike_phase1_established(self, lab: VPNLab) -> None:
        with allure.step("Run 'ipsec statusall' on Site A"):
            result = lab.exec(VPNLab.SITE_A, "ipsec statusall")

        with allure.step("Assert ESTABLISHED keyword is present"):
            allure.attach(
                result.stdout, name="ipsec statusall", attachment_type=allure.attachment_type.TEXT
            )
            assert "ESTABLISHED" in result.stdout, (
                "IKE Phase 1 SA not established. Full output attached."
            )

    @allure.title("IKE Phase 2 — Child SA (ESP) is INSTALLED in Kernel")
    @allure.description(
        "Verifies the IPSec Child SA (ESP) was successfully negotiated and "
        "INSTALLED into the Linux XFRM database, meaning packets will be encrypted."
    )
    @allure.severity(allure.severity_level.BLOCKER)
    def test_ike_phase2_child_sa_installed(self, lab: VPNLab) -> None:
        with allure.step("Run 'ipsec statusall' on Site A"):
            result = lab.exec(VPNLab.SITE_A, "ipsec statusall")

        with allure.step("Assert INSTALLED keyword is present"):
            assert "INSTALLED" in result.stdout, (
                "IKE Phase 2 Child SA not installed. Full output attached."
            )

    @allure.title("Both Sites Independently Confirm ESTABLISHED Tunnel")
    @allure.description(
        "Validates symmetry: queries each gateway separately and asserts both "
        "report the IKE SA as ESTABLISHED. A one-sided ESTABLISHED is a misconfiguration indicator."
    )
    @allure.severity(allure.severity_level.CRITICAL)
    def test_both_sites_see_established_tunnel(self, lab: VPNLab) -> None:
        with allure.step("Query Site A"):
            result_a = lab.exec(VPNLab.SITE_A, "ipsec status")
        with allure.step("Query Site B"):
            result_b = lab.exec(VPNLab.SITE_B, "ipsec status")

        with allure.step("Assert ESTABLISHED on both sides"):
            allure.attach(result_a.stdout, name="Site A status", attachment_type=allure.attachment_type.TEXT)
            allure.attach(result_b.stdout, name="Site B status", attachment_type=allure.attachment_type.TEXT)
            assert "ESTABLISHED" in result_a.stdout, "Site A does not see an established tunnel"
            assert "ESTABLISHED" in result_b.stdout, "Site B does not see an established tunnel"

    @allure.title("Tunnel Covers the Correct Subnets (192.168.201.0/24 ↔ 192.168.202.0/24)")
    @allure.description(
        "Confirms the negotiated traffic selectors match the intended subnets. "
        "A wrong selector means the tunnel exists but protects the wrong traffic."
    )
    @allure.severity(allure.severity_level.CRITICAL)
    def test_correct_subnets_in_tunnel(self, lab: VPNLab) -> None:
        with allure.step("Run 'ipsec statusall' on Site A"):
            result = lab.exec(VPNLab.SITE_A, "ipsec statusall")

        with allure.step("Assert both subnets appear in the SA output"):
            assert "192.168.201.0/24" in result.stdout
            assert "192.168.202.0/24" in result.stdout
