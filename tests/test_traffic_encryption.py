import re
import subprocess
import threading
import time

import allure
import pytest

from tests.helpers import VPNLab

_TIMESTAMP_RE = re.compile(r"^\d{2}:\d{2}:\d{2}")


def _capture_packets(container: str, tcpdump_filter: str, count: int = 10, wait: int = 8) -> list[str]:
    """
    Runs tcpdump inside *container* for up to *wait* seconds (or until *count* packets).
    Returns stdout lines that start with a packet timestamp.
    """
    result = subprocess.run(
        [
            "docker", "exec", container,
            "timeout", str(wait),
            "tcpdump", "-i", "any", "-n", "-c", str(count), tcpdump_filter,
        ],
        capture_output=True,
        text=True,
    )
    return [line for line in result.stdout.splitlines() if _TIMESTAMP_RE.match(line)]


def _trigger_cross_site_traffic(lab: VPNLab) -> None:
    lab.exec(
        VPNLab.SITE_A,
        f"ping -c 5 -W 2 -I {VPNLab.SITE_A_LAN} {VPNLab.SITE_B_LAN}",
        check=False,
        timeout=20,
    )


@pytest.mark.vpn
@allure.epic("VPN Quality Gate")
@allure.feature("Traffic Encryption — ESP / NAT-T")
class TestTrafficEncryption:

    @allure.title("UDP Port 4500 (NAT-T / ESP-in-UDP) Traffic Present on WAN During Cross-Site Ping")
    @allure.description(
        "Captures packets on the WAN interface while pinging across sites. "
        "Asserts that UDP port 4500 packets are observed, confirming the ICMP "
        "payload is wrapped inside the ESP-in-UDP (NAT-T) envelope."
    )
    @allure.severity(allure.severity_level.CRITICAL)
    def test_natt_encapsulated_traffic_on_wan(self, lab: VPNLab) -> None:
        packet_lines: list[str] = []

        def capture() -> None:
            packet_lines.extend(
                _capture_packets(VPNLab.SITE_A, "udp port 4500", count=10, wait=8)
            )

        t = threading.Thread(target=capture, daemon=True)
        t.start()
        time.sleep(0.5)

        with allure.step("Generate cross-site ICMP traffic"):
            _trigger_cross_site_traffic(lab)

        t.join(timeout=15)

        with allure.step("Assert UDP 4500 packets were captured on WAN"):
            allure.attach(
                "\n".join(packet_lines) or "(no output)",
                name="tcpdump — udp port 4500",
                attachment_type=allure.attachment_type.TEXT,
            )
            assert len(packet_lines) > 0, (
                "No UDP 4500 (NAT-T) packets captured during cross-site traffic. "
                "VPN may be down or forceencaps=yes did not take effect."
            )

    @allure.title("No Plaintext ICMP Visible Between WAN IPs During Cross-Site Ping")
    @allure.description(
        "The critical encryption test: captures ICMP packets between the two WAN IPs "
        "(192.168.200.10 ↔ 192.168.200.20) while pinging. If the VPN is working correctly, "
        "zero ICMP packets should appear — all payload is encrypted inside UDP 4500. "
        "Any ICMP hit here is a security violation (traffic leak)."
    )
    @allure.severity(allure.severity_level.BLOCKER)
    def test_no_plaintext_icmp_between_wan_ips(self, lab: VPNLab) -> None:
        packet_lines: list[str] = []

        wan_icmp_filter = (
            f"icmp and (host {VPNLab.SITE_A_WAN} or host {VPNLab.SITE_B_WAN})"
        )

        def capture() -> None:
            packet_lines.extend(
                _capture_packets(VPNLab.SITE_A, wan_icmp_filter, count=5, wait=8)
            )

        t = threading.Thread(target=capture, daemon=True)
        t.start()
        time.sleep(0.5)

        with allure.step("Generate cross-site ICMP traffic"):
            _trigger_cross_site_traffic(lab)

        t.join(timeout=15)

        with allure.step("Assert zero plaintext ICMP between WAN endpoints"):
            allure.attach(
                "\n".join(packet_lines) if packet_lines else "(empty — PASS)",
                name="tcpdump — plaintext ICMP",
                attachment_type=allure.attachment_type.TEXT,
            )
            assert len(packet_lines) == 0, (
                "SECURITY VIOLATION: Plaintext ICMP detected between WAN IPs!\n"
                "The VPN tunnel is not encrypting traffic correctly.\n\n"
                + "\n".join(packet_lines)
            )
