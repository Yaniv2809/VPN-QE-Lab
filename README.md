# VPN-QE-Lab

**Site-to-Site VPN Quality Gate — Docker + strongSwan + pytest**

A self-contained testing laboratory that spins up two IPSec VPN gateways in Docker, establishes a tunnel between them, and runs an automated quality gate against it: tunnel establishment, end-to-end routing, traffic encryption, and NAT Traversal.

---

## Network Topology

```
+----------------------------------------------------------------+
|                      WAN (100.64.0.0/24)                       |
|                                                                 |
|  +----------------+   IPSec Tunnel (UDP 4500)  +---------------+|
|  |  vpn-site-a    |<-------------------------->|  vpn-site-b   ||
|  |  100.64.0.10   |                            |  100.64.0.20  ||
|  +-------+--------+                            +-------+-------+|
+----------+-------------------------------------------------+----+
           |                                             |
    LAN-A (100.64.1.0/24)                    LAN-B (100.64.2.0/24)
     Site A: 100.64.1.1                        Site B: 100.64.2.1
```

All cross-site traffic (100.64.1.x <-> 100.64.2.x) is encrypted inside the tunnel. The WAN interface only carries UDP port 4500 (NAT-T encapsulated ESP) — zero plaintext payload.

---

## IPSec Concepts

### IKE Phase 1 — `IKE_SA_INIT` + `IKE_AUTH`

Phase 1 establishes the **IKE Security Association (SA)** — a secure, authenticated channel used to negotiate everything else.

| Step | Message | Purpose |
|---|---|---|
| 1 | `IKE_SA_INIT` (→) | Propose algorithms, DH key exchange, nonce |
| 2 | `IKE_SA_INIT` (←) | Accept proposals, respond with DH public key |
| 3 | `IKE_AUTH` (→) | Authenticate with PSK/certificate, propose Child SA |
| 4 | `IKE_AUTH` (←) | Confirm authentication, create Child SA |

When complete, both sides have a shared symmetric key derived via Diffie-Hellman. The result is `ESTABLISHED` in `ipsec statusall`.

**Algorithms used in this lab:** AES-256-CBC / HMAC-SHA-256 / MODP-2048

### IKE Phase 2 — Child SA (ESP)

Phase 2 creates the actual **IPSec Child SA** — the tunnel that encrypts traffic.

- The kernel installs **XFRM policies**: any packet matching `src 100.64.1.0/24 -> dst 100.64.2.0/24` is handed to the ESP engine.
- ESP wraps each IP packet: `[IP][UDP:4500][ESP header][encrypted original packet][ESP trailer]`.
- The result is `INSTALLED` in `ipsec statusall`.

### NAT Traversal (NAT-T)

Standard ESP (IP protocol 50) cannot cross a NAT device because NAT rewrites the IP header but leaves no port to track the session. NAT-T solves this by wrapping ESP packets inside UDP port 4500.

This lab sets `forceencaps=yes` in `ipsec.conf`, which activates NAT-T encapsulation unconditionally — simulating a real-world SD-WAN deployment where sites sit behind NAT.

---

## Prerequisites

- Docker Desktop (or Docker Engine + Compose v2)
- Python 3.10+
- Linux host or WSL2 (IPSec uses Linux kernel XFRM — requires a Linux kernel)

> **Windows note**: Run inside WSL2. Docker Desktop with WSL2 backend works correctly.

---

## Quick Start

```bash
git clone https://github.com/your-username/VPN-QE-Lab.git
cd VPN-QE-Lab

python -m venv venv
source venv/bin/activate

pip install -r requirements.txt
pytest tests/ -v
```

pytest will:
1. Build the Docker images for site-a and site-b
2. Start both containers (`docker compose up -d`)
3. Wait up to 90 seconds for the tunnel to reach `ESTABLISHED`
4. Run all 9 test cases
5. Tear down and remove containers + volumes (`docker compose down -v`)

### With Allure report

```bash
pytest tests/ -v --alluredir=allure-results
allure serve allure-results
```

### Manual lab start (for exploration)

```bash
docker compose -f docker/docker-compose.yml up -d --build

# Check tunnel status
docker exec vpn-site-a ipsec statusall

# Ping across the tunnel
docker exec vpn-site-a ping -c 4 -I 100.64.1.1 100.64.2.1

# Live capture on WAN interface
docker exec vpn-site-a tcpdump -i any -n udp port 4500

# Tear down
docker compose -f docker/docker-compose.yml down -v
```

---

## Test Cases

### `test_vpn_establishment.py` — IKE Phase 1 & 2

| Test | Asserts |
|---|---|
| `test_ike_phase1_established` | `ipsec statusall` on Site A contains `ESTABLISHED` |
| `test_ike_phase2_child_sa_installed` | `ipsec statusall` contains `INSTALLED` (Child SA in XFRM) |
| `test_both_sites_see_established_tunnel` | Both gateways independently report `ESTABLISHED` |
| `test_correct_subnets_in_tunnel` | Traffic selectors in the SA match `100.64.1.0/24` <-> `100.64.2.0/24` |

### `test_routing_and_nat.py` — Routing + NAT-T

| Test | Asserts |
|---|---|
| `test_ping_site_a_to_b` | `ping -I 100.64.1.1 100.64.2.1` exits 0, output contains `0% packet loss` |
| `test_ping_site_b_to_a` | Reverse direction: `ping -I 100.64.2.1 100.64.1.1` also passes |
| `test_nat_traversal_port_4500_active` | `ipsec statusall` references port `4500` (NAT-T active) |

### `test_traffic_encryption.py` — ESP Verification

| Test | Asserts |
|---|---|
| `test_natt_encapsulated_traffic_on_wan` | UDP port 4500 packets are captured on WAN during cross-site ping |
| `test_no_plaintext_icmp_between_wan_ips` | **Zero** plaintext ICMP between 100.64.0.10 <-> 100.64.0.20 — payload is encrypted |

The encryption tests use `tcpdump` inside the containers via a background thread, concurrent with the ping that generates traffic.

---

## Configuration Reference

### `ipsec.conf` key settings

| Option | Value | Meaning |
|---|---|---|
| `keyexchange` | `ikev2` | Use IKEv2 (modern, recommended) |
| `authby` | `secret` | Pre-Shared Key authentication |
| `ike` | `aes256-sha256-modp2048!` | Phase 1 cipher suite (`!` = exact match) |
| `esp` | `aes256-sha256!` | Phase 2 (ESP) cipher suite |
| `forceencaps` | `yes` | Force NAT-T / UDP-4500 encapsulation |
| `auto` | `start` / `add` | Site A initiates; Site B responds |
| `dpdaction` | `restart` | Dead Peer Detection: restart tunnel if peer is unresponsive |

### Network addresses

| Variable | Value | Role |
|---|---|---|
| `SITE_A_WAN` | `100.64.0.10` | Site A WAN/tunnel endpoint |
| `SITE_B_WAN` | `100.64.0.20` | Site B WAN/tunnel endpoint |
| `SITE_A_LAN` | `100.64.1.1` | Site A LAN gateway (IPSec traffic selector) |
| `SITE_B_LAN` | `100.64.2.1` | Site B LAN gateway (IPSec traffic selector) |

---

## Project Structure

```
VPN-QE-Lab/
+-- docker/
|   +-- docker-compose.yml          # 3 networks (wan, lan-a, lan-b) + 2 services
|   +-- site-a/
|   |   +-- Dockerfile              # Alpine + strongSwan + iputils + tcpdump
|   |   +-- ipsec.conf              # IKEv2 config, forceencaps=yes, auto=start
|   |   +-- ipsec.secrets           # PSK
|   |   +-- entrypoint.sh           # ip_forward + exec ipsec start --nofork
|   +-- site-b/
|       +-- Dockerfile
|       +-- ipsec.conf              # Mirror of site-a with left/right swapped, auto=add
|       +-- ipsec.secrets
|       +-- entrypoint.sh
+-- tests/
|   +-- helpers.py                  # VPNLab class (docker exec / compose wrappers)
|   +-- conftest.py                 # Session fixture: up -> wait for ESTABLISHED -> yield -> down
|   +-- test_vpn_establishment.py   # 4 tests — IKE Phase 1 & 2
|   +-- test_routing_and_nat.py     # 3 tests — ping + NAT-T
|   +-- test_traffic_encryption.py  # 2 tests — ESP capture + no ICMP leak
+-- .github/workflows/ci.yml
+-- requirements.txt
+-- pytest.ini
+-- README.md
```

---

## CI/CD

GitHub Actions runs on every push and pull request:

1. Builds both Docker images fresh from source
2. Runs `pytest tests/ -v` (conftest handles `compose up/down`)
3. Uploads Allure results as a build artifact
4. Always runs `docker compose down -v` to clean up, even on failure

See `.github/workflows/ci.yml`.
