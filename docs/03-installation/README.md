# 03 — Installation guides

> Step-by-step reproducible deployment of the SOC lab on **Proxmox VE 9.1.7**.
> Each guide documents the exact commands that worked, the pitfalls encountered, and the validation checks performed.

## Prerequisites

| Item | Value |
|---|---|
| Hypervisor | Proxmox VE 9.1.7 (IM2AG node `ProxProf-rapacchd-326`) |
| Available resources | 24 GB RAM, 147 GB `local-lvm` thin pool (after extension) |
| Linux bridges | `vmbr0` mgmt, `vmbr1` WAN (NAT), `vmbr2-vmbr6` for VLANs 10/20/30/40/50 |
| Internet access | UGA campus + NAT through `vmbr1` |
| Admin access | Proxmox web UI + SSH on each VM |

The lab targets the **V1 scope** (no Active Directory, no Windows endpoints). VLAN 20 (Corporate) bridge exists but is unused; AD is documented as future work in the top-level README.

## Recommended deployment order

| # | Guide | Component | Time | Validates |
|---|---|---|---|---|
| 0 | [00-proxmox-host.md](00-proxmox-host.md) | Proxmox storage + bridges | 30 min | `lvs`, `brctl show` |
| 1 | [01-pfsense-firewall.md](01-pfsense-firewall.md) | pfSense CE 2.7.2 (VM 100) | 1 h | Web UI on each VLAN gateway |
| 2 | [02-wazuh-server.md](02-wazuh-server.md) | Wazuh AIO 4.14.5 (VM 101) | 1 h | `https://10.10.40.50` |
| 3 | [03-ubuntu-dmz.md](03-ubuntu-dmz.md) | Ubuntu DMZ + SSH multiport + Docker (VM 104) | 1 h | SSH on ports 2200 + 2222 |
| 4 | [04-dvwa.md](04-dvwa.md) | DVWA container | 15 min | `http://10.10.30.50` |
| 5 | [05-cowrie-honeypot.md](05-cowrie-honeypot.md) | Cowrie SSH honeypot on port 22 | 30 min | `ssh test@10.10.30.50` |
| 6 | [06-wazuh-agent-dmz.md](06-wazuh-agent-dmz.md) | Wazuh agent + Cowrie log ingestion | 30 min | Agent `Active` in dashboard |
| 7 | [07-suricata-pfsense.md](07-suricata-pfsense.md) | Suricata IDS on LAN + DMZ interfaces | 45 min | Alerts on Nmap from Kali |
| 8 | [08-kali-analyst-vms.md](08-kali-analyst-vms.md) | Kali (VM 103) + Analyst Desktop (VM 102) | 30 min | Reachability across VLANs |

After each major step, take a Proxmox snapshot — see the "Snapshots" section at the bottom of each guide.

## Final architecture (after step 7)

| VM | ID | IP | VLAN | OS | Role |
|---|---|---|---|---|---|
| pfSense-FW | 100 | gateways `.1` on every VLAN | all | pfSense CE 2.7.2 | Firewall + routing + **Suricata × 2 instances** |
| Wazuh-Server | 101 | 10.10.40.50 | 40 SOC | Ubuntu Server 24.04 | Wazuh Manager + Indexer + Dashboard |
| Analyst-Desktop | 102 | 10.10.50.50 | 50 Analyst | Ubuntu Desktop 24.04 | Investigation workstation |
| Kali-Attack | 103 | 10.10.10.51 | 10 Attack | Kali Linux 2025.3 | Purple Team attacker |
| Ubuntu-DMZ | 104 | 10.10.30.50 | 30 DMZ | Ubuntu Server 24.04 | DVWA (80) + Cowrie (22) + vulnerable SSH (2200) |

## Convention used across guides

- All shell snippets are tested on the actual VMs.
- A **"Pitfalls"** section is included whenever a real issue was hit during deployment — these are the parts most worth reading.
- A **"Validation"** section gives the exact command/UI check that proves the step succeeded.
- Credentials shown are lab-only and rotated before defense.

---

**Next:** [00-proxmox-host.md →](00-proxmox-host.md)
