# 08 — Kali attacker + Analyst desktop

> Two endpoint VMs that round out the Purple Team setup: Kali on VLAN 10 to launch the attacks, Ubuntu Desktop on VLAN 50 to investigate them.

## Kali-Attack (VM 103)

### Specs

| Setting | Value |
|---|---|
| VM ID | 103 |
| Name | Kali-Attack |
| BIOS | OVMF (UEFI) + EFI disk |
| CPU | 2 cores, type `host` |
| RAM | 4 GB |
| Disk | 25 GB on `local-lvm` |
| NIC | VirtIO on `vmbr2` (VLAN 10 Attack) |
| ISO | `kali-linux-2025.3-installer-amd64.iso` |
| Static IP | `10.10.10.51/24`, gateway `10.10.10.1`, DNS `10.10.10.1` |

### Install

Default Kali installer — accept defaults except:

- Set a static IP (or set it post-install via `nmtui` / `/etc/network/interfaces`)
- Pick the `xfce` desktop (lighter than GNOME, fine for the lab)
- Skip the Kali metapackage if you want to save disk — `kali-tools-top10` is enough for V1

### Tools required for the V1 scenarios

The default Kali install already includes everything we need, but verify:

```bash
which nmap                # scenario 01 (recon)
which sshpass             # scenario 02 (SSH brute force loop)
which sqlmap              # scenario 03 (SQL injection)
which curl                # scenario 04 (web shell upload via POST)
```

If any are missing:

```bash
sudo apt update && sudo apt install -y nmap sshpass sqlmap curl hydra
```

### Connectivity sanity check

```bash
ping -c 2 10.10.10.1        # gateway
ping -c 2 10.10.30.50       # DMZ host (the target)
ping -c 2 10.10.40.50       # Wazuh manager (should also be reachable for ops)
curl -sI http://10.10.30.50/ | head -1     # HTTP/1.1 200 OK from DVWA
```

### Snapshot

```
Proxmox → VM 103 → Snapshots → Take snapshot
Name: kali-base-tools-ready
Description: Kali 2025.3 with nmap/sshpass/sqlmap/hydra installed, full L3 reachability to DMZ
```

---

## Analyst-Desktop (VM 102)

### Specs

| Setting | Value |
|---|---|
| VM ID | 102 |
| Name | Analyst-Desktop |
| BIOS | OVMF (UEFI) + EFI disk |
| CPU | 2 cores, type `host` |
| RAM | 4 GB |
| Disk | 30 GB on `local-lvm` |
| NIC | VirtIO on `vmbr6` (VLAN 50 Analyst) |
| ISO | `ubuntu-24.04.4-desktop-amd64.iso` |
| Static IP | `10.10.50.50/24`, gateway `10.10.50.1`, DNS `10.10.50.1` |

### Install

Minimal Ubuntu Desktop install. After first boot:

```bash
echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4
sudo apt update && sudo apt upgrade -y
sudo apt install -y firefox chromium-browser openssh-client git curl
```

### SSH key pair for DMZ admin access

```bash
ssh-keygen -t ed25519 -C "socadmin@analyst" -f ~/.ssh/dmz_admin
# The public key is then deployed on Ubuntu-DMZ — see 03-ubuntu-dmz.md, step 3
```

### Optional — Wazuh agent on the analyst desktop

If you want endpoint telemetry from the analyst workstation itself (useful for the soutenance to demonstrate scope), install the agent the same way as on the DMZ — see [06-wazuh-agent-dmz.md](06-wazuh-agent-dmz.md), but with:

```bash
WAZUH_AGENT_GROUP='default,linux,analyst'
```

(Create the `analyst` group on the manager first, as in step 1 of guide 06.)

### Dashboard bookmark

In Firefox/Chromium, bookmark:

- `https://10.10.40.50` — Wazuh Dashboard
- `https://10.10.40.1` — pfSense web UI (cross-VLAN routing required; pass rule already in place)
- `http://10.10.30.50` — DVWA (to compare attacker view vs. server logs)

Accept the self-signed certificates on first visit.

### Snapshot

```
Proxmox → VM 102 → Snapshots → Take snapshot
Name: analyst-desktop-base
Description: Ubuntu Desktop 24.04 with SSH key for DMZ admin, dashboard bookmarks ready
```

---

## End-to-end reachability matrix

Once both VMs are up, validate the full mesh:

| From → To | Expected |
|---|---|
| Kali → DMZ:80 | `200 OK` (DVWA) |
| Kali → DMZ:22 | Cowrie banner (`SSH-2.0-OpenSSH_7.x`) |
| Kali → DMZ:2200 | Real `sshd` banner |
| Analyst → DMZ:2222 (key) | Logged in as `socadmin` |
| Analyst → Wazuh:443 | Dashboard login page |
| Kali → Wazuh:443 | Dashboard reachable too (useful for live demo) |
| DMZ → Wazuh:1514 | Agent connected (validated in guide 06) |
| pfSense → Wazuh:514 (UDP) | Syslog flowing (validated in guide 07) |

All green → the V1 lab is fully operational and ready for attack scenarios (`docs/05-attack-scenarios/`).

---

## What's not in this guide (deliberate scope choice)

| Component | Why it's out of V1 |
|---|---|
| Windows Server 2022 + Active Directory | Out of memory budget on the assigned Proxmox node (24 GB total). Documented as future work in the top-level README. |
| Windows 10 endpoints + Sysmon | Same reason — and the Linux-only stack is enough to demonstrate every detection layer (HIDS, NIDS, deception). |
| TheHive / MISP / Shuffle (SOAR + TI) | Scope-cut to keep V1 finishable and defensible. Roadmap in the top-level README. |

These were conscious cuts to ship a **complete** V1 rather than an ambitious-but-broken project — the same posture defended in the soutenance.

---

← Back to [README.md](README.md)
