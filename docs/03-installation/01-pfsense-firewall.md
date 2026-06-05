# 01 — pfSense firewall (VM 100)

> Deploy pfSense CE 2.7.2 as the single firewall and router for the lab.
> One WAN interface (NAT to the Internet) and five LAN interfaces (one per VLAN).

## VM specs

| Setting | Value |
|---|---|
| VM ID | 100 |
| Name | pfSense-FW |
| BIOS | OVMF (UEFI) + EFI disk |
| CPU | 1 core (raise to 2 if Suricata is enabled later — see [07-suricata-pfsense.md](07-suricata-pfsense.md)) |
| RAM | 1 GB (raise to 4 GB before installing Suricata) |
| Disk | 8 GB on `local-lvm`, discard + SSD emulation |
| NICs | 6 × VirtIO, one per bridge: `vmbr1` (WAN) + `vmbr2..vmbr6` (LAN/OPT1..OPT4) |
| ISO | `pfSense-CE-2.7.2-RELEASE-amd64.iso` |

> Always attach the NICs in the same order as the table below — pfSense uses the discovery order to map physical adapters to its internal interface names.

| pfSense interface | Bridge | VLAN | IPv4 |
|---|---|---|---|
| WAN (em0/vtnet0) | `vmbr1` | — | DHCP (`192.168.42.x` from the NAT range) |
| LAN (em1/vtnet1) | `vmbr2` | 10 Attack | `10.10.10.1/24` |
| OPT1 (em2/vtnet2) | `vmbr3` | 20 Corp | `10.10.20.1/24` |
| OPT2 (em3/vtnet3) | `vmbr4` | 30 DMZ | `10.10.30.1/24` |
| OPT3 (em4/vtnet4) | `vmbr5` | 40 SOC | `10.10.40.1/24` |
| OPT4 (em5/vtnet5) | `vmbr6` | 50 Analyst | `10.10.50.1/24` |

## 1. Installer

Boot the VM on the ISO and accept the defaults until the disk-selection screen:

- Filesystem: **ZFS** (single-disk stripe)
- **Press SPACE to tick `da0`** before pressing OK — if you don't, the installer aborts with `stripe: not enough disks selected`
- Confirm Install → eject the ISO when prompted → Reboot

## 2. First-boot console assignment

When pfSense reaches the console menu:

1. **Option 1 — Assign Interfaces** → answer `n` to VLAN setup → assign in this order:
   - WAN: `vtnet0`
   - LAN: `vtnet1`
   - OPT1: `vtnet2`, OPT2: `vtnet3`, OPT3: `vtnet4`, OPT4: `vtnet5`
2. **Option 2 — Set interface IP address**, for each LAN/OPT, set the IPv4 from the table above with `/24`, no DHCP yet (we'll enable DHCP from the web UI), no IPv6.
3. The WAN should already have an IP from `vmbr1`'s NAT range.

The console then prints the management URLs. Hit https://10.10.40.1 from a VM on VLAN 40 (or temporarily from VLAN 10 — LAN is the only interface that has a default permissive rule).

## 3. Initial web UI setup

Default credentials: `admin` / `pfsense` (change on the wizard).

Run the **Setup Wizard**:

- Hostname: `pfsense-fw`, domain: `lab.local`
- Primary DNS: `195.83.24.30` (UGA upstream), or `1.1.1.1` as a fallback
- Timezone: `Europe/Paris`
- WAN: DHCP (leave the defaults)
- LAN: confirm `10.10.10.1/24`
- New admin password
- Reload

## 4. DHCP server per VLAN

**Services → DHCP Server**, enable on each OPT interface with a reasonable pool:

| Interface | Pool |
|---|---|
| LAN (VLAN 10) | `10.10.10.50 – 10.10.10.100` |
| OPT1 (VLAN 20) | `10.10.20.50 – 10.10.20.100` |
| OPT2 (VLAN 30) | `10.10.30.50 – 10.10.30.100` |
| OPT3 (VLAN 40) | `10.10.40.50 – 10.10.40.100` |
| OPT4 (VLAN 50) | `10.10.50.50 – 10.10.50.100` |

> In practice every lab VM is given a **static IP** (`.50` or `.51`) outside the pool. The pool is only there for one-off test VMs.

## 5. Firewall rules

By default **only LAN** has an "allow any" rule. Every other OPT interface blocks everything inbound. For the lab to function end-to-end, add on each OPT:

**Firewall → Rules → OPTx → Add (top)**

- Action: Pass
- Interface: OPTx
- Protocol: any
- Source: OPTx net
- Destination: any
- Description: `Allow all from VLANxx`

Repeat for OPT1, OPT2, OPT3, OPT4. Save → Apply Changes.

This gives wide-open routing across the lab, which is intentional: we want attacks to reach their targets so we can detect them. Detection — not blocking — is the goal of V1.

## 6. DNS Resolver

**Services → DNS Resolver → General Settings**:

- Enable
- Network Interfaces: `All` (or at least every LAN/OPT)
- Outgoing Network Interfaces: `WAN`
- Enable forwarding mode (uses the upstream DNS from Setup Wizard)

This lets every VM resolve `archive.ubuntu.com`, `packages.wazuh.com`, etc. without depending on a local resolver.

## 7. Quick connectivity test

From any LAN/OPT VM:

```bash
ping -c 2 10.10.40.1        # pfSense gateway of VLAN 40
ping -c 2 8.8.8.8           # WAN reachability
getent hosts packages.wazuh.com  # DNS resolution
```

All three must succeed before installing anything else.

## Pitfalls

| Symptom | Root cause | Fix |
|---|---|---|
| `stripe: not enough disks selected` during install | Forgot to tick `da0` with SPACE on the disk-selection screen | Re-run the installer, press SPACE on `da0` |
| ICMP from a VLAN to its gateway fails | Default deny on every OPT interface | Add the OPT pass rule from step 5 |
| `apt` on VMs reports DNS timeouts | DNS Resolver not enabled or not listening on that OPT | Step 6 — enable Resolver on all interfaces |
| WAN has no IP after install | NIC 0 not on `vmbr1` / NAT not configured on host | Verify the VM hardware → `net0` is on `vmbr1`; check NAT on the node |

## Validation

- Web UI reachable at every gateway IP from its respective VLAN
- `Status → Interfaces` shows every interface up with the expected IP
- `Status → Services` shows DHCP Server and DNS Resolver as **Running**
- A test VM on VLAN 40 pulls a lease in the configured pool

## Snapshot recommendation

```
Proxmox → VM 100 → Snapshots → Take snapshot
Name: pfsense-base-routing
Description: pfSense 2.7.2, 5 VLANs configured, DHCP + DNS up, firewall pass rules on all OPT
```

---

**Next:** [02-wazuh-server.md →](02-wazuh-server.md)
