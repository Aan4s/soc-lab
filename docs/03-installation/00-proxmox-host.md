# 00 — Proxmox host preparation

> Extend the `local-lvm` thin pool and create the Linux bridges that back the lab VLANs.
> Performed on the IM2AG node `ProxProf-rapacchd-326` (24 GB RAM, 200 GB allocated disk).

## Why this step matters

By default the Proxmox installer reserves only part of the physical disk to the LVM thin pool. After the infrastructure team extended the underlying virtual disk to 200 GB, `local-lvm` was still capped at 60 GB and sitting at **86 % usage**, which would have blocked every subsequent VM creation.

We extend the partition, the LVM PV, and the thin pool **in this order** — none of the layers grow automatically.

## Prerequisites

- Root shell on the Proxmox node (via web UI **Datacenter → Node → Shell** or SSH)
- A confirmed disk extension on the underlying storage (check with `lsblk` — `/dev/sda` should report the new size)
- `growpart` available (`apt install cloud-guest-utils` if missing)

## 1. Diagnose the current state

```bash
lsblk
# Expect to see /dev/sda at the new size but /dev/sda3 still at the old size

pvs
vgs
lvs
# Confirm the thin pool /dev/pve/data is the bottleneck
```

## 2. Back up the partition table (safety net)

```bash
sfdisk -d /dev/sda > /root/sda-partitions-backup-$(date +%F).txt
```

## 3. Extend the LVM partition

```bash
# Dry-run first — read the output, confirm the new end sector
growpart --dry-run /dev/sda 3

# Apply
growpart /dev/sda 3

# Verify: sda3 should now reflect the new size
lsblk
```

## 4. Resize the LVM physical volume

```bash
pvresize /dev/sda3
pvs
# /dev/sda3 should now show the full size, with free PE
vgs
```

## 5. Extend the thin pool

```bash
lvextend -l +100%FREE /dev/pve/data
lvs
# Data% should drop dramatically (we went from 86 % → 35 %)
```

> The thin pool **data** volume holds every VM disk. Once it's resized, `local-lvm` shows the new capacity in the Proxmox web UI without a restart.

## 6. Create the lab bridges

Edit `/etc/network/interfaces` (or use **Datacenter → Node → System → Network**) and add one Linux bridge per VLAN. **Do not** put any IP on these bridges — they are pure L2 segments that pfSense will gateway.

```ini
auto vmbr2
iface vmbr2 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
# VLAN10_Attack

auto vmbr3
iface vmbr3 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
# VLAN20_Corp (reserved for V2)

auto vmbr4
iface vmbr4 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
# VLAN30_DMZ

auto vmbr5
iface vmbr5 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
# VLAN40_SOC

auto vmbr6
iface vmbr6 inet manual
    bridge-ports none
    bridge-stp off
    bridge-fd 0
# VLAN50_Analyst
```

Then:

```bash
ifreload -a
brctl show
```

The WAN bridge (`vmbr1`) was created earlier by the infra team and is connected to the node's uplink with NAT enabled, so pfSense can reach the Internet through it.

## Pitfalls

| Symptom | Root cause | Fix |
|---|---|---|
| Disk extended but `local-lvm` still full | Each layer (partition → PV → LV) is independent | Run all three resize commands in order |
| `growpart` complains "GPT table needs to be updated" | Real disk grew, GPT backup header still at the old end of disk | `growpart` rewrites the GPT — no manual fix needed |
| `lvextend` says "Insufficient free space" | Forgot `pvresize` before extending the LV | Re-run `pvresize /dev/sda3` first |

## Validation

```bash
# Storage check
lvs | grep data
# Expected: data ... 147.43g ... ~35.00% (your numbers will vary)

# Bridge check
brctl show
# Expected: vmbr0, vmbr1, vmbr2, vmbr3, vmbr4, vmbr5, vmbr6
```

In the web UI, **Datacenter → Storage → local-lvm** should display the new size with healthy free space.

## Snapshot recommendation

This is the host itself, not a VM — there's nothing to snapshot here. The safety net is the `sfdisk -d` backup taken in step 2.

---

**Next:** [01-pfsense-firewall.md →](01-pfsense-firewall.md)
