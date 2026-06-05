# 02 — Wazuh server (VM 101)

> Deploy Wazuh 4.14.5 in **All-In-One** mode (Manager + Indexer + Dashboard) on Ubuntu Server 24.04.
> This is the central SIEM that every agent and every Suricata/Cowrie pipeline reports to.

## VM specs

| Setting | Value |
|---|---|
| VM ID | 101 |
| Name | Wazuh-Server |
| BIOS | OVMF (UEFI) + EFI disk |
| CPU | 2 cores, type `host` |
| RAM | 6 GB (4 GB is too tight; 8 GB recommended if you can spare it) |
| Disk | 50 GB on `local-lvm`, discard + SSD emulation |
| NIC | VirtIO on `vmbr5` (VLAN 40 SOC) |
| ISO | `ubuntu-24.04.4-live-server-amd64.iso` |
| Static IP | `10.10.40.50/24`, gateway `10.10.40.1`, DNS `10.10.40.1` |

## 1. Install Ubuntu Server

Standard guided install with these choices:

- Minimized server install
- OpenSSH server enabled at install time
- LVM enabled → **then immediately extend the LV after first boot** (see pitfall below)

## 2. Post-install — extend the LV to the full disk

The Ubuntu installer creates the LV at ~50 % of the disk by default. Fix it:

```bash
sudo vgs           # confirm there's free space in the VG
sudo lvextend -l +100%FREE /dev/ubuntu-vg/ubuntu-lv
sudo resize2fs /dev/ubuntu-vg/ubuntu-lv
df -h /            # should now show ~47 GB
```

## 3. Lock the network and force IPv4 for apt

Set the static IP via Netplan (`/etc/netplan/50-cloud-init.yaml`, exact filename may differ):

```yaml
network:
  version: 2
  ethernets:
    ens18:
      dhcp4: no
      addresses: [10.10.40.50/24]
      routes:
        - to: default
          via: 10.10.40.1
      nameservers:
        addresses: [10.10.40.1]
```

```bash
sudo netplan apply
ip a show ens18
```

Force IPv4 for apt (the lab WAN has no working IPv6):

```bash
echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4
sudo apt update && sudo apt upgrade -y
sudo reboot
```

## 4. Sysctl tuning (only needed on HDD-backed storage)

If the underlying datastore is an HDD, Wazuh's installer can starve the kernel during the indexer init. Add:

```bash
sudo tee /etc/sysctl.d/99-wazuh.conf > /dev/null <<EOF
kernel.hung_task_timeout_secs = 600
vm.swappiness = 10
vm.max_map_count = 262144
EOF
sudo sysctl --system
```

`vm.max_map_count = 262144` is required by the OpenSearch indexer and the installer will warn if it's missing.

## 5. Run the All-In-One installer

```bash
curl -sO https://packages.wazuh.com/4.14/wazuh-install.sh
sudo bash ./wazuh-install.sh -a
```

The script provisions, in order:

1. Repositories and dependencies
2. Self-signed certificates
3. Wazuh Indexer (OpenSearch)
4. Wazuh Manager
5. Wazuh Dashboard

On HDD this takes **≈50 minutes**. On SSD count 10–15 minutes.

When it finishes, you get the dashboard URL and the `admin` password in the console — **copy them immediately**:

```
INFO: --- Summary ---
INFO: You can access the web interface https://<wazuh-dashboard-ip>:443
    User: admin
    Password: <generated>
INFO: Installation finished.
```

If you miss them, they are also written to `/root/wazuh-install-files/wazuh-passwords.txt`.

## 6. First login

Open `https://10.10.40.50` from the Analyst Desktop (VM 102). Accept the self-signed cert, log in as `admin`.

Expected view:

- **Wazuh → Agents**: empty (we'll enroll the DMZ agent later)
- **Server management → Status**: every node `Active`
- **Dashboard → Discover** with `wazuh-alerts-*` index → events from the manager itself (`agent.id=000`)

## Pitfalls

| Symptom | Root cause | Fix |
|---|---|---|
| Install dies with `No space left on device` even though the disk is 50 GB | Ubuntu LVM allocated only ~25 GB to the LV | Step 2 — extend the LV with `lvextend -l +100%FREE` |
| `apt update` hangs on IPv6 endpoints | Lab WAN has no usable IPv6 | Step 3 — `Acquire::ForceIPv4 "true"` |
| Kernel logs spammed with `rcu_preempt detected stalls` and OOM warnings | HDD too slow for default sysctl settings | Step 4 — apply the sysctl tuning |
| `wazuh-keystore: No such file or directory` after a failed install + `rm -rf /var/ossec` | Manual `rm -rf` ran before `dpkg --purge wazuh-manager`, leaving the package in `ri` state | Bypass the broken hooks: write empty `prerm`/`postrm` in `/var/lib/dpkg/info/wazuh-manager.*` and run `dpkg --purge --force-all wazuh-manager` before reinstalling |
| Dashboard reachable but agents never connect | UDP/TCP 1514, TCP 1515, TCP 55000 blocked by pfSense | Pass rules on the SOC interface (see [01-pfsense-firewall.md](01-pfsense-firewall.md)) |

> **Hard rule learned the hard way:** always run `sudo apt purge wazuh-manager wazuh-indexer wazuh-dashboard` **before** any manual cleanup. Never `rm -rf` first.

## Validation

```bash
# On the Wazuh server
sudo systemctl status wazuh-manager wazuh-indexer wazuh-dashboard
# All three: active (running)

curl -k -u admin:'<password>' https://localhost:55000/?pretty
# Expect a JSON banner with the Wazuh version
```

Dashboard checks:

- `Server management → Status` → every node green
- `Server management → Cluster` → manager up
- `Discover` on `wazuh-alerts-*` shows at least the manager's own events

## Snapshot recommendation

```
Proxmox → VM 101 → Snapshots → Take snapshot
Name: wazuh-aio-fresh
Description: Wazuh 4.14.5 AIO installed, dashboard reachable, no agents yet
```

This is the snapshot you roll back to if anything ever corrupts the indexer.

---

**Next:** [03-ubuntu-dmz.md →](03-ubuntu-dmz.md)
