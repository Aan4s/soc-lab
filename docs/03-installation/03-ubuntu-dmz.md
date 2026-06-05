# 03 — Ubuntu DMZ host (VM 104)

> Ubuntu Server 24.04 hosting **three SSH services on different ports** plus Docker for DVWA and Cowrie.
> This is the lab's exposed target: an attacker on Kali (VLAN 10) should be able to reach it on ports 22, 80, 2200, 2222.

## Service layout on this VM

| Port | Service | Provided by | Purpose |
|---|---|---|---|
| 22 | Cowrie | Docker (later) | SSH honeypot — every connection is bait |
| 80 | DVWA | Docker (later) | Vulnerable web app |
| 2200 | OpenSSH | system | **Vulnerable** SSH (user `admin` / password `admin123`) — brute-force target |
| 2222 | OpenSSH | system | **Hardened** SSH (key auth only, allowed users only) — admin access |

## VM specs

| Setting | Value |
|---|---|
| VM ID | 104 |
| Name | Ubuntu-DMZ |
| BIOS | OVMF (UEFI) + EFI disk |
| CPU | 2 cores, type `host` |
| RAM | 4 GB with ballooning |
| Disk | 25 GB on `local-lvm`, discard + SSD emulation |
| NIC | VirtIO on `vmbr4` (VLAN 30 DMZ) |
| QEMU agent | enabled |
| ISO | `ubuntu-24.04.4-live-server-amd64.iso` |
| Static IP | `10.10.30.50/24`, gateway `10.10.30.1`, DNS `10.10.30.1` |

## 1. Install Ubuntu

Standard minimized install + OpenSSH server. Set the static IP via Netplan as in [02-wazuh-server.md](02-wazuh-server.md) (adjust IP/gateway).

Force IPv4 for apt and update:

```bash
echo 'Acquire::ForceIPv4 "true";' | sudo tee /etc/apt/apt.conf.d/99force-ipv4
sudo apt update && sudo apt upgrade -y
```

## 2. Create the three user accounts

```bash
# socadmin — sudo, key-only via port 2222
sudo adduser --gecos "" socadmin
sudo usermod -aG sudo socadmin

# admin — NO sudo, password 'admin123', vulnerable target on port 2200
sudo adduser --gecos "" admin
echo 'admin:admin123' | sudo chpasswd
# Do NOT add 'admin' to sudo

# anass — default user kept as a fallback admin
```

## 3. Inject the SSH public key for socadmin

Generated on **Analyst-Desktop** with:

```bash
ssh-keygen -t ed25519 -C "socadmin@analyst" -f ~/.ssh/dmz_admin
```

Then on the DMZ:

```bash
sudo -u socadmin mkdir -p /home/socadmin/.ssh
sudo -u socadmin chmod 700 /home/socadmin/.ssh
sudo -u socadmin tee /home/socadmin/.ssh/authorized_keys > /dev/null <<'EOF'
ssh-ed25519 AAAA... socadmin@analyst
EOF
sudo -u socadmin chmod 600 /home/socadmin/.ssh/authorized_keys
```

## 4. Configure multiport SSH

Edit `/etc/ssh/sshd_config`, replace the `Port 22` line with:

```sshd_config
# Listen on two non-default ports — port 22 is reserved for Cowrie
Port 2200
Port 2222

# Hardened access on 2222 — key only, restricted users
Match LocalPort 2222
    PasswordAuthentication no
    PubkeyAuthentication yes
    PermitRootLogin no
    AllowUsers socadmin anass

# Deliberately vulnerable on 2200 — password only, only the 'admin' user
Match LocalPort 2200
    PasswordAuthentication yes
    PubkeyAuthentication no
    PermitRootLogin no
    AllowUsers admin
    MaxAuthTries 6
```

## 5. Disable socket activation (Ubuntu 24.04 specific)

**This is the part that bites everyone on Ubuntu 22.10+.** OpenSSH ships as a *socket-activated* unit, and the `ssh.socket` overrides every `Port` directive in `sshd_config`. You have to mask it explicitly:

```bash
sudo systemctl stop ssh.socket
sudo systemctl disable ssh.socket
sudo systemctl mask ssh.socket   # stronger than disable — prevents auto re-enable
sudo pkill -9 sshd               # kill the zombie sshd that survives the disable
sudo systemctl enable --now ssh.service
sudo systemctl restart ssh.service
```

Verify the daemon is listening on the right ports and **not** on 22:

```bash
sudo ss -lntp | grep sshd
# tcp LISTEN 0 128 *:2200 *:* users:(("sshd",pid=...,fd=3))
# tcp LISTEN 0 128 *:2222 *:* users:(("sshd",pid=...,fd=4))
# (nothing on :22 — that's what Cowrie will use)
```

## 6. SSH validation matrix

From **Analyst-Desktop** (10.10.50.50):

```bash
# Key-based admin access on 2222
ssh -i ~/.ssh/dmz_admin -p 2222 socadmin@10.10.30.50
# → should connect with no password

# Vulnerable target on 2200
sshpass -p 'admin123' ssh -p 2200 -o StrictHostKeyChecking=no admin@10.10.30.50
# → should connect with the password

# Default port reserved for Cowrie
ssh -p 22 anyuser@10.10.30.50
# → Connection refused (expected — Cowrie not deployed yet)
```

If all three behave as expected, the SSH foundation is correct.

## 7. Install Docker Engine

```bash
sudo apt update && sudo apt install -y ca-certificates curl gnupg lsb-release

sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
  -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] \
  https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io \
                    docker-buildx-plugin docker-compose-plugin

sudo systemctl enable --now docker
sudo usermod -aG docker socadmin   # reconnect SSH after this
docker run --rm hello-world         # sanity check
```

## Pitfalls

| Symptom | Root cause | Fix |
|---|---|---|
| `Port` directives ignored, `sshd` still on 22 | `ssh.socket` overrides `sshd_config` on Ubuntu 22.10+ | Mask the socket and kill the zombie `sshd` — step 5 |
| `ss -lntp` still shows port 22 after `systemctl restart ssh.service` | Old `sshd` process from the socket unit is still alive | `sudo pkill -9 sshd` then restart `ssh.service` |
| `docker run hello-world` permission denied | Current user not yet in the `docker` group | Reconnect SSH after `usermod -aG docker` |
| Account `admin` accidentally has sudo | Created with `adduser` while logged in as sudo user that pushed default groups | `sudo deluser admin sudo` |

## Validation

- `ss -lntp` shows `sshd` on **2200 and 2222 only** (port 22 stays free for Cowrie)
- Key login works on 2222 for `socadmin`, password login works on 2200 for `admin`, both fail on the wrong port
- `docker info` reports a working engine

## Snapshot recommendation

```
Proxmox → VM 104 → Snapshots → Take snapshot
Name: dmz-base-ssh-docker
Description: Ubuntu 24.04 with multiport SSH (2200 vulnerable + 2222 hardened) and Docker engine ready
```

---

**Next:** [04-dvwa.md →](04-dvwa.md)
