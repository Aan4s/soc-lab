# 05 — Cowrie SSH honeypot

> Deploy Cowrie on port 22 of the DMZ. Every connection on port 22 is now bait — anyone hitting it is, by definition, doing something they shouldn't.
> Cowrie's JSON log is what Wazuh consumes later (see [06-wazuh-agent-dmz.md](06-wazuh-agent-dmz.md)).

## Prerequisites

- [03-ubuntu-dmz.md](03-ubuntu-dmz.md) complete — and **port 22 must be free** (the system `sshd` listens only on 2200/2222, validated with `ss -lntp`)
- Docker engine running

## 1. Directory layout

Cowrie runs as **UID/GID 999** inside the container. The bind-mount targets on the host must be **owned by 999:999 in advance**, or Cowrie crashes the first time it tries to generate its SSH keys or write a TTY log.

```bash
sudo mkdir -p /home/socadmin/cowrie/{etc,var/lib/cowrie/tty,var/lib/cowrie/downloads,var/log/cowrie,var/run}
sudo chown -R 999:999 /home/socadmin/cowrie
sudo chmod -R 750 /home/socadmin/cowrie
```

## 2. `userdb.txt` — the credential trap

The exact file is versioned at [`configs/cowrie/userdb.txt`](../../configs/cowrie/userdb.txt). Content:

```
root:x:!root
root:x:!toor
root:x:*
admin:x:*
oracle:x:*
ubuntu:x:*
pi:x:*
```

Conventions:

- `:!password` → **reject** this exact password (sends "wrong password")
- `:password` → **accept** this exact password (login.success → attractive to the attacker)

With this file:

- `root` rejects `root` and `toor`, accepts anything else (catches the standard rockyou attempts)

Install it with `sudo tee` (the bind mount + bash redirection issue is documented in the pitfalls below):

```bash
sudo tee /home/socadmin/cowrie/etc/userdb.txt > /dev/null <<'EOF'
root:x:!root
root:x:!toor
root:x:*
admin:x:*
oracle:x:*
ubuntu:x:*
pi:x:*
EOF
sudo chown 999:999 /home/socadmin/cowrie/etc/userdb.txt
```

## 3. Compose file

Versioned at [`configs/cowrie/docker-compose.yml`](../../configs/cowrie/docker-compose.yml). Copy it to `/home/socadmin/cowrie/` and start:

```bash
cd /home/socadmin/cowrie
docker compose up -d
docker compose logs -f cowrie
# Wait for "Reactor running" — then Ctrl+C
```

## 4. First contact

From Kali:

```bash
ssh test@10.10.30.50
# Password: test789
# → fake busybox shell, type 'ls', 'whoami', then 'exit'
```

Then on the DMZ:

```bash
tail -1 /home/socadmin/cowrie/var/log/cowrie/cowrie.json | python3 -m json.tool
# JSON record with eventid=cowrie.login.success, src_ip=10.10.10.51, etc.
```

If you see that JSON line, the honeypot is live and producing the exact log format Wazuh expects in the next guide.

## Pitfalls

| Symptom | Root cause | Fix |
|---|---|---|
| Cowrie container restarts in a loop, logs `Could not generate SSH server key` | Bind-mounted directories owned by root, not UID 999 | Re-`chown -R 999:999` on every subdirectory **before** the first start |
| `cowrie.json` is empty even though SSH connections show up | TTY log dir missing (`var/lib/cowrie/tty`) — Cowrie aborts before writing the event | Create every subdir from step 1, then restart the container |
| `sudo cat > /home/socadmin/cowrie/etc/userdb.txt << EOF` fails with "Permission denied" | Bash redirection (`>`) is done by your shell, not by `sudo`; it has no rights on the bind-mount path | Use `sudo tee path < /dev/null` (or the heredoc pattern in step 2) |
| Cowrie accepts `root` with any password | `root:x:*` was used by accident — `:*` matches anything | Use targeted patterns like `:!root,!toor,!password` instead |
| `Port 22 already in use` on startup | The system `sshd` is still listening on port 22 | See [03-ubuntu-dmz.md](03-ubuntu-dmz.md) — mask `ssh.socket` and `pkill -9 sshd` |

## Validation

```bash
# On the DMZ
docker compose ps           # cowrie: Up
ss -lntp | grep ':22 '      # port 22 owned by the docker proxy, NOT by sshd

# From Kali — three test events
ssh test@10.10.30.50            # login.success (password test789)
ssh root@10.10.30.50            # login.failed (password 'root' rejected)
```

Then on the DMZ:

```bash
grep -c 'login.success' /home/socadmin/cowrie/var/log/cowrie/cowrie.json
grep -c 'login.failed'  /home/socadmin/cowrie/var/log/cowrie/cowrie.json
```

## Snapshot recommendation

```
Proxmox → VM 104 → Snapshots → Take snapshot
Name: dmz-dvwa-cowrie-ready
Description: Ubuntu DMZ with DVWA on :80, Cowrie on :22, hardened SSH on :2222, vulnerable SSH on :2200
```

This is the snapshot you roll back to if a scenario goes wrong and the container state is corrupted.

---

**Next:** [06-wazuh-agent-dmz.md →](06-wazuh-agent-dmz.md)
