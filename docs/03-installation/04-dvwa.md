# 04 — DVWA (Damn Vulnerable Web App)

> Deploy DVWA on port 80 of the DMZ as the target for the SQL injection and web shell scenarios.

## Prerequisites

- [03-ubuntu-dmz.md](03-ubuntu-dmz.md) complete (Docker engine running, ports 22/2200/2222 sorted)

## 1. Compose file

The compose file is versioned at [`configs/dvwa/docker-compose.yml`](../../configs/dvwa/docker-compose.yml). Drop it into `/home/socadmin/dvwa/` on the DMZ host.

```bash
mkdir -p /home/socadmin/dvwa
cd /home/socadmin/dvwa
# Copy configs/dvwa/docker-compose.yml here (scp, git pull, etc.)
docker compose up -d
docker compose ps
# dvwa container: Up
```

## 2. First-run setup

Browse to `http://10.10.30.50` from Kali or Analyst-Desktop. You land on the **setup.php** page.

1. Click **Create / Reset Database** → wait for the success banner
2. Log in with `admin` / `password`
3. **DVWA Security → Security Level → Low → Submit**

> Low security is intentional. The point of the lab is to *detect* the attack, not to make DVWA hard to exploit.

## 3. Sanity check

```bash
# From Kali
curl -s http://10.10.30.50/login.php | grep -i "<title>"
# <title>Damn Vulnerable Web Application (DVWA) v1.10 *Development*</title>
```

The web app is now ready for:

- **SQL Injection** module → consumed by attack scenario 03 (Suricata rule `100202`)
- **File Upload** module → consumed by attack scenario 04 (Wazuh FIM)
- **Command Injection** module → bonus reverse-shell scenario

## Validation

- `http://10.10.30.50` shows the DVWA login page
- After login, `DVWA Security` reports **Security level: low**
- `docker compose ps` shows the container as `Up` (healthy)

## Snapshot recommendation

Not a separate snapshot — extends `dmz-base-ssh-docker` from [03-ubuntu-dmz.md](03-ubuntu-dmz.md). After Cowrie is also deployed, take the combined snapshot.

---

**Next:** [05-cowrie-honeypot.md →](05-cowrie-honeypot.md)
