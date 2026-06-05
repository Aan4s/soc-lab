# 07 — Suricata IDS on pfSense (two instances)

> Run Suricata as a pfSense package on **two interfaces** so every attack is detected from two independent vantage points (attacker-side and victim-side).
> Forward the alerts as syslog to the Wazuh manager so they appear next to the HIDS events in the same dashboard — a single pane of glass.

## Why two instances

| Instance | Interface | What it sees |
|---|---|---|
| `#1 LAN_Suricata` | LAN (VLAN 10, `vtnet1`) | Traffic **leaving Kali** — the attacker's outbound POV |
| `#2 DMZ_Suricata` | OPT2 (VLAN 30, `vtnet3`) | Traffic **entering the DMZ host** — the victim's inbound POV |

For every Nmap scan, every SQLi, every web shell upload, we get **two distinct alerts** that correlate by source IP and timestamp. This is concrete, log-backed proof of defense in depth — not a marketing claim.

## Prerequisites

- [01-pfsense-firewall.md](01-pfsense-firewall.md) — pfSense running
- pfSense VM raised from 1 GB to **4 GB RAM** (Proxmox → VM 100 → Hardware → Memory → 4096 → reboot the firewall)
- [02-wazuh-server.md](02-wazuh-server.md) — manager reachable on `10.10.40.50`

## 1. Install the Suricata package

In the pfSense web UI:

1. **System → Package Manager → Available Packages** → search `suricata` → **Install**
2. **Services → Suricata → Global Settings**:
   - ☑ Install ETOpen Emerging Threats rules
   - Update Interval: `1 day`
3. **Services → Suricata → Updates → Update** → wait for the ETOpen pack (~30 000 rules) to download

## 2. Create the two instances

**Services → Suricata → Interfaces → +Add** — fill in twice with these values:

### Instance #1 — LAN_Suricata

| Setting | Value |
|---|---|
| Interface | LAN |
| Description | `LAN_Suricata` |
| Send Alerts to System Log | ☑ — facility `LOG_AUTH`, priority `LOG_NOTICE` |
| Enable EVE JSON Log | ☑ — output **FILE** |
| Block Offenders | ☐ (IDS mode, not IPS) |

### Instance #2 — DMZ_Suricata

Same as above but with `Interface: OPT2` and `Description: DMZ_Suricata`.

## 3. Enable rule categories

For **each** instance, **Categories** tab:

- ☑ `emerging-scan.rules` → port scans, Nmap fingerprints
- ☑ `emerging-trojan.rules` → known malware C2 patterns
- ☑ `emerging-info.rules` → recon and information-disclosure patterns
- ☑ `emerging-web_specific.rules` → SQLi, XSS, RFI, LFI (this one catches the `sqlmap` traffic in scenario 03)

Apply.

## 4. Start both instances

**Services → Suricata → Interfaces** → press **▶** on each row → wait for the status to flip to **Running** (~30 s while rules compile).

## 5. Forward pfSense syslog to the Wazuh manager

**Status → System Logs → Settings → Remote Logging Options**:

- ☑ Enable Remote Logging
- Source Address: `default`
- IP Protocol: IPv4
- Remote log servers: `10.10.40.50:514`
- Remote Syslog Contents: ☑ Everything (or at least Firewall events + System events)

Save.

## 6. Open UDP/514 on the Wazuh manager

On the Wazuh server (`10.10.40.50`), edit `/var/ossec/etc/ossec.conf` and append (before `</ossec_config>`):

```xml
<remote>
  <connection>syslog</connection>
  <port>514</port>
  <protocol>udp</protocol>
  <allowed-ips>10.10.40.1</allowed-ips>
  <local_ip>10.10.40.50</local_ip>
</remote>
```

The exact snippet is also versioned at [`configs/wazuh/manager-ossec-remote.conf`](../../configs/wazuh/manager-ossec-remote.conf).

```bash
sudo systemctl restart wazuh-manager
sudo ss -lnup | grep ':514 '
# udp UNCONN ... 10.10.40.50:514
```

> The `<allowed-ips>` value is the pfSense SOC-side interface IP (`10.10.40.1`) — that's the source address pfSense uses when forwarding syslog to the manager on VLAN 40

## 7. Deploy the Suricata decoder + rules

The custom Wazuh content is versioned in the repo:

- [`configs/wazuh/local_decoder.xml`](../../configs/wazuh/local_decoder.xml) — parses the pfSense-prefixed Suricata JSON with PCRE2 regex
- [`configs/wazuh/local_rules.xml`](../../configs/wazuh/local_rules.xml) — defines rules `100200..100203` (catch-all, recon, web attacks)

```bash
# On the Wazuh manager
sudo cp configs/wazuh/local_decoder.xml /var/ossec/etc/decoders/
sudo cp configs/wazuh/local_rules.xml   /var/ossec/etc/rules/
sudo chown wazuh:wazuh /var/ossec/etc/decoders/local_decoder.xml \
                      /var/ossec/etc/rules/local_rules.xml
sudo systemctl restart wazuh-manager
sudo tail /var/ossec/logs/ossec.log | grep -i error   # should be empty
```

## 8. End-to-end validation

From Kali:

```bash
nmap -sV -p 22,80,3306 10.10.30.50
```

On the manager:

```bash
sudo tail -n 50 /var/ossec/logs/alerts/alerts.log | grep 10020
```

You should see **at least six rule `100201` (level 8) alerts** — three from `suricata[...]` with `in_iface:vtnet1` (LAN instance) and three from `suricata[...]` with `in_iface:vtnet3` (DMZ instance). Each carries the MITRE mapping:

```
mitre.id:        T1595
mitre.tactic:    Reconnaissance
mitre.technique: Active Scanning
```

That double-detection (one alert per vantage point per scan) is the concrete proof point of the defense-in-depth claim.

## Pitfalls

| Symptom | Root cause | Fix |
|---|---|---|
| Suricata refuses to start, OOM in logs | pfSense VM still at 1 GB RAM | Raise to 4 GB before installing the package |
| ETOpen rules download fails | pfSense WAN has no Internet / DNS broken | Validate WAN with `ping 8.8.8.8` and `Diagnostics → DNS Lookup` from pfSense |
| No syslog reaches the manager | UDP/514 not opened in `ossec.conf`, or `allowed-ips` doesn't match the pfSense source IP | Step 6 — restart the manager, check `ss -lnup` |
| Manager receives the messages but the decoder doesn't extract anything | The built-in JSON decoder matches *before* a custom child decoder using OSRegex; greedy `.+` patterns fail on Suricata payloads | Use the **PCRE2** child decoder pattern with lazy quantifiers (`.*?`) — see [`configs/wazuh/local_decoder.xml`](../../configs/wazuh/local_decoder.xml) |
| Alerts include the catch-all 100200 but never the targeted 100201/100202 | Rule chain misordered (catch-all stops the chain) or fields not extracted | Confirm `<order>` line in the decoder, restart the manager, run `nmap` again |

## Validation

```bash
# On the manager
sudo grep -c 'rule_id.*"100201"' /var/ossec/logs/alerts/alerts.json
# > 0 after running Nmap from Kali

# In the dashboard
# Threat Hunting → filter: rule.id:(100201 OR 100202 OR 100203)
# → events tagged with both in_iface values
```

## Snapshot recommendation

```
Proxmox → VM 100 → Snapshots → Take snapshot
Name: pfsense-suricata-2-instances
Description: pfSense 2.7.2 + Suricata x2 (LAN + DMZ), ETOpen rules loaded, syslog forwarding to Wazuh manager validated end-to-end
```

```
Proxmox → VM 101 → Snapshots → Take snapshot
Name: wazuh-with-suricata-pipeline
Description: Wazuh manager + custom decoder/rules for pfSense-Suricata, MITRE mapping verified
```

---

**Next:** [08-kali-analyst-vms.md →](08-kali-analyst-vms.md)
