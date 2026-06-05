# 06 — Wazuh agent on the DMZ + Cowrie log ingestion

> Install the Wazuh agent on the DMZ, register it against the manager with the right groups, and configure it to tail the Cowrie JSON log so honeypot events flow into the SIEM.

## Prerequisites

- [02-wazuh-server.md](02-wazuh-server.md) complete (manager reachable on `10.10.40.50`)
- [05-cowrie-honeypot.md](05-cowrie-honeypot.md) complete (`cowrie.json` is being written)
- pfSense passes UDP/TCP 1514, TCP 1515, TCP 55000 between VLAN 30 and VLAN 40

## 1. Create the agent groups on the manager first

This trips up everyone. If you set `WAZUH_AGENT_GROUP='linux,dmz'` during installation but those groups don't exist on the manager, enrollment loops forever with `ERROR: Invalid group: linux. Unable to add agent (from manager)`.

On the Wazuh server (`10.10.40.50`):

```bash
sudo /var/ossec/bin/agent_groups -a -g linux -q
sudo /var/ossec/bin/agent_groups -a -g dmz -q
sudo /var/ossec/bin/agent_groups -l        # confirm both groups appear
```

## 2. Install the agent on the DMZ

On `10.10.30.50`:

```bash
# Wazuh GPG key + repo
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | \
  sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update

# Install with auto-enrollment baked into the install env
sudo WAZUH_MANAGER='10.10.40.50' \
     WAZUH_AGENT_NAME='Ubuntu-DMZ' \
     WAZUH_AGENT_GROUP='default,linux,dmz' \
     apt install -y wazuh-agent

# Disable the repo so the agent doesn't auto-upgrade unexpectedly
sudo sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list

sudo systemctl daemon-reload
sudo systemctl enable --now wazuh-agent
```

## 3. Verify enrollment

```bash
sudo tail /var/ossec/logs/ossec.log
# Look for:
# INFO: (4102): Valid key received.
# INFO: Connected to the server (10.10.40.50:1514).
```

In the dashboard: **Agents → Endpoints** → `Ubuntu-DMZ` listed as **Active**.

If it stays `Never connected` or `Disconnected`, check (in order):

1. pfSense rules on VLAN 30 outbound and VLAN 40 inbound for 1514/1515/55000
2. Did you create the groups in step 1?
3. `sudo systemctl status wazuh-agent` for restart loops
4. Manager logs: `sudo tail /var/ossec/logs/ossec.log` on the manager itself

## 4. Add the Cowrie JSON log as a monitored source

The Wazuh agent already tails `/var/log/auth.log`, `/var/log/syslog`, etc. by default. We add Cowrie's JSON output:

Edit `/var/ossec/etc/ossec.conf`, add **just before** `</ossec_config>`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/home/socadmin/cowrie/var/log/cowrie/cowrie.json</location>
  <label key="@source">cowrie-honeypot</label>
</localfile>
```

> `<log_format>json</log_format>` makes the agent push the file as structured events, not raw lines — which is what the decoder rules in [`configs/wazuh/local_decoder.xml`](../../configs/wazuh/local_decoder.xml) expect.

Restart and confirm:

```bash
sudo systemctl restart wazuh-agent
sudo tail -20 /var/ossec/logs/ossec.log
# Look for:
# INFO: Monitoring JSON output of file: '/home/socadmin/cowrie/var/log/cowrie/cowrie.json'.
```

> **Note:** `sudo /var/ossec/bin/wazuh-control configtest` does **not** exist on Wazuh 4.14 (only `start|stop|restart|reload|status|info`). Just restart and check the log — that's the only validation available on this version.

## 5. End-to-end test

This is the moment the SOC stack proves it works:

```bash
# From Kali — triggers a Cowrie login.success
ssh test@10.10.30.50
# Password: test789
```

On the manager:

```bash
sudo tail -f /var/ossec/logs/alerts/alerts.log
# Expect a Cowrie alert (rule 100100..100105, defined in configs/wazuh/local_rules.xml)
```

In the dashboard: **Threat Hunting → search** `rule.id: (100100 OR 100101 OR 100102 OR 100103 OR 100104 OR 100105)` → events from `Ubuntu-DMZ`.

If you see the alert in both places, the pipeline **agent → manager → indexer → dashboard** is fully working.

## Pitfalls

| Symptom | Root cause | Fix |
|---|---|---|
| Agent stays `Never connected` | Groups `linux`/`dmz` don't exist on the manager | Run step 1 *before* installing the agent (or re-enroll after) |
| `configtest` not recognized | Subcommand removed in Wazuh 4.14 | Just `systemctl restart wazuh-agent` and check `/var/ossec/logs/ossec.log` |
| Agent runs fine but no Cowrie alerts | The decoders + rules from [`configs/wazuh/`](../../configs/wazuh/) aren't deployed on the manager yet | See [`configs/wazuh/local_decoder.xml`](../../configs/wazuh/local_decoder.xml) and `local_rules.xml`; restart the manager after dropping them in `/var/ossec/etc/` |
| Cowrie log path empty | Cowrie ran before its bind-mount dirs were `chown 999:999` | See [05-cowrie-honeypot.md](05-cowrie-honeypot.md) — fix permissions and restart Cowrie |

## Validation checklist

- Dashboard → **Agents** → `Ubuntu-DMZ` is **Active**
- Agent modules listed for the endpoint: `logcollector`, `syscheckd` (FIM), `modulesd`, `sca`, `rootcheck`
- `Ubuntu-DMZ` is a member of groups `default,linux,dmz`
- A Cowrie attempt from Kali produces an alert (rule 1001xx) in the dashboard within seconds

## Snapshot recommendation

```
Proxmox → VM 104 → Snapshots → Take snapshot
Name: dmz-wazuh-agent-cowrie-ingest
Description: Wazuh agent enrolled (groups linux+dmz), Cowrie JSON ingested, end-to-end Cowrie alerts validated in dashboard
```

This snapshot is the one to use as the demo baseline for the SSH-bruteforce attack scenario.

---

**Next:** [07-suricata-pfsense.md →](07-suricata-pfsense.md)
