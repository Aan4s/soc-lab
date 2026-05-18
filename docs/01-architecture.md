# 01 — Architecture

> Reference document describing the technical architecture of the SOC Lab project, design choices, and their justifications.

**Author:** Anass CHAMMAMI <br>
**Project:** TER - Master 1 Cybersecurity, UGA IM2AG <br>
**Status:** Design phase - POC validation pending <br>
**Last updated:** May 2026 <br>

---

## Table of contents

1. [Overview](#1-overview)
2. [IP addressing plan](#2-ip-addressing-plan)
3. [VLAN details](#3-vlan-details)
4. [Software stack](#4-software-stack)
5. [Flows and communications](#5-flows-and-communications)
6. [Design choices and justifications](#6-design-choices-and-justifications)
7. [Sizing and performance](#7-sizing-and-performance)
8. [Security of the architecture](#8-security-of-the-architecture)
9. [Limitations and assumptions](#9-limitations-and-assumptions)


---

## 1. Overview

### 1.1 Architecture purpose

This architecture defines a **virtualized SOC environment** that reproduces the key characteristics of an enterprise information system, scaled down to a single physical host. It is designed as a learning, demonstration, and operational training platform for a future SOC analyst role.

The architecture covers four dimensions of a modern Security Operations Center:

- **Visibility** — centralized log collection across endpoints, network, and applications
- **Detection** — correlation rules mapped to the MITRE ATT&CK framework
- **Investigation** — analyst workflows aligned with NIST SP 800-61
- **Deception** — honeypot-based detection of unauthorized activity

The intent is not to simulate a large enterprise (tens of thousands of endpoints), but to **reproduce the attack and detection patterns** that exist at any scale. A SOC analyst working in a 50-endpoint SME or a 50,000-endpoint multinational deals with the same fundamentals: log ingestion, rule writing, alert triage, and incident response.

### 1.2 Guiding principles

The architecture is governed by five principles that drive every technical choice:

| Principle | Application in this architecture |
|---|---|
| **Network segmentation** | Five distinct VLANs, with all inter-VLAN traffic routed and filtered through a central firewall |
| **Least privilege** | No flow is allowed by default; each authorized communication is explicitly justified |
| **Defense in depth** | Detection happens at four independent layers: network (Suricata), endpoint (Sysmon + Wazuh agents), application (web server logs), and behavioral (Wazuh correlation rules) |
| **Observability first** | Every notable event is logged and centralized in the SIEM; no detection without telemetry |
| **Reproducibility** | All configurations are versioned in Git and documented; the entire lab can be rebuilt from the repository |

These principles are not academic — they map directly to the **NIST Cybersecurity Framework** (Identify, Protect, Detect, Respond, Recover) and to the operational practices of any mature SOC.

### 1.3 Reference diagrams

The architecture is described visually in one network diagram stored in the repository:

| Diagram | File | Purpose |
|---|---|---|
| Network topology | `diagrams/soc-lab-architecture.png` | Global view of VLANs and flows |


This document describes the **textual companion** to this diagram.

### 1.4 The Purple Team approach

A central methodological choice of this project is the **Purple Team** approach: the same operator alternates between offensive (Red Team) and defensive (Blue Team) postures.

This choice has three justifications:

1. **Pedagogical** — understanding detection requires understanding attacks, and vice versa. A SOC analyst who has never executed a Kerberoasting attack will struggle to write a meaningful detection rule for it.
2. **Operational realism** — modern SOC teams increasingly adopt purple-team practices to validate their detection coverage. The methodology is industry-aligned.
3. **Scope efficiency** — for a solo project, having a single operator play both roles allows tight feedback loops between attack execution and detection tuning.

The Purple Team workflow is formalized in the `attack-scenarios-playbook.md` document: each of the eight scenarios prescribes the attack execution, the expected telemetry, the detection rule, and the SOC response procedure.

### 1.5 Scope and out of scope

To stay focused and deliverable within the project timeline, the scope is explicitly bounded.

**In scope:**

- A five-VLAN virtualized network with central firewall
- An Active Directory domain with one Domain Controller and two Windows 10 endpoints
- A DMZ with one intentionally vulnerable web application (DVWA), one weak SSH server, and one Cowrie honeypot
- A complete SOC stack (Wazuh SIEM, Elastic Stack, Suricata IDS)
- Endpoint visibility through Sysmon and Wazuh agents
- Eight end-to-end attack scenarios with corresponding detection rules
- Detection rule mapping to MITRE ATT&CK
- Incident response runbooks aligned with NIST SP 800-61

**Out of scope:**

- Multi-tenant or multi-site architecture
- Cloud workload protection (no AWS/Azure/GCP integration)
- Email security (no Exchange server, no anti-phishing gateway)
- Endpoint Detection and Response (EDR) commercial products
- Compliance audits (ISO 27001, PCI-DSS, etc.)
- High availability and disaster recovery of the SIEM itself
- Production-grade hardening of the SIEM components

These exclusions are deliberate. Including them would either dilute the educational focus or require resources beyond a single-host virtualized environment.

---

## 2. IP addressing plan

### 2.1 Subnet allocation

The lab uses the private RFC 1918 address space `10.10.0.0/16`, subdivided into five `/24` networks. The third octet of each subnet **matches the VLAN identifier**, which makes log triage and traffic analysis significantly faster: an IP address immediately reveals which VLAN it belongs to.

| VLAN | Name | Subnet | Gateway | DHCP range | Role |
|------|------|--------|---------|------------|------|
| 10 | Attack | 10.10.10.0/24 | 10.10.10.1 | .50 – .100 | Offensive platform |
| 20 | Corporate | 10.10.20.0/24 | 10.10.20.1 | .50 – .100 | AD domain + user endpoints |
| 30 | DMZ | 10.10.30.0/24 | 10.10.30.1 | static only | Exposed services + honeypot |
| 40 | SOC | 10.10.40.0/24 | 10.10.40.1 | static only | Detection stack |
| 50 | Analyst | 10.10.50.0/24 | 10.10.50.1 | .50 – .100 | Investigation workstation |

The gateway of each VLAN is always `.1`, which is a widely adopted convention and reduces cognitive load when reading configuration files. DHCP is enabled only on VLANs where dynamic addressing is acceptable (Attack, Corporate user side, Analyst). DMZ and SOC servers use static IPs because their addresses appear in firewall rules, detection rules, and dashboards — they must be stable.

### 2.2 Static host addressing

The following hosts have permanent IP addresses and stable hostnames. Hostnames follow the convention `<role>.<vlan-name>` to keep them human-readable.

| IP address | Hostname | Role |
|------------|----------|------|
| 10.10.10.10 | `kali.attack` | Primary offensive platform |
| 10.10.20.10 | `dc.corp.lab` | Domain Controller (AD + DNS + DHCP for domain) |
| 10.10.20.20 | `win10-1.corp.lab` | User endpoint #1 |
| 10.10.20.21 | `win10-2.corp.lab` | User endpoint #2 |
| 10.10.30.10 | `honey.dmz` | Cowrie SSH honeypot |
| 10.10.30.20 | `web.dmz` | Ubuntu server hosting DVWA |
| 10.10.30.30 | `ssh-vuln.dmz` | Ubuntu server with weak SSH credentials |
| 10.10.40.10 | `wazuh.soc` | Wazuh Manager |
| 10.10.40.20 | `elastic.soc` | Elasticsearch + Kibana |
| 10.10.40.30 | `suricata.soc` | Suricata IDS sensor |
| 10.10.50.10 | `analyst.soc` | Analyst workstation |
| 10.10.50.20 | `thehive.soc` | TheHive + MISP *(optional, bonus phase)* |

The `.10` suffix is consistently used for the primary host in each VLAN, with `.20`, `.21`, `.30` used for additional hosts. This regularity makes the topology easier to memorize and discuss verbally.

### 2.3 DHCP configuration per VLAN

DHCP is served by pfSense on the VLANs that require dynamic addressing. Each pool reserves the first 49 addresses for static assignments and infrastructure use.

| VLAN | DHCP enabled | Pool | Lease duration | Notes |
|------|--------------|------|----------------|-------|
| 10 (Attack) | Yes | .50–.100 | 7 days | For ephemeral attack VMs |
| 20 (Corporate) | Partially | .50–.100 | 7 days | DC and clients have static reservations |
| 30 (DMZ) | No | — | — | All hosts are statically configured |
| 40 (SOC) | No | — | — | All hosts are statically configured |
| 50 (Analyst) | Yes | .50–.100 | 7 days | For analyst session flexibility |

The decision to disable DHCP on DMZ and SOC is intentional: production SOCs use static addressing for any server that appears in security rules, because IP rotation would silently break detections.

### 2.4 DNS and name resolution

Two DNS resolution paths coexist in the lab:

1. **Internal DNS** — for the `corp.lab` Active Directory domain, the Domain Controller (`10.10.20.10`) acts as the authoritative DNS server. All Windows endpoints are configured to query the DC for AD-related records (`_kerberos._tcp.corp.lab`, etc.).
2. **External DNS** — for general Internet resolution (Wazuh agents fetching updates, ISO downloads, etc.), pfSense acts as a DNS resolver and forwards queries upstream.

For non-AD Linux servers (DMZ and SOC), hostname resolution is handled either through static `/etc/hosts` entries or through pfSense's resolver. This separation prevents the AD DNS from becoming a bottleneck or a single point of failure for the SOC stack.

A dedicated `corp.lab` DNS zone is configured on the Domain Controller with the following records:

- `dc.corp.lab` → 10.10.20.10
- `win10-1.corp.lab` → 10.10.20.20
- `win10-2.corp.lab` → 10.10.20.21
- Service Principal Names (SPNs) for AD services
- One intentionally weak SPN (`MSSQLSvc/sql.corp.lab:1433`) used for the Kerberoasting scenario

---

## 3. VLAN details

This section describes each of the five VLANs in depth: its role in the architecture, the virtual machines it hosts, their sizing, and the design rationale that led to this configuration.

### 3.1 VLAN 10 — Attack

#### Role

VLAN 10 hosts the **offensive platform** used to execute the eight attack scenarios. It is the source of all simulated adversarial activity in the lab. In a real-world SOC scope, this VLAN represents either an external attacker on the Internet, or an insider threat with network access, depending on the scenario being executed.

#### Components

| Component | Software | Purpose |
|-----------|----------|---------|
| Kali Linux | Kali 2026.x | Primary offensive distribution |
| Recon tools | Nmap, Gobuster, Nikto | Network and web reconnaissance |
| Exploitation tools | sqlmap, Hydra, Metasploit | Web and credential attacks |
| AD attack tools | Impacket, BloodHound, Rubeus | Active Directory exploitation |
| Adversary emulation | MITRE Caldera, Atomic Red Team | Structured TTP execution |

#### Sizing

| Resource | Value | Justification |
|----------|-------|---------------|
| vCPU | 2 | Sufficient for most attack tools; sqlmap and hashcat occasionally need more |
| RAM | 4 GB | Comfortable for parallel browser, terminal, and tool execution |
| Disk | 40 GB | Includes Kali tools, wordlists (rockyou), and captured loot |

#### Design rationale

Placing the attacker in a **dedicated VLAN** rather than directly on the host network has three benefits. First, it forces all attack traffic to traverse the firewall, where it can be logged and filtered, mirroring how real attackers reach a network. Second, it allows network-level detection rules to use the attacker's IP range as a known indicator. Third, it preserves the option to add additional attack vectors later (a second Kali, a Caldera Red C2 server) without restructuring the network.

The choice of Kali Linux over alternatives (Parrot OS, BlackArch) is pragmatic: Kali has the largest ecosystem, the best documentation, and is the de facto standard in offensive security education.

### 3.2 VLAN 20 — Corporate

#### Role

VLAN 20 represents the **corporate user network**: where the employees, their workstations, and the Active Directory domain live. It is the high-value target of the lab — the equivalent of "what the attacker is ultimately after" in a real intrusion. Successful compromise of this VLAN means the attacker has reached the crown jewels: domain admin credentials, internal data, and lateral movement opportunities.

#### Components

| Component | Software | Purpose |
|-----------|----------|---------|
| Domain Controller | Windows Server 2022 Eval | AD DS, DNS, DHCP for the domain |
| User endpoint #1 | Windows 10 Enterprise Eval | Employee workstation, domain-joined |
| User endpoint #2 | Windows 10 Enterprise Eval | Employee workstation, domain-joined |
| Endpoint visibility | Sysmon (SwiftOnSecurity config) | Detailed process and network telemetry |
| Log shipper | Wazuh agent | Forwards events to Wazuh Manager |

#### Sizing

| VM | vCPU | RAM | Disk |
|----|------|-----|------|
| DC | 2 | 4 GB | 60 GB |
| Win10 #1 | 2 | 4 GB | 50 GB |
| Win10 #2 | 2 | 4 GB | 50 GB |

#### Design rationale

The domain is named `corp.lab` — a generic name that mirrors real corporate naming conventions without resembling any specific organization. Two user endpoints are deployed (rather than one) for two reasons: first, lateral movement scenarios require at least two machines to demonstrate movement; second, having two endpoints allows comparing detection coverage when only one is compromised.

Five fictitious users are created during the AD setup phase, organized in three OUs (`Users`, `Admins`, `Service Accounts`). One service account is deliberately configured with a weak password and an associated SPN, enabling the Kerberoasting scenario.

The decision to use **evaluation editions** of Windows Server and Windows 10 is legal and pragmatic: the 180-day evaluation period is sufficient for the project, and these editions are functionally identical to the licensed versions for all SOC-relevant features.

### 3.3 VLAN 30 — DMZ

#### Role

VLAN 30 hosts services that are conceptually **exposed to untrusted networks**. In a real enterprise, this is where web servers, mail relays, and remote-access gateways live. In this lab, it serves two purposes simultaneously: hosting **realistically vulnerable services** that the attacker can compromise, and hosting a **honeypot** that captures unauthorized interaction attempts.

#### Components

| Component | Software | Purpose |
|-----------|----------|---------|
| Vulnerable web app | DVWA (Docker) | SQLi, XSS, RCE, file upload exercises |
| Vulnerable SSH server | OpenSSH on Ubuntu with weak credentials | SSH brute-force target |
| SSH honeypot | Cowrie | Captures unauthorized SSH attempts |
| Endpoint visibility | Wazuh agent + File Integrity Monitoring | Detects web shell uploads, log tampering |
| Log shipper (honeypot) | Filebeat | Ships Cowrie JSON logs to Wazuh |

#### Sizing

| VM | vCPU | RAM | Disk |
|----|------|-----|------|
| Web (DVWA host) | 2 | 2 GB | 20 GB |
| SSH (vulnerable) | 2 | 2 GB | 20 GB |
| Cowrie honeypot | 2 | 2 GB | 20 GB |

#### Design rationale

The DMZ contains **three distinct VMs** rather than colocating services on one host. This separation reflects production practice: a real DMZ never runs the honeypot and the production web server on the same machine, because a compromise of either would taint the other.

A subtle but important design choice is the **placement of the honeypot alongside the real targets**. This allows side-by-side comparison: the same attacker scanning the DMZ will hit both the vulnerable SSH server and the Cowrie honeypot. The SOC analyst can then compare the visibility provided by each, which is a powerful demonstration of deception's value.

The web target uses **DVWA in a Docker container** rather than installing a vulnerable application natively. This is faster, more reproducible, and isolates the vulnerability from the underlying OS — meaning that exploits stay within the container by default. The container is configured with the host's web port published, so externally it looks like a normal vulnerable web server.

### 3.4 VLAN 40 — SOC

#### Role

VLAN 40 is the **operational heart of the project**: where the SIEM, the IDS, and the log indexing layer live. Every meaningful event from every other VLAN is collected, normalized, correlated, and stored here. This VLAN is also the most resource-intensive of the lab.

#### Components

| Component | Software | Purpose |
|-----------|----------|---------|
| SIEM Manager | Wazuh Manager 4.14.5 | Receives logs, applies rules, generates alerts |
| Search and storage | Elasticsearch 8.x | Stores indexed events |
| Visualization | Kibana 8.x | Dashboards and search interface |
| Network IDS | Suricata 8.0.4 | Inspects network traffic for known signatures |
| Threat feeds | Emerging Threats Open ruleset | Free, community-maintained Suricata rules |

#### Sizing

| VM | vCPU | RAM | Disk |
|----|------|-----|------|
| Wazuh Manager | 4 | 8 GB | 80 GB |
| Elastic + Kibana | 4 | 8 GB | 80 GB |
| Suricata | 2 | 4 GB | 40 GB |

#### Design rationale

The decision to **separate the Wazuh Manager from the Elastic Stack** (rather than the Wazuh all-in-one deployment) reflects a production-style architecture. In real deployments, the SIEM correlation engine and the search backend scale independently and have very different resource profiles. Keeping them in separate VMs in the lab mirrors that reality and makes it possible to apply realistic tuning.

Suricata runs in its own VM and receives a **mirrored copy** of network traffic. In a production environment this is achieved via a SPAN port on a managed switch; in this lab, it is implemented through VMware's network promiscuity settings on the dedicated `VMnet-SOC` interface. Suricata writes alerts to `eve.json`, which is then shipped to Wazuh via Filebeat, allowing all alerts (network and endpoint) to be correlated in a single pane of glass.

A common alternative is **the ELK Stack with Filebeat and Logstash** (without Wazuh). Wazuh was chosen over this approach because it provides out-of-the-box endpoint agents, file integrity monitoring, rootcheck, vulnerability detection, and a mature rule library — features that would require significant custom development on a pure ELK stack. The full justification of this choice appears in section 6.

### 3.5 VLAN 50 — Analyst

#### Role

VLAN 50 hosts the **human-operated investigation workstation**. It is intentionally separated from VLAN 40 (where the SOC servers run) to enforce a key principle: the analyst is a **consumer** of the SOC services, not an administrator of the SIEM internals. This separation reduces the privilege exposure and reflects the organization of mature SOC teams.

#### Components

| Component | Software | Purpose |
|-----------|----------|---------|
| Analyst workstation | Ubuntu Desktop 22.04 | Primary investigation environment |
| Web access | Firefox / Chromium | Kibana UI, MITRE Navigator, OSINT lookups |
| Investigation tools | Wireshark, jq, terminal | Packet analysis, log parsing |
| Case management *(bonus)* | TheHive 5 | Incident ticketing aligned with NIST 800-61 |
| Threat intel *(bonus)* | MISP | IOC sharing and correlation |
| Reporting | OBS Studio, Flameshot | Video recording and annotated screenshots |

#### Sizing

| VM | vCPU | RAM | Disk |
|----|------|-----|------|
| Analyst workstation | 2 | 4 GB | 40 GB |
| TheHive + MISP *(bonus)* | 4 | 6 GB | 60 GB |

#### Design rationale

The choice of **Ubuntu Desktop** over Windows 10 for the analyst workstation reflects a common pattern in modern SOC teams: many analysts work from Linux because most investigation tools, log-parsing utilities, and scripting environments are native to Unix. Using Ubuntu also keeps the lab resource-efficient, with no Windows licensing concerns.

The analyst workstation is **not joined to the corp.lab domain**. This is a deliberate security choice that follows the principle of separation of duties: a SOC analyst monitoring a network should not be authenticated against the same identity provider as the network they monitor. This prevents a compromise of the domain from automatically compromising the SOC view.

The bonus TheHive + MISP stack is described as optional because its deployment, while valuable, is significant. If included, it transforms the analyst experience from "watching dashboards" to "managing an incident lifecycle with proper case files and threat intelligence enrichment" — bringing the lab from intermediate to advanced maturity.

---

## 4. Software stack

This section describes each technology layer in the lab, including the specific version retained, the role it plays, and the alternatives that were considered.

### 4.1 Hypervisor — VMware Workstation Pro 25H2

**Role.** Hosts all virtual machines and provides the virtual networking layer (VMnets) that materializes the five logical zones of the architecture.

**Version.** Workstation Pro 25H2 (new calendar versioning, equivalent of the former 17.7.x branch). Free for personal and educational use since the November 2024 Broadcom policy change.

**Why this choice.** Three reasons. First, Workstation Pro is the industry-standard hypervisor on desktop, mirroring what is used in enterprise IT operations (with vSphere/ESXi as its server-side counterpart). Second, its virtual network editor allows creating multiple isolated host-only networks with per-subnet DHCP control, which is exactly what the architecture requires. Third, its snapshot system enables rapid rollback between architectural states — critical for an iterative project where misconfigurations are expected.

**Alternatives considered.**

- *VirtualBox* — free and simpler, but its networking is more limited (no fine-grained DHCP per host-only network) and its performance is noticeably lower at this VM count.
- *Hyper-V* — Windows-native, but conflicts with Workstation Pro on the same host and is less natural for mixed Linux/Windows fleets.
- *Proxmox* — production-grade hypervisor, but requires a dedicated host and a different operational mindset (web-based, no desktop integration).

Workstation Pro offers the best balance for a single-host lab targeting an SOC analyst skill profile.

### 4.2 Firewall and router — pfSense CE 2.7

**Role.** Central routing and filtering between the five VLANs, plus DHCP and DNS services. pfSense is the only component that touches every VLAN.

**Version.** pfSense Community Edition 2.7.x on FreeBSD 14.

**Why this choice.** pfSense is the de facto open-source firewall in SME and lab environments. Its web interface is mature, its rule syntax is explicit (PF-based), and it offers all the services this lab needs without requiring additional VMs: DHCP, DNS resolver, syslog client, NAT, traffic shaping, IDS hooks. Crucially, pfSense supports many WAN/LAN interfaces simultaneously, which lets a single VM act as the inter-VLAN router for the entire lab.

**Alternatives considered.**

- *OPNsense* — a fork of pfSense with a more modern UI. Technically equivalent, but pfSense has a larger community knowledge base, which matters for a project where time is limited.
- *VyOS* — CLI-only, closer to Cisco-style configuration. More authentic to enterprise practice but steeper learning curve.
- *A Linux router with iptables/nftables* — more flexible but requires significantly more setup effort and produces less professional artifacts (no web UI to screenshot for the report).

pfSense is the right balance of professional output and reasonable setup time.

### 4.3 SIEM — Wazuh 4.14.5 + Elastic Stack 8.x

**Role.** Wazuh is the central detection engine: it collects logs, applies correlation rules, and generates alerts. The Elastic Stack provides searchable storage and visualization through Kibana.

**Version.** Wazuh 4.14.5 (April 2026 release) for the manager and agents. Elasticsearch and Kibana in their compatible versions.

**Why this choice.** Wazuh combines in a single platform what would otherwise require multiple commercial products: HIDS (host intrusion detection), FIM (file integrity monitoring), rootcheck, vulnerability assessment, log management, and SCA (security configuration assessment). It is open-source, well-documented, MITRE ATT&CK-aware in its built-in rules, and used in production by thousands of organizations including MSSPs.

**Alternatives considered.**

- *Splunk Free* — industry standard, but the free edition has a 500 MB/day ingestion limit and no alerting, making it unsuitable for a real SOC simulation.
- *Pure ELK Stack (Elasticsearch + Logstash + Kibana + Beats)* — fully open-source but requires building correlation logic from scratch (writing detection rules in Watcher or Sigma converters). Wazuh provides this layer ready-to-use.
- *Security Onion* — an excellent all-in-one SOC distribution, but its monolithic nature makes it harder to demonstrate individual component understanding.
- *Graylog* — capable log manager but lighter on detection capabilities than Wazuh.

The Wazuh + Elastic combination provides the maximum learning value per hour invested: it exposes both the SIEM correlation logic (Wazuh) and the search/visualization layer (Elastic), which are two distinct skill domains in real SOC operations.

### 4.4 Network IDS — Suricata 8.0.4

**Role.** Passive network traffic inspection. Suricata receives a mirrored copy of network traffic and matches it against signature-based rules to detect known attack patterns (port scans, web exploits, malware C2 traffic, etc.).

**Version.** Suricata 8.0.4 (March 2026), the latest stable release.

**Why this choice.** Suricata is the modern successor to Snort, with a multi-threaded engine, native JSON output (eve.json), and excellent integration with the Emerging Threats (ET) rule ecosystem. Its eve.json output can be directly ingested by Wazuh via Filebeat, allowing network alerts to be correlated with endpoint events in a single SIEM pane.

**Alternatives considered.**

- *Snort 3* — historically the dominant IDS, now improved with a more modern engine, but Suricata has overtaken it in adoption and active development.
- *Zeek (Bro)* — more powerful for traffic analysis and metadata extraction, but its scripting language has a steep learning curve and its detection capabilities are not signature-based, making it complementary to (not a replacement for) Suricata.

A more mature lab would run both Suricata and Zeek side by side. For this project, Suricata alone covers the signature-based detection needs.

### 4.5 Endpoint visibility — Sysmon + Wazuh agents

**Role.** On Windows endpoints, Sysmon (System Monitor by Microsoft Sysinternals) augments the native Windows Event Log with extremely detailed process, network, and registry telemetry. The Wazuh agent then ships these events, together with standard Windows Event Logs, to the Wazuh Manager.

**Sysmon configuration.** The lab uses the **SwiftOnSecurity Sysmon configuration**, the de facto community baseline. It is opinionated, well-commented, and tuned to balance visibility with log volume. Custom additions can be layered on top for project-specific scenarios (e.g., logging access to honeypot-related paths).

**Why this choice.** Sysmon is free, lightweight, and effectively a prerequisite for any serious Windows SOC. The combination of Sysmon (for granular events) and Wazuh agent (for shipping) replicates what an EDR product provides at a fraction of the cost — perfect for a learning environment.

**Alternatives considered.**

- *Native Windows Event Log only* — insufficient. The default audit policy does not log process creation with full command lines, which is a critical detection signal.
- *Velociraptor or osquery* — both excellent for endpoint visibility, but they overlap rather than complement Sysmon's per-event telemetry. They would be the next addition in a more advanced lab iteration.

### 4.6 Honeypot — Cowrie

**Role.** Cowrie is a medium-interaction SSH and Telnet honeypot. It emulates a Linux shell, captures every command the attacker types, downloads any payload they try to drop, and logs everything in structured JSON.

**Why this choice.** Cowrie is mature, well-maintained, easy to deploy via Docker, and produces high-signal logs: any interaction with the honeypot is by definition suspicious, since no legitimate user should ever connect to it. Its JSON output integrates cleanly with Wazuh via Filebeat.

**Alternatives considered.**

- *T-Pot* — a multi-protocol honeypot suite (SSH, HTTP, Telnet, MQTT, etc.) maintained by Deutsche Telekom. Powerful but heavyweight (8 Go RAM, full Elastic stack of its own). Overkill for the lab's scope.
- *Dionaea* — captures malware via SMB/FTP/HTTP. Useful but specialized; less educational value than Cowrie for the scenarios in this project.

Cowrie provides the maximum educational return per Go of RAM consumed.

### 4.7 Offensive tools — Kali Linux 2026.x and adversary emulation frameworks

**Role.** Kali is the operator's offensive platform. It is used to execute the eight attack scenarios documented in the playbook.

**Tool selection.** The lab makes deliberate use of these tool families:

- *Reconnaissance:* Nmap, Gobuster, Nikto
- *Web exploitation:* sqlmap, Hydra, Burp Suite Community
- *Active Directory:* Impacket suite (`GetUserSPNs`, `secretsdump`, `psexec`), BloodHound (with BloodHound.py collector for cross-platform use), Rubeus
- *Adversary emulation:* MITRE Caldera (server + agents), Atomic Red Team (atomic test framework)

**Why both manual tools and emulation frameworks?** Manual tools (Hydra, sqlmap) teach the analyst what an attack looks like at the wire level. Emulation frameworks (Caldera, Atomic) allow running large numbers of MITRE-mapped techniques quickly to validate detection coverage. Both perspectives are needed in a Purple Team setting.

### 4.8 Bonus stack — TheHive 5, MISP, Shuffle

**Role.** Optional components added if time permits, transforming the lab from an SIEM-centric environment into a full SOC platform.

- *TheHive 5* — incident case management. Alerts from Wazuh are converted into cases, which the analyst processes through the full NIST 800-61 lifecycle (triage, investigation, containment, eradication, recovery, lessons learned).
- *MISP* — Malware Information Sharing Platform. Stores Indicators of Compromise (IOCs) and shares them across investigations.
- *Shuffle* — open-source SOAR. Automates response workflows (e.g., on a high-severity alert: enrich with VirusTotal, block IP at pfSense, create TheHive case, notify via Slack).

**Why optional.** Deploying these three adds approximately one full day of work and demands continuous resource availability. The core architecture is complete and defensible without them. They are positioned as differentiators: if delivered, they place the project at the maturity level of a small MSSP's tooling stack — a significant CV asset.

---

## 5. Flows and communications

### 5.1 Authorized flow matrix

The architecture defines an explicit matrix of authorized flows between VLANs. Any flow not in this matrix is denied by default at the pfSense firewall.

| From → To | VLAN 10 (Attack) | VLAN 20 (Corp) | VLAN 30 (DMZ) | VLAN 40 (SOC) | VLAN 50 (Analyst) |
|-----------|:----------------:|:--------------:|:-------------:|:-------------:|:-----------------:|
| **VLAN 10 (Attack)** | — | ✅ (scenarios) | ✅ (scenarios) | ❌ | ❌ |
| **VLAN 20 (Corp)** | ❌ | — | ❌ | ✅ (logs) | ❌ |
| **VLAN 30 (DMZ)** | ❌ | ⚠️ (scenarios only) | — | ✅ (logs) | ❌ |
| **VLAN 40 (SOC)** | ❌ | ❌ | ❌ | — | ⚠️ (HTTPS) |
| **VLAN 50 (Analyst)** | ❌ | ❌ | ❌ | ✅ (HTTPS to Kibana) | — |

Legend:
- ✅ Authorized by design
- ⚠️ Authorized only for specific protocols/ports
- ❌ Denied by default

**Key principles encoded in this matrix:**

1. The **attacker zone** can reach the targets but never the SOC or the analyst — mirroring how an external attacker cannot directly compromise security tooling without first achieving a foothold elsewhere.
2. The **DMZ** can only reach the **Corporate zone** via the attack flow in Scenario 5 (SSH pivot using a stolen key). This is an intentional misconfiguration meant to be detected.
3. The **SOC** is a sink — it receives logs but does not initiate connections inward. This protects it from being weaponized if compromised.
4. The **analyst** has read-only HTTPS access to Kibana but cannot SSH into SIEM components — enforcing the consumer/producer separation discussed in 3.5.

### 5.2 Log flows toward the SIEM

All collected telemetry converges on the Wazuh Manager (`10.10.40.10`), which is the single ingestion point of the SOC. From there, indexed events flow to Elasticsearch (`10.10.40.20`).

| Source | Transport | Protocol | Port |
|--------|-----------|----------|------|
| Wazuh agents on Windows (VLAN 20) | Wazuh agent protocol | TCP | 1514 |
| Wazuh agents on Linux (VLANs 30, 40) | Wazuh agent protocol | TCP | 1514 |
| Cowrie honeypot (VLAN 30) | Filebeat → Wazuh | TCP | 5044 |
| Suricata IDS (VLAN 40) | Filebeat → Wazuh | TCP | 5044 |
| pfSense firewall | Syslog | UDP | 514 |
| Wazuh Manager → Elasticsearch | Wazuh indexer module | HTTPS | 9200 |

Two distinct ingestion paths exist on purpose. Native Wazuh agents use the Wazuh-specific protocol on port 1514 (encrypted with pre-shared keys). External data sources that don't have a Wazuh agent (Suricata eve.json, Cowrie JSON, etc.) are shipped through Filebeat into Wazuh's Filebeat-compatible ingestion endpoint on port 5044. This dual-path approach mirrors real SOC implementations and demonstrates an understanding of Wazuh's flexibility.

### 5.3 Simulated attack flows

The eight attack scenarios produce specific, predictable flows between VLANs. These flows are documented in detail in the `attack-scenarios-playbook.md`. As a summary:

| Scenario | Source | Destination | Flow |
|----------|--------|-------------|------|
| 1. Recon | Kali (VLAN 10) | VLAN 30 (DMZ) | TCP scan, all ports |
| 2. SSH brute | Kali | DMZ Ubuntu SSH | TCP/22, repeated auth attempts |
| 3. SQLi | Kali | DMZ DVWA | HTTP/80, malformed queries |
| 4. Web shell | Kali | DMZ DVWA | HTTP/80, file upload + RCE |
| 5. Pivot | DMZ | VLAN 20 (Corp jumpbox) | TCP/22 with stolen SSH key |
| 6. BloodHound | Compromised Corp endpoint | DC | LDAP/389, SMB/445 |
| 7. Kerberoasting | Corp endpoint | DC | Kerberos/88 |
| 8. Full kill chain | Multiple | Multiple | Combination of the above |

Each of these flows triggers detection logic in either Suricata (network) or Wazuh (endpoint), and often both. The redundancy is intentional: a mature SOC should be able to detect the same attack from multiple angles.

### 5.4 pfSense firewall policy

The pfSense ruleset is organized in three explicit layers:

1. **Default deny.** A bottom rule on every interface drops any flow not explicitly allowed.
2. **Service rules.** Inbound flows to allowed services (e.g., Kali → DMZ on tcp/80, tcp/443, tcp/22) are explicitly authorized.
3. **Logging rules.** All denied flows are logged and shipped to Wazuh via syslog, creating visibility on unauthorized lateral movement attempts.

This structure follows the **deny-by-default + explicit-allow** model that is universally recommended in enterprise firewall design.

---

## 6. Design choices and justifications

This section addresses the "why" behind the key architectural decisions. Each justification is structured to be reusable during the project defense.

### 6.1 Why pfSense rather than OPNsense or Cisco virtual?

pfSense was retained for three reasons. First, it has the largest community documentation in the open-source firewall space, which translates into faster troubleshooting during the project. Second, its native multi-WAN/multi-LAN support without additional licensing fits the five-VLAN architecture out of the box. Third, the Web UI is mature enough to produce professional screenshots for the final report — a tangible deliverable benefit.

OPNsense is technically equivalent and was a close runner-up; the choice reduces to ecosystem maturity. Cisco virtual appliances would have brought authenticity but require licensing and a steeper configuration learning curve incompatible with the project timeline.

### 6.2 Why Wazuh rather than pure ELK or Splunk?

Three considerations led to Wazuh.

First, **time efficiency.** Wazuh ships with a built-in rule library covering hundreds of detection use cases out of the box. Achieving the same coverage on pure ELK would require writing every rule from scratch.

Second, **endpoint integration.** Wazuh agents are first-class citizens: they provide log forwarding, FIM, rootcheck, SCA, and vulnerability detection without additional software. With ELK, each of these would require a separate Beat or third-party tool.

Third, **CV value.** Wazuh has gained significant market share in European SOCs and MSSPs. Knowing it is a transferable skill. Pure ELK without a SIEM layer is less recognized as a "SOC competence."

Splunk Free was excluded for licensing reasons (volume cap, no alerting); the commercial editions are out of scope.

### 6.3 Why five VLANs and not three?

A simpler architecture with three zones (Internal / DMZ / SOC) would have worked, but five zones provide three concrete benefits.

First, **separation between attacker and corporate users.** Putting Kali in its own VLAN allows the firewall to log attack flows distinctly from legitimate user traffic, simplifying detection.

Second, **separation between SOC servers and the analyst workstation.** The principle of least privilege dictates that an analyst's browser should not run on the same network as the SIEM database. With five VLANs, a compromise of the analyst workstation does not give direct access to the SIEM internals.

Third, **realism.** Mature enterprise networks routinely have dozens of VLANs. Demonstrating an understanding of why segmentation matters — and applying it pragmatically at five zones — is more representative of real operations than collapsing everything into three.

### 6.4 Why a separate DMZ rather than putting the vulnerable services in the Corp network?

This is a common question, and the answer is foundational. In enterprise networks, public-facing or exposed services are **always** placed in a DMZ for one reason: if they get compromised, the attacker is contained in a low-trust zone and must still pivot to reach high-value assets. Replicating this pattern in the lab does two things: it makes the attack scenarios more educational (Scenario 5 specifically exercises the DMZ-to-Corp pivot), and it demonstrates architectural literacy to the project's evaluators.

Collapsing DMZ into Corp would also short-circuit the deception value of the honeypot: a Cowrie deployed alongside production endpoints would generate false positives every time a legitimate process scans the network.

### 6.5 Why include a honeypot?

The honeypot is not strictly necessary for the SOC to function, but its inclusion is high-value for three reasons.

First, **detection signal-to-noise ratio.** Any connection to the honeypot is by definition suspicious. Detection rules built on honeypot interactions have near-zero false positives, which is rare and valuable.

Second, **threat intelligence.** Cowrie captures the actual passwords, commands, and payloads that attackers attempt. This produces real-world IOCs that can feed MISP (in the bonus phase) and demonstrate the upstream side of threat intelligence sharing.

Third, **CV differentiation.** Deception technology is a topic SOC analyst candidates rarely have hands-on experience with. Having implemented and operated a honeypot is a measurable differentiator in interviews.

### 6.6 Why use MITRE ATT&CK as the central framework?

MITRE ATT&CK has become the industry-standard taxonomy for describing adversary behavior. It serves three functions in this project.

First, it provides **a shared vocabulary** for describing attacks: instead of saying "the attacker dumped credentials," one says "T1003.001 — OS Credential Dumping: LSASS Memory."

Second, it gives a **coverage metric.** By mapping each detection rule to a technique, the project can quantify how much of the ATT&CK matrix it covers — a real-world SOC KPI.

Third, it ensures **continuity with recruiter expectations.** Every modern SOC role posting mentions MITRE ATT&CK literacy. Demonstrating it through the project removes any doubt about the candidate's familiarity.

### 6.7 Why NIST SP 800-61 for the incident response workflow?

The NIST Special Publication 800-61 (Computer Security Incident Handling Guide) is the most widely referenced incident response standard. Its six-phase model (Preparation → Detection & Analysis → Containment → Eradication → Recovery → Post-Incident Activity) is recognized internationally and is the basis of most SOC playbooks.

Aligning the lab's incident response workflow (modeled in the UML activity diagram) on this standard has the same triple benefit as ATT&CK alignment: shared vocabulary, measurable structure, and recruiter-recognized format.

---

## 7. Sizing and performance

### 7.1 Per-VM resource allocation

The total resource budget is constrained by the physical host (64 GB RAM in the target deployment). The following allocation has been validated as feasible while leaving headroom for the host OS and VMware overhead.

| VM | vCPU | RAM | Disk | Reasoning |
|----|------|-----|------|-----------|
| pfSense Firewall | 2 | 2 GB | 20 GB | FreeBSD is lightweight; 2 GB is plenty for routing + DHCP + DNS |
| Kali Linux (Attack) | 2 | 4 GB | 40 GB | Comfortable for parallel tool execution and a browser |
| Windows Server 2022 (DC) | 2 | 4 GB | 60 GB | Microsoft minimum for AD with Desktop Experience |
| Windows 10 Client #1 | 2 | 4 GB | 50 GB | Minimum viable for Windows 10 with Sysmon |
| Windows 10 Client #2 | 2 | 4 GB | 50 GB | Same |
| Ubuntu Web (DVWA host) | 2 | 2 GB | 20 GB | Lightweight Docker host |
| Ubuntu SSH (vulnerable) | 2 | 2 GB | 20 GB | Minimal Ubuntu Server |
| Cowrie Honeypot | 2 | 2 GB | 20 GB | Minimal |
| Wazuh Manager | 4 | 8 GB | 80 GB | Memory-intensive for rule engine + agent management |
| Elasticsearch + Kibana | 4 | 8 GB | 80 GB | Elasticsearch JVM needs 4 GB heap minimum |
| Suricata IDS | 2 | 4 GB | 40 GB | Multi-threaded engine, traffic-volume dependent |
| Analyst Workstation | 2 | 4 GB | 40 GB | Ubuntu Desktop + browser + investigation tools |
| **Total (core)** | **28 vCPU** | **48 GB** | **520 GB** | |
| TheHive + MISP (bonus) | 4 | 6 GB | 60 GB | Two Java applications + databases |
| **Total (with bonus)** | **32 vCPU** | **54 GB** | **580 GB** | |

The 54 GB of RAM at peak utilization leaves approximately 10 GB for the host operating system and VMware overhead, which is sufficient. The 32 vCPU allocation is **oversubscribed** relative to a typical 8-core physical CPU, but this is acceptable: VMs are rarely all CPU-active simultaneously, and VMware's scheduler handles contention gracefully.

### 7.2 Expected processing capacity

Sizing the Wazuh Manager realistically requires an estimate of the **events per second (EPS)** it will need to process. For this lab:

| Source | Estimated EPS at idle | Estimated EPS during attack scenario |
|--------|----------------------:|-------------------------------------:|
| Wazuh agents on DC (Windows logs + Sysmon) | 5 | 50 |
| Wazuh agents on Win10 clients (×2) | 4 | 30 |
| Wazuh agents on DMZ Linux (×3) | 3 | 20 |
| Suricata IDS | 1 | 100 |
| Cowrie honeypot | 0.1 | 10 |
| pfSense syslog | 2 | 20 |
| **Total** | **~15 EPS** | **~230 EPS** |

These figures are conservative and well within Wazuh's documented capacity (a single-node Wazuh manager handles 1,500+ EPS sustained on similar hardware). The lab will never be EPS-bound; bottlenecks, if any, will come from Elasticsearch indexing latency under bursty workloads.

### 7.3 Optimization options

Three optimizations are available if performance becomes constrained during the project:

1. **Selective VM shutdown.** When working on a specific scenario, only the relevant VMs need to run. For example, the Kerberoasting scenario only requires pfSense, the DC, one Windows 10 client, Kali, Wazuh, and Elastic — about 30 GB of RAM. The DMZ and analyst VMs can be temporarily shut down.
2. **Linked clones.** VMware Workstation supports linked clones, where multiple VMs share a base disk and only store their delta. For the two Windows 10 clients (which are nearly identical), this can save 30–40 GB of disk space.
3. **Snapshot management.** Snapshots accumulate disk usage over time. The convention adopted in this lab is to keep one "clean baseline" snapshot per VM and delete intermediate snapshots after each scenario, after the scenario report has been written and committed.

### 7.4 Thematic subsets for constrained environments

If the project must temporarily run on lower-resource hardware (e.g., a personal laptop with 16 GB RAM), the architecture can be partitioned into thematic subsets, each runnable independently:

| Subset | VMs needed | RAM | Use case |
|--------|------------|-----|----------|
| "Recon and SSH" | pfSense + Kali + Ubuntu SSH + Cowrie + Wazuh + Elastic | ~24 GB | Scenarios 1, 2 |
| "Web exploitation" | pfSense + Kali + DVWA + Wazuh + Elastic + Suricata | ~26 GB | Scenarios 3, 4 |
| "AD attacks" | pfSense + Kali + DC + Win10 + Wazuh + Elastic | ~28 GB | Scenarios 5, 6, 7 |
| "Full kill chain" | All VMs | ~48 GB | Scenario 8 (requires the full target host) |

This subset approach is what allows the validation-by-POC strategy to work even on modest hardware: each scenario can be executed and detected on its dedicated subset, with the full architecture documented in design only.

---

## 8. Security of the architecture

The architecture intentionally hosts vulnerable services and offensive tools. This section explains the security boundaries that prevent the lab from becoming a liability to its physical host or to the broader network.

### 8.1 Network isolation

All five VLANs are implemented as **VMware host-only networks** (VMnet2 through VMnet6). Host-only networks have a critical property: they are not routable to any physical network interface. Traffic generated by any VM stays inside the host's virtual switch and is never seen on the LAN that the host is connected to.

The only exception is the WAN side of pfSense, which is bridged through VMware NAT (VMnet8) to provide Internet access for software updates, ISO downloads, and signature updates. **No inbound traffic** from the host's external network can reach the lab VMs.

This dual property — outbound Internet allowed, inbound external traffic blocked — is enforced by two layers:

1. The VMware NAT itself drops all unsolicited inbound connections.
2. pfSense's WAN interface has no port-forwarding rules. Even if VMware NAT were misconfigured, the firewall would reject inbound traffic.

### 8.2 Compartmentalization of vulnerable services

The DMZ hosts deliberately vulnerable services (DVWA, weak SSH credentials). Their containment is enforced at three levels:

1. **VM-level isolation.** Each vulnerable service runs in its own VM. A compromise of DVWA does not give access to the SSH server, and vice versa.
2. **Container-level isolation.** DVWA runs in a Docker container, adding a second isolation layer. A successful RCE in DVWA breaks out into the container, not the host VM directly.
3. **Network-level isolation.** The DMZ VLAN cannot initiate connections to the Corp or SOC zones by default (firewall rules deny by default). The Scenario 5 pivot relies on a deliberately allowed exception that the SOC then detects.

### 8.3 Privilege separation

The principle of least privilege is applied to operational accounts:

- The **Wazuh agent service** runs with minimum required privileges on each host (read-only access to log files, no shell).
- The **analyst workstation** is not joined to the corp.lab domain, preventing identity-based pivots from Corp to Analyst.
- The **Active Directory administrator account** is used only for AD configuration; daily operations on Windows clients use lower-privileged accounts.
- One AD service account (`svc-sql`) has deliberately weak password and SPN — this is intentional bait for the Kerberoasting scenario, **not** an accident.

### 8.4 Sensitive material handling

The lab generates artifacts that could be sensitive if leaked (captured credentials from DVWA exfiltration, password hashes from Kerberoasting, honeypot interaction logs). These artifacts:

- Are **never** committed to the public Git repository.
- Are stored in `/home/<user>/soc-lab-evidence/` on the host, outside the repo working tree.
- The repository's `.gitignore` excludes `evidence/`, `*.pcap`, `*.hashes`, `secrets/`, and similar patterns to prevent accidental commits.
- Reports and scenario documentation use **redacted or fabricated samples**, never real captured data.

### 8.5 Host hardening

The physical host machine running VMware should follow basic hardening practices:

- Full-disk encryption (LUKS for Linux, BitLocker for Windows).
- Automatic screen lock on inactivity.
- Up-to-date OS and VMware patches.
- No unnecessary services exposed on the host's primary network interface.

These practices are not specific to the lab but become non-negotiable when sensitive material may exist on the host (even temporarily).

---

## 9. Limitations and assumptions

A professional architecture document should be honest about its limitations. This section lists the deliberate scope decisions that were made and the assumptions on which the design rests.

### 9.1 Assumed limitations

The architecture is **single-host**. It does not address what happens if the physical machine fails, gets stolen, or becomes unavailable. In a production SOC, this would be a critical concern; in this lab, it is accepted because the project artifacts (rules, dashboards, documentation, scenario reports) live in Git and can be rebuilt from scratch in a few hours.

The lab is **time-bounded**. The Windows evaluation editions expire after 180 days, and the project itself is expected to remain active until August at the latest. Long-term operation would require either purchasing licenses or migrating to alternative OS (e.g., Windows 10 LTSC trials, AlmaLinux replacements).

The SIEM has **no high availability**. The Wazuh Manager and the Elastic node are single points of failure. In production, both would be clustered. Replicating this in a lab adds significant complexity for limited educational return.

The **threat model is artificial**. Real attackers do not stop after eight scenarios. The lab simulates a curated subset of techniques, not the full breadth of the MITRE ATT&CK matrix. The scenarios were chosen for educational coverage, not for statistical representativeness of actual attacks.

### 9.2 Architectural assumptions

The design assumes that the host machine has:

- At least 32 GB of RAM, with 64 GB strongly preferred for the full deployment.
- A modern CPU supporting hardware-assisted virtualization (Intel VT-x or AMD-V) with VT-d/AMD-Vi for IOMMU.
- At least 500 GB of free SSD storage for VM disks, ISOs, and snapshots.
- A reasonably fast Internet connection for the initial setup phase (ISOs total ~25 GB).

It also assumes that the operator has:

- **Local administrator rights** on the physical host (required for VMware installation and virtual network configuration).
- **Time availability** equivalent to the academic project's full-time phase (~4 weeks for a complete deployment plus scenarios, plus documentation time).
- **Foundational familiarity** with Linux command line, Windows administration, and basic networking concepts.

### 9.3 Future evolutions

If the project were to continue past its academic deadline, three evolution paths are natural:

1. **Cloud deployment.** Migrating the SOC stack to AWS or Azure (Terraform-managed) would replicate a modern MSSP setup and add cloud-security telemetry to the detection scope (CloudTrail, Azure Activity Logs).
2. **EDR integration.** Replacing or supplementing Sysmon + Wazuh with a commercial EDR (CrowdStrike Falcon, SentinelOne) would add behavioral detection capabilities and expand the candidate's hands-on tool exposure.
3. **Threat intelligence pipeline.** Connecting MISP to commercial or community feeds (CIRCL, MISP-galaxy, OTX) would automate IOC enrichment and feed detection rules continuously, moving the lab closer to a real CTI program.

These are noted here as roadmap items, not as commitments for the current project.

---
