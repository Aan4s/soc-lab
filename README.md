# 🛡️ Home SOC Lab — Purple Team SIEM Environment

> A fully virtualized Security Operations Center (SOC) lab built from scratch to learn, demonstrate, and operate end-to-end detection capabilities — from log ingestion to incident response, with realistic attack surfaces and honeypots.

**Status:** 🚧 In progress | **Started:** May 2026 | **Author:** Anass CHAMMAMI — Master 1 Cybersecurity, UGA IM2AG

---

## 📌 Project context

This project is conducted as part of the **TER (Travaux d'Études et de Recherche)** at the University Grenoble Alpes (IM2AG) under the "Entreprise" formula, oriented towards an M2 work-study program in cybersecurity.

The goal is to **build, operate and document a complete SOC environment**, mirroring real-world enterprise architectures, in order to develop hands-on skills equivalent to a junior SOC analyst internship.

## 🎯 Objectives

- Deploy a **realistic enterprise-like network** (segmented VLANs, Active Directory, DMZ with exposed services)
- Centralize and analyze logs through a **production-grade SIEM stack** (Wazuh + Elastic)
- Detect attacks using **MITRE ATT&CK-mapped** rules and scenarios
- Simulate **realistic full-chain attacks** (web → pivot → AD → exfiltration) using a Purple Team approach
- Integrate **honeypots and deception** for threat detection
- Document everything as if it were a professional engagement

## 🏗️ Architecture overview

```
┌─────────────────────────────────────────────────────────────────────┐
│                  pfSense (firewall / inter-VLAN router)             │
└─────────────────────────────────────────────────────────────────────┘
        │           │            │            │            │
   ┌────▼───┐  ┌────▼────┐  ┌───▼────┐  ┌────▼────┐  ┌────▼────┐
   │ VLAN10 │  │ VLAN20  │  │ VLAN30 │  │ VLAN40  │  │ VLAN50  │
   │ Attack │  │  Corp.  │  │  DMZ   │  │  SOC    │  │ Analyst │
   │ (Kali) │  │ (AD+PC) │  │(Web/   │  │(Wazuh)  │  │  (Kib.) │
   │        │  │         │  │ SSH/HP)│  │         │  │         │
   └────────┘  └─────────┘  └────────┘  └─────────┘  └─────────┘
```

| Zone        | Components                                                   | Purpose                              |
|-------------|--------------------------------------------------------------|--------------------------------------|
| VLAN 10     | Kali Linux, Caldera, Atomic Red Team                         | Adversary emulation                  |
| VLAN 20     | Windows Server 2022 (AD DC), 2× Windows 10 clients           | Corporate environment (target)       |
| VLAN 30     | DVWA, vulnerable Ubuntu (SSH), Cowrie honeypot               | DMZ — exposed services + deception   |
| VLAN 40     | Wazuh manager, Elasticsearch, Kibana, Suricata IDS           | SOC stack                            |
| VLAN 50     | Analyst workstation, TheHive, MISP (optional)                | Investigation and case management    |

## 🧰 Tech stack

**Hypervisor:** VMware Workstation Pro 17
**Firewall / Router:** pfSense CE
**SIEM / XDR:** Wazuh 4.x + Elasticsearch + Kibana
**Network IDS:** Suricata
**Endpoint visibility:** Sysmon (with SwiftOnSecurity config) + Wazuh agent
**Vulnerable targets:** DVWA (web), hardened-down Ubuntu (SSH)
**Honeypots:** Cowrie (SSH deception alongside the real SSH target)
**Adversary emulation:** Atomic Red Team, MITRE Caldera, Hydra, Impacket, BloodHound
**Case management (bonus):** TheHive 5
**Threat intel (bonus):** MISP
**SOAR (bonus):** Shuffle

## 🎯 Detection coverage (MITRE ATT&CK)

| Tactic             | Technique                          | Detection source              | Status |
|--------------------|------------------------------------|-------------------------------|--------|
| Reconnaissance     | T1595 — Active Scanning            | Suricata + pfSense logs       | ⏳ |
| Initial Access     | T1190 — Exploit Public App (DVWA)  | Suricata + Wazuh FIM          | ⏳ |
| Initial Access     | T1110 — SSH Brute Force            | Wazuh auth.log + Cowrie       | ⏳ |
| Execution          | T1059.004 — Unix Shell (web shell) | Wazuh process monitoring      | ⏳ |
| Credential Access  | T1110 — RDP / SMB Brute Force      | Windows Event 4625            | ⏳ |
| Credential Access  | T1558.003 — Kerberoasting          | Windows Event 4769            | ⏳ |
| Credential Access  | T1552.004 — Private Keys (SSH)     | Wazuh FIM on ~/.ssh           | ⏳ |
| Discovery          | T1087 — Account Discovery          | Sysmon process creation       | ⏳ |
| Lateral Movement   | T1021 — Remote Services (PsExec)   | Sysmon + Wazuh                | ⏳ |
| Persistence        | T1136 — Create Account             | Event 4720                    | ⏳ |
| Defense Evasion    | T1070.001 — Clear Windows logs     | Event 1102                    | ⏳ |
| Exfiltration       | T1041 — Exfil over C2              | Suricata                      | ⏳ |
| C2                 | T1071.001 — Web protocols          | Suricata + Wazuh              | ⏳ |
| Deception          | Honeypot interaction               | Cowrie → Wazuh                | ⏳ |

## 🎭 Attack scenarios (Purple Team)

The lab implements **8 end-to-end attack scenarios**, each executed and then detected/investigated as a SOC analyst:

1. **External reconnaissance** — Nmap port and service scan against DMZ
2. **SSH brute force** against the vulnerable Ubuntu, with parallel Cowrie honeypot comparison
3. **DVWA SQL injection** leading to data exfiltration
4. **DVWA RCE → web shell** persistence on the web server
5. **DMZ → Corp pivot** via stolen SSH key
6. **Active Directory reconnaissance** with BloodHound from a compromised endpoint
7. **Kerberoasting** against a service account
8. **Full kill chain** combining 6 of the above into one realistic intrusion

Each scenario has its own report in `docs/04-attack-scenarios/` with: attack steps, detection rules triggered, MITRE mapping, screenshots, and a responder playbook.

## 📂 Repository structure

```
soc-lab/
├── README.md                          # this file
├── docs/
│   ├── 01-architecture.md             # detailed architecture and IP plan
│   ├── 02-installation/               # step-by-step setup per component
│   ├── 03-detection-rules.md          # all custom detection rules
│   ├── 04-attack-scenarios/           # 8 scenarios, one report each
│   ├── 05-dashboards.md               # Kibana SOC dashboard exports
│   ├── 06-playbooks/                  # IR playbooks for each detection
│   └── journal.md                     # daily logbook
├── configs/
│   ├── pfsense/                       # firewall rules, VLAN config
│   ├── wazuh/                         # custom rules, decoders, agent config
│   ├── sysmon/                        # Sysmon configuration
│   └── suricata/                      # custom rules
├── scripts/
│   ├── deploy/                        # automation scripts (PowerShell / Bash)
│   └── attack-simulation/             # attack scripts (Atomic / custom)
├── diagrams/                          # architecture diagrams (drawio / png)
└── reports/
    ├── tech-study-video-script.md     # UE deliverable: tech video script
    └── final-report.md                # 6-page final report
```

## 📅 Roadmap

| Week | Dates       | Phase                | Key milestone                              |
|------|-------------|----------------------|--------------------------------------------|
| W1   | 12–17 May   | Build infrastructure | Lab deployed, network segmented, AD live   |
| W2   | 18–24 May   | Detection layer      | Wazuh ingesting all logs, 10+ rules active |
| W3   | 25–31 May   | Attack & investigate | 8 scenarios executed and documented        |
| W4   | 1–8 June    | Deliverables         | Video + report + presentation ready        |
|      | 9–11 June   | 🎓 Defense           | TER soutenance                             |

## 📊 Key metrics

- Number of detection rules written: `0 / 15`
- MITRE ATT&CK techniques covered: `0 / 14`
- Attack scenarios fully documented: `0 / 8`
- Mean Time to Detect (MTTD) in simulated scenarios: `TBD`
- Honeypot interactions captured: `TBD`

## 📚 Documentation philosophy

Every component is documented as if a **new SOC analyst joins the team tomorrow** and needs to understand:

1. **Why** it is there (threat model)
2. **How** it was deployed (reproducible steps)
3. **What** it detects (mapped to MITRE)
4. **How to respond** (runbook / playbook)

## 🎓 Learning resources

- MITRE ATT&CK — https://attack.mitre.org/
- Wazuh documentation — https://documentation.wazuh.com/
- Sigma rules repository — https://github.com/SigmaHQ/sigma
- Atomic Red Team — https://atomicredteam.io/
- DetectionLab inspiration — https://github.com/clong/DetectionLab

## ⚠️ Disclaimer

All offensive content (DVWA, vulnerable SSH, attack scripts) is hosted in a **fully isolated virtual environment** with no external exposure. The lab is for educational purposes within the framework of an academic project.

## 👤 Contact

[![Email](https://img.shields.io/badge/Email-0078D4?style=for-the-badge&logo=gmail&logoColor=white)](mailto:anasschammami04@gmail.com) [![LinkedIn](https://img.shields.io/badge/LinkedIn-0077B5?style=for-the-badge&logo=linkedin&logoColor=white)](https://www.linkedin.com/in/anass-chammami-78ab25304/)