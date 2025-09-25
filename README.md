# Incident Report – Fake Web Traffic Analysis

---

## 1. Executive Summary

This investigation analyzed a PCAP capture to identify signs of compromise within the LAN segment **10.1.17.0/24**. Using Wireshark, the infected client was isolated, its host identity and user account were confirmed, and malicious traffic was traced to a fake Google Authenticator phishing domain along with several external command-and-control (C2) servers. Evidence suggests credential theft followed by persistent external communications with attacker-controlled infrastructure.

---

## 2. Environment Overview

**LAN Segment Details (from PCAP):**

* **LAN range:** 10.1.17.0/24 (10.1.17.0 – 10.1.17.255)
* **Gateway:** 10.1.17.1 (exit point to the internet)
* **Broadcast:** 10.1.17.255 (host discovery / reconnaissance traffic)
* **Domain:** bluemoontuesday[.]com
* **Active Directory DC:** 10.1.17.2 (WIN-GSH54QLW48D)
* **AD Environment Name:** BLUEMOONTUESDAY

These details establish which hosts are internal vs. external and highlight the AD domain controller that authenticates users.

---

## 3. Findings

### 3.1 Infected Windows Client

* **IP Address:** 10.1.17.215
* **MAC Address:** 00:d0:b7:26:4a:74
* **Host Name:** DESKTOP-L8CGS5J (via NBNS registration)
* **Windows User Account:** shutchenson (from Kerberos authentication exchange)

**Evidence:**

* [IPv4 conversations showing 10.1.17.215 sending the most packets](https://github.com/user-attachments/assets/7ac0515b-835d-40c5-98b7-d455243ba629)
* [Ethernet endpoint statistics confirming MAC 00:d0:b7:26:4a:74](https://github.com/user-attachments/assets/90442115-7d6a-4805-8bed-a2abad9463d9)
* [NBNS traffic showing host name DESKTOP-L8CGS5J and AD environment BLUEMOONTUESDAY](https://github.com/user-attachments/assets/63a7aea8-f417-476d-a1fe-cdbffde39920)
* [Kerberos packet revealing username shutchenson](https://github.com/user-attachments/assets/587d4251-e3e8-4d5f-88c5-5c00cafe3e14)

---

### 3.2 Malicious Domain (Phishing Page)

* **Domain Queried:** authenticatoor.org
* **Description:** Fake Google Authenticator phishing site (typosquatting “authenticator”)
* **Resolution:** Resolved to **82.221.136.26** during DNS query
* **Purpose:** Likely used for initial credential harvesting before redirecting to true C2 infrastructure

---

### 3.3 Command-and-Control (C2) Servers

Analysis of external connections from 10.1.17.215 revealed sustained high-volume traffic with the following IPs:

| IP Address    | Packets | Bytes  | Notes                                                             |
| ------------- | ------- | ------ | ----------------------------------------------------------------- |
| 45.125.66.32  | 10,940  | 10 MB  | Long-lived C2 connection                                          |
| 5.252.153.241 | 9,076   | 7 MB   | Persistent data exchange                                          |
| 45.125.66.252 | 1,369   | 107 KB | Secondary C2 channel                                              |
| 82.221.136.26 | 2,470   | 2 MB   | Tied to phishing domain authenticatoor.org; likely staging server |

**Observation:**
While `82.221.136.26` is directly linked to the phishing domain, the three IPs (`45.125.66.32`, `5.252.153.241`, `45.125.66.252`) exhibit the most sustained encrypted sessions, characteristic of malware beaconing and exfiltration.

---

## 4. Attack Flow (Reconstruction)

1. User **shutchenson** on **DESKTOP-L8CGS5J (10.1.17.215)** browsed to the fake domain `authenticatoor.org`.
2. DNS resolved the domain to **82.221.136.26**.
3. The client established a TLS connection to 82.221.136.26, presenting **SNI = authenticatoor.org**.
4. After the initial interaction, malware established longer-lived sessions with **C2 IPs 45.125.66.32, 5.252.153.241, and 45.125.66.252**.
5. Persistent encrypted traffic suggests ongoing attacker control and potential data exfiltration.

---

## 5. Indicators of Compromise (IOCs)

**Host-based IOCs:**

* Hostname: DESKTOP-L8CGS5J
* User: shutchenson
* MAC: 00:d0:b7:26:4a:74
* IP: 10.1.17.215

**Network IOCs:**

* Phishing Domain: authenticatoor.org
* Phishing IP: 82.221.136.26
* C2 Servers:

  * 45.125.66.32
  * 5.252.153.241
  * 45.125.66.252

---

## 6. Recommendations

### Immediate Containment

* Quarantine infected host (`10.1.17.215`) from the network.
* Block outbound traffic to malicious IPs/domains at firewall and proxy.

### Credential Security

* Reset credentials for user **shutchenson**.
* Audit Active Directory logs for suspicious login activity.

### Network Defense

* Deploy IDS/IPS signatures for identified IOCs.
* Monitor for beaconing patterns on other hosts.

### User Awareness

* Conduct phishing-awareness training, focusing on lookalike domains such as `authenticatoor.org`.

### Forensic Follow-Up

* Perform disk and memory forensic analysis of DESKTOP-L8CGS5J.
* Identify malware family and persistence mechanisms.
* Collect memory dumps to extract possible decrypted C2 instructions.

---

## 7. Conclusion

The PCAP analysis confirms a compromise of host **10.1.17.215 (DESKTOP-L8CGS5J)** belonging to user **shutchenson**. The infection originated via a phishing domain (`authenticatoor.org`) and transitioned into persistent communication with multiple external C2 servers. Prompt host isolation, credential resets, and network-level blocking are required to mitigate further compromise.

---
