Incident Report – Fake Web Traffic Analysis
1. Executive Summary

This investigation analyzed a PCAP capture to identify signs of compromise within the LAN segment 10.1.17.0/24. Using Wireshark, we isolated the infected client, confirmed its host identity and user account, and traced malicious traffic to a fake Google Authenticator phishing domain and several external command-and-control (C2) servers. Evidence suggests credential theft followed by persistent external communications with attacker-controlled infrastructure.

2. Environment Overview

LAN Segment Details (from PCAP):

LAN range: 10.1.17.0/24 (10.1.17.0 – 10.1.17.255)

Gateway: 10.1.17.1 (exit point to internet)

Broadcast: 10.1.17.255 (host discovery / reconnaissance traffic)

Domain: bluemoontuesday[.]com

Active Directory DC: 10.1.17.2 (WIN-GSH54QLW48D)

AD Environment Name: BLUEMOONTUESDAY

These details establish which hosts are internal vs. external and highlight the AD domain controller that authenticates users.

3. Findings
3.1 Infected Windows Client

IP Address: 10.1.17.215

MAC Address: 00:d0:b7:26:4a:74

Host Name: DESKTOP-L8CGS5J (via NBNS registration)

Domain Membership: BLUEMOONTUESDAY

User Account: shutchenson (from Kerberos authentication exchange)

3.2 Malicious Domain (Phishing Page)

Domain Queried: authenticatoor.org

Description: Fake Google Authenticator phishing site (typosquatting “authenticator”)

Resolution: Resolved to 82.221.136.26 during DNS query

Purpose: Likely initial credential harvesting before redirection to true C2 infrastructure

3.3 Command-and-Control (C2) Servers

Analysis of external connections from 10.1.17.215 revealed sustained high-volume traffic with the following IPs:

IP Address	Packets	Bytes	Notes
45.125.66.32	10,940	10 MB	Long-lived C2 connection
5.252.153.241	9,076	7 MB	Persistent data exchange
45.125.66.252	1,369	107 KB	Secondary C2 channel
82.221.136.26	2,470	2 MB	Tied to phishing domain (authenticatoor.org), likely staging server

Observation:
While 82.221.136.26 is linked to the phishing domain, the true sustained C2 channels are the three IPs (45.125.66.32, 5.252.153.241, 45.125.66.252). These exhibit prolonged encrypted sessions, characteristic of malware beaconing and exfiltration.

4. Attack Flow (Reconstruction)

User shutchenson on DESKTOP-L8CGS5J (10.1.17.215) browses to fake domain authenticatoor.org.

DNS resolves this domain to 82.221.136.26.

Client establishes TLS connection to 82.221.136.26, presenting SNI = authenticatoor.org.

After initial interaction, malware establishes longer-lived sessions with C2 IPs (45.125.66.32, 5.252.153.241, 45.125.66.252).

Persistent encrypted traffic suggests ongoing attacker control and possible data exfiltration.

5. Indicators of Compromise (IOCs)

Host-based IOCs

Hostname: DESKTOP-L8CGS5J

User: shutchenson

MAC: 00:d0:b7:26:4a:74

IP: 10.1.17.215

Network IOCs

Phishing Domain: authenticatoor.org

Phishing IP: 82.221.136.26

C2 Servers:

45.125.66.32

5.252.153.241

45.125.66.252

6. Recommendations

Immediate Containment

Quarantine infected host (10.1.17.215) from the network.

Block outbound traffic to malicious IPs/domains at firewall/proxy.

Credential Security

Reset credentials for user shutchenson.

Audit AD logs for suspicious login activity.

Network Defense

Deploy IDS/IPS signatures for identified IOCs.

Monitor for beaconing patterns on similar hosts.

User Awareness

Train users on phishing detection, especially lookalike domains (authenticatoor.org).

Forensic Follow-up

Perform disk/host forensic analysis of DESKTOP-L8CGS5J to identify malware family and persistence mechanisms.

Collect memory dump to extract possible decrypted C2 instructions.

7. Conclusion

The PCAP analysis confirms a compromise of host 10.1.17.215 (DESKTOP-L8CGS5J) belonging to user shutchenson. The infection originated via a phishing domain (authenticatoor.org) and transitioned into persistent communication with multiple external C2 servers. Prompt containment and credential hygiene are critical to mitigate further compromise.

<img width="1470" height="956" alt="image" src="https://github.com/user-attachments/assets/57c8e587-710c-40e2-8938-6621c9a0a556" />
This is me trying to filter infected client
<img width="1470" height="956" alt="image" src="https://github.com/user-attachments/assets/753ef475-2101-470b-a33a-f0051c7f7e20" />
statistics -> endpoint -> address

looks like 10.1.17.215 is the infected client 
check ethernet to see the MAC address
looks like it is 00:d0:b7:26:4a:74
<img width="1470" height="956" alt="image" src="https://github.com/user-attachments/assets/f55668cc-1f06-4025-b9c6-1ef42a68e1b1" />

<img width="1470" height="956" alt="image" src="https://github.com/user-attachments/assets/05d93d0a-749f-4d32-9c7c-39e2b9a39394" />
<img width="1470" height="956" alt="image" src="https://github.com/user-attachments/assets/2531b393-e720-479c-8d2e-d8d5308c5d4e" />
NetBios Name Service (NBNS)
Registration NB DESKTOP-L8CGS5J<00>

This means infected client host 10.1.17.215 registered the NetBIOS name is DESKTOP-L8CGS5J.

Registration NB BLUEMOONTUESDAY<00>

This is the domain/workgroup name being announced.

Registration response, Name is owned by another node NB 10.1.17.2

The domain controller (10.1.17.2) replies saying “that name belongs to me”.
The infected Windows client was DESKTOP-L8CGS5J (10.1.17.215 / 00:d0:b7:26:4a:74) in the BLUEMOONTUESDAY domain.
<img width="1470" height="956" alt="image" src="https://github.com/user-attachments/assets/95126db7-73ac-449d-a25b-229bcde3f13c" />
kRB5-NT-PRINCIPAL (1)
name : shutchenson
<img width="1470" height="768" alt="image" src="https://github.com/user-attachments/assets/10fb27d5-9692-42d7-9e60-9a288bf93ee7" />

<img width="1470" height="956" alt="image" src="https://github.com/user-attachments/assets/e5517863-f95a-4637-b1a9-4e3b3582eef8" />





