# FakeWebTrafficAnalysis
This project demonstrates how to use WireShark to capture network traffic and how to make use of the information to give a good input

WHAT DOES LAN SEGMENT DETAILS FROM THE PCAP MEANS?
LAN segment range:  10.1.17[.]0/24   (10.1.17[.]0 through 10.1.17[.]255)
It shows the scope of local traffic, which means we can differentiate the internal and external communication by filtering traffic by subnet in Wireshark (ip.addr == 10.1.17.0/24) to analyze only the internal communications
Domain:  bluemoontuesday[.]com
Active Directory (AD) domain controller:  10.1.17[.]2 - WIN-GSH54QLW48D
AD environment name:  BLUEMOONTUESDAY
AD/DC traffic (like Kerberos, LDAP, SMB) usually means authentication or file-sharing activity. thus, if there is suspicious logins, brute-force attempts or unusual SMB traffic within this domain controller, it needs to be highlighted
LAN segment gateway:  10.1.17[.]1
Gateway means the exit point to other networks or internet. so, it is useful to track what traffic is leaving the LAN
LAN segment broadcast address:  10.1.17[.]255
It looks for broadcast protocols like ARP, NetBIOS, DHCP, which can help in network reconnaissance or host discovery. If there is ARP Spoofing or lots of broadcast traffic, it can be documented as intrusion detection demo
What is the IP address of the infected Windows client?
What is the mac address of the infected Windows client?
What is the host name of the infected Windows client?
What is the user account name from the infected Windows client?
What is the likely domain name for the fake Google Authenticator page?
What are the IP addresses used for C2 servers for this infection?

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



