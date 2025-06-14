# IP-Reputo
 PowerShell script to scan multiple IPs using the VirusTotal API — shows risk scores, country, owner, passive DNS domains, and communicating files. Built for SOC analysts and incident responders. Scan and enrich IPs from logs using VirusTotal — in PowerShell, no Kali needed.


# 🔍 VirusTotal IP Intelligence Scanner (PowerShell)

A lightweight PowerShell script for batch scanning multiple IP addresses using the VirusTotal API.  
Perfect for **SOC analysts**, **threat hunters**, and **incident responders** who want to quickly gather intelligence on suspicious IPs — even in **restricted environments without access to tools like Kali Linux**.

---

## 🚀 Features

- ✅ **Batch scan IPs from a CSV file**
- 📂 **Automatically extracts all IP addresses**, regardless of which column they appear in
- 🧬 **Pulls VirusTotal intelligence** including:
  - Malicious & Suspicious scores
  - Country and ASN owner
  - Passive DNS (related domains)
  - Communicating files (malware or artifacts connected to the IP)
- 🎨 **Color-coded PowerShell output**
  - 🔴 Risky IPs (Malicious/Suspicious)
  - 🟢 Safe IPs
  - 🟡 Owner/Country Info
  - 🔗 Passive DNS & Files in Cyan
- 💾 **Optional CSV export** of the full results
- ⏳ **Rate-limit friendly** (sleep delay added for free VirusTotal API usage)

---
🧪 Sample Command:

.\VT_IP_Scanner.ps1 -InputFile "logs.csv"


Sample output:

=== Checking IP: 8.8.8.8 ===
✅ SAFE : 8.8.8.8 -> Malicious: 0, Suspicious: 0
🌍 Country : US
🏢 Owner   : Google LLC
🔗 Passive DNS (Related Domains):
   • dns.google
🗂 Communicating Files:
   • dns_resolver.dll
