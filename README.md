
# VirusTotal IP Checker PowerShell Script

This PowerShell script reads a CSV file containing IP addresses, queries the [VirusTotal API](https://www.virustotal.com/), and provides a risk summary of each IP, including malicious/suspicious reports, country, owner, passive DNS domains, and communicating files.

## 🚀 Features

- Extracts valid unique IPs from all columns of the provided CSV.
- Checks IP info using VirusTotal API.
- Displays:
  - Malicious and suspicious analysis stats
  - Country and owner information
  - Related passive DNS domains
  - Communicating files (up to 5)
- Option to save results to a CSV file.
- Handles API rate limits gracefully.

## 📌 Requirements

- PowerShell 5.1 or higher
- A valid [VirusTotal API key](https://developers.virustotal.com/reference/getting-started)

## 📝 Usage

1. **Set your VirusTotal API key**
   Edit the script and set your API key:
   ```powershell
   $apiKey = "YOUR_API_KEY_HERE"
   ```

2. **Prepare your input CSV**
   The CSV should contain IP addresses in any column.

3. **Run the script**
   ```powershell
   .\YourScriptName.ps1 -InputFile "path\to\input.csv"
   ```

4. **Choose to save results**
   The script will prompt:
   ```
   Save output to CSV file? (Y/N)
   ```
   - `Y`: Results will be saved to a timestamped CSV file.
   - `N`: Results will only display in the console.

## 📂 Example

```powershell
.\Check-VT-IPs.ps1 -InputFile "C:\data\ips.csv"
```

Example prompt:
```
Save output to CSV file? (Y/N)
```

## ⏱ Notes

- The script respects VirusTotal's rate limit with a 15-second delay between IP queries.
- It saves output CSV as:
  ```
  VT_Results_yyyyMMdd_HHmmss.csv
  ```

## ⚠️ Disclaimer

- This script is for educational and internal use.
- Make sure your use complies with VirusTotal API terms.

## 🖥 Sample Output (Console)

```
=== Checking IP: 8.8.8.8 ===
✅ SAFE : 8.8.8.8 -> Malicious: 0, Suspicious: 0
🌍 Country : US
🏢 Owner   : Google LLC
🔗 Passive DNS (Related Domains):
   • dns.google
🗂 Communicating Files:
   None
```
