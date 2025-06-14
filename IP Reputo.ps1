param (
    [Parameter(Mandatory = $true)]
    [string]$InputFile
)

# Replace with your actual VirusTotal API key
$apiKey = ""

if (-not (Test-Path $InputFile)) {
    Write-Error "Input file '$InputFile' does not exist."
    exit 1
}

# Ask user if they want to save output to CSV
$saveToCsv = $null
do {
    $saveToCsv = Read-Host "Save output to CSV file? (Y/N)"
} while ($saveToCsv -notin @('Y','y','N','n'))

$saveToCsv = $saveToCsv.ToUpper() -eq 'Y'

$outputResults = @()

# Import CSV and extract unique, valid IPs from all columns
$csvContent = Import-Csv -Path $InputFile
$ipRegex = '\b(?:\d{1,3}\.){3}\d{1,3}\b'

$ips = $csvContent | ForEach-Object {
    $_.PSObject.Properties | ForEach-Object {
        if ($_.Value -match $ipRegex) {
            [regex]::Matches($_.Value, $ipRegex) | ForEach-Object { $_.Value }
        }
    }
} | Sort-Object -Unique

if ($ips.Count -eq 0) {
    Write-Warning "No valid IPs found in the CSV."
    exit
}

$headers = @{ "x-apikey" = $apiKey }

foreach ($ip in $ips) {
    Write-Host "`n=== Checking IP: $ip ===" -ForegroundColor Cyan

    try {
        # Get IP info
        $url = "https://www.virustotal.com/api/v3/ip_addresses/$ip"
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method GET
        $attributes = $response.data.attributes
        $stats = $attributes.last_analysis_stats

        $malicious = $stats.malicious
        $suspicious = $stats.suspicious
        $isRisk = ($malicious -gt 0 -or $suspicious -gt 0)

        if ($isRisk) {
            Write-Host "⚠️  RISKY: $ip -> Malicious: $malicious, Suspicious: $suspicious" -ForegroundColor Red
        } else {
            Write-Host "✅ SAFE : $ip -> Malicious: $malicious, Suspicious: $suspicious" -ForegroundColor Green
        }

        $country = $attributes.country
        if ($country) {
            Write-Host "🌍 Country : $country" -ForegroundColor Yellow
        }

        $as_owner = $attributes.as_owner
        if ($as_owner) {
            Write-Host "🏢 Owner   : $as_owner" -ForegroundColor Yellow
        }

        # Fetch Passive DNS (related domains)
        $domains = @()
        $nextUrl = "https://www.virustotal.com/api/v3/ip_addresses/$ip/resolutions"
        for ($page = 0; $page -lt 2 -and $nextUrl; $page++) {
            $resResp = Invoke-RestMethod -Uri $nextUrl -Headers $headers -Method GET
            $domains += $resResp.data | ForEach-Object { $_.attributes.host_name }
            $nextUrl = if ($resResp.links.PSObject.Properties.Name -contains 'next') { $resResp.links.next } else { $null }
        }
        $domains = $domains | Select-Object -Unique

        Write-Host "🔗 Passive DNS (Related Domains):" -ForegroundColor Cyan
        if ($domains.Count -gt 0) {
            foreach ($domain in $domains) {
                Write-Host "   • $domain"
            }
        } else {
            Write-Host "   None" -ForegroundColor DarkGray
        }

        # Fetch communicating files (up to 5)
        $filesUrl = "https://www.virustotal.com/api/v3/ip_addresses/$ip/communicating_files"
        $filesResponse = Invoke-RestMethod -Uri $filesUrl -Headers $headers -Method GET

        $communicatingFiles = @()
        foreach ($file in $filesResponse.data | Select-Object -First 5) {
            $name = $file.attributes.names[0]
            if (-not $name) { $name = $file.id.Substring(0, 12) + "..." }
            $communicatingFiles += $name
        }

        Write-Host "🗂 Communicating Files:" -ForegroundColor Cyan
        if ($communicatingFiles.Count -gt 0) {
            foreach ($fileName in $communicatingFiles) {
                Write-Host "   • $fileName"
            }
        } else {
            Write-Host "   None" -ForegroundColor DarkGray
        }

        # Prepare data for CSV output
        if ($saveToCsv) {
            $outputResults += [PSCustomObject]@{
                IP                 = $ip
                Malicious          = $malicious
                Suspicious         = $suspicious
                RiskDetected       = $isRisk
                Country            = $country
                Owner              = $as_owner
                PassiveDNSDomains  = ($domains -join "; ")
                CommunicatingFiles = ($communicatingFiles -join "; ")
            }
        }

    } catch {
        $errorMessage = $_.Exception.Message
        Write-Host "⚠️  ERROR: $ip -> $errorMessage" -ForegroundColor Yellow

        if ($saveToCsv) {
            $outputResults += [PSCustomObject]@{
                IP                 = $ip
                Malicious          = "Error"
                Suspicious         = "Error"
                RiskDetected       = "Error"
                Country            = ""
                Owner              = ""
                PassiveDNSDomains  = ""
                CommunicatingFiles = ""
            }
        }
    }

    Start-Sleep -Seconds 15  # Respect VirusTotal API rate limit
}

if ($saveToCsv) {
    $csvFileName = "VT_Results_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $outputResults | Export-Csv -Path $csvFileName -NoTypeInformation
    Write-Host "`nResults saved to $csvFileName" -ForegroundColor Green
} else {
    Write-Host "`nOutput not saved to CSV as per user choice." -ForegroundColor Yellow
}
