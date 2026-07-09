Write-Host "====================================="
Write-Host "        Security Audit Tool"
Write-Host "====================================="
Write-Host ""

$report = @()
$findings = @()
$lowRiskCount = 0
$reviewCount = 0
$timestamp = Get-Date

function Get-PortProcess($portNumber) {

    $processInfo = lsof -i ":$portNumber" | Select-String "LISTEN" | Select-Object -First 1

    if ($processInfo) {

        $line = $processInfo.ToString()

        $parts = $line -split "\s+"

        $processName = $parts[0]
        $processID = $parts[1]

        return "$processName (PID: $processID)"

    }

    else {

        return "No process found"

    }
}


Write-Host ""
Write-Host "Collecting System Information..."
Write-Host ""

$computerName = hostname
$currentUser = whoami
$operatingSystem = $PSVersionTable.OS

Write-Host "Computer Name: $computerName"
Write-Host "Current User: $currentUser"
Write-Host "Operating System: $operatingSystem"

$report += "<h2>System Information</h2>"
$report += "<p>Computer Name: $computerName</p>"
$report += "<p>Current User: $currentUser</p>"
$report += "<p>Operating System: $operatingSystem</p>"


Write-Host ""
Write-Host "Collecting Network Information..."
Write-Host ""

$networkConnections = netstat -an

$totalConnections = $networkConnections.count

Write-Host "Total Network Entries:  $totalConnections"


$listeningPorts = netstat -an | Select-String "tcp" | Select-String "LISTEN"

Write-Host ""
Write-Host "Listening Port Analysis:"
Write-Host ""

foreach ($port in $listeningPorts) {

    $parts = $port -split "\s+"

    $localAddress = $parts[3]

    $portNumber = $localAddress.split(".")[-1]

    $process = Get-PortProcess $portNumber

    if ($localAddress -match "127.0.0.1") {
	
	$lowRiskCount++
        Write-Host "[LOW RISK] Local Only Service:"
        Write-Host "Port: $portNumber"
        Write-Host ""

	$report += "<p style='color:green'>LOW RISK - Local Service: $localAddress</p>"
	$findings += "<tr><td>Low Risk</td><td>$localAddress</td><td>Local Only Service</td></tr>"
    }

    elseif ($localAddress -match "0.0.0.0|\*") {

	$reviewCount++
        Write-Host "[REVIEW] Available On All Interfaces:"
        Write-Host $localAddress
        Write-Host ""

	$report += "<p style='color:red'>REVIEW - Exposed Service: $localAddress</p>"
	$findings += "<tr><td>Review</td><td>$localAddress</td><td>$process</td></tr>"

    }

    else {
	
	$reviewCount++
        Write-Host "[REVIEW] Network Interface Service:"
        Write-Host $localAddress
        Write-Host ""

	$report += "<p style='color:orange'>REVIEW - Network Interface Service: $localAddress</p>"
	$findings += "<tr><td>Review</td><td>$localAddress</td><td>Network Interface Service</td></tr>"
	
    }
}

$html = @"
<html>
<head>
<title>Security Audit Report</title>
<style>
    body {
        font-family: 'Segoe UI', -apple-system, BlinkMacSystemFont, Roboto, sans-serif;
        margin: 40px auto;
        max-width: 1200px;
        background-color: #f8f9fa;
        color: #333;
        line-height: 1.6;
    }
    h1 {
        text-align: center;
        color: #1a202c;
        font-weight: 700;
        margin-bottom: 5px;
    }
    .timestamp {
        text-align: center;
        color: #718096;
        font-size: 14px;
        margin-bottom: 40px;
    }
    h2 {
        color: #2d3748;
        border-bottom: 2px solid #e2e8f0;
        padding-bottom: 8px;
        margin-top: 30px;
        font-weight: 600;
    }
    .card {
        background: white;
        padding: 24px;
        border-radius: 8px;
        box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05), 0 2px 4px -1px rgba(0,0,0,0.03);
        margin-bottom: 25px;
    }
    .summary-box {
        display: inline-block;
        padding: 12px 24px;
        border-radius: 6px;
        margin-right: 15px;
        font-weight: bold;
        font-size: 15px;
    }
    .low-risk-box { background-color: #e6fffa; color: #008767; border: 1px solid #b2f5ea; }
    .review-box { background-color: #fff5f5; color: #e53e3e; border: 1px solid #fed7d7; }
    
    table {
        border-collapse: collapse;
        width: 100%;
        margin-top: 15px;
        background: white;
        border-radius: 8px;
        overflow: hidden;
    }
    th {
        background-color: #1a202c;
        color: white;
        text-align: left;
        padding: 12px 16px;
        font-weight: 600;
        font-size: 14px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    td {
        padding: 12px 16px;
        border-bottom: 1px solid #edf2f7;
        font-size: 14px;
    }
    tr:nth-child(even) td {
        background-color: #f7fafc;
    }
    tr:hover td {
        background-color: #edf2f7;
    }
    .sys-info p {
        margin: 8px 0;
        font-size: 15px;
    }
    .sys-info strong {
        color: #4a5568;
    }
</style>
</head>
<body>

<h1>Security Audit Report</h1>
<p class="timestamp">Report Generated: $timestamp</p>

<h2>Risk Summary</h2>
<div class="card">
    <div class="summary-box low-risk-box">Low Risk Findings: $lowRiskCount</div>
    <div class="summary-box review-box">Review Required: $reviewCount</div>
</div>

<h2>Security Findings</h2>
<div class="card" style="padding: 0;">
    <table>
        <thead>
            <tr>
                <th>Risk Level</th>
                <th>Address</th>
                <th>Description</th>
            </tr>
        </thead>
        <tbody>
            $($findings -join "`n")
        </tbody>
    </table>
</div>

<h2>System Details Log</h2>
<div class="card sys-info">
    $($report -join "`n")
</div>

</body>
</html>
"@


$html | Out-File SecurityAuditReport.html
