param(
    [Parameter(Mandatory = $true)]
    [string] $BinaryPath
)

$ErrorActionPreference = "Stop"
$runnerTemp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } elseif ($env:TEMP) { $env:TEMP } else { [IO.Path]::GetTempPath() }
$curlCommand = Get-Command curl.exe -ErrorAction SilentlyContinue
if ($null -eq $curlCommand) {
    $curlCommand = Get-Command curl -ErrorAction Stop
}
$curlPath = $curlCommand.Source
$workDir = Join-Path $runnerTemp "nettrap-listener-smoke"
$configPath = Join-Path $workDir "config.toml"
$smtpDir = Join-Path $workDir "smtp"
$messagePath = Join-Path $workDir "message.eml"
$eventsPath = Join-Path $workDir "events.jsonl"
$httpV6BodyPath = Join-Path $workDir "http-v6.body"
$stdoutPath = Join-Path $workDir "stdout.log"
$stderrPath = Join-Path $workDir "stderr.log"
$process = $null

New-Item -ItemType Directory -Force -Path $workDir | Out-Null
New-Item -ItemType Directory -Force -Path $smtpDir | Out-Null
@"
attribution_enabled = false
default_decision = "emulate"
pcap_enabled = false
output_format = "jsonl"
smtp_dir = "$($smtpDir.Replace('\', '/'))"
output_path = "$($eventsPath.Replace('\', '/'))"

[[listeners]]
name = "dns-smoke"
protocol = "udp"
port = 53539
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "http-smoke"
protocol = "tcp"
port = 18088
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "dns-smoke-v6"
protocol = "udp"
port = 53540
bind_address = "::1"
enabled = true
emulate_response = true

[[listeners]]
name = "dns-tcp-smoke"
protocol = "tcp"
port = 53541
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "http-smoke-v6"
protocol = "tcp"
port = 18089
bind_address = "::1"
enabled = true
emulate_response = true

[[listeners]]
name = "tls-smoke"
protocol = "tcp"
port = 18444
bind_address = "127.0.0.1"
enabled = true
emulate_response = true
use_ssl = true

[[listeners]]
name = "ssh-smoke"
protocol = "tcp"
port = 12222
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "telnet-smoke"
protocol = "tcp"
port = 12323
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "smtp-smoke"
protocol = "tcp"
port = 12526
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "ftp-smoke"
protocol = "tcp"
port = 12122
bind_address = "127.0.0.1"
enabled = true
emulate_response = true
pasv_ports = "30110-30115"

[[listeners]]
name = "pop3-smoke"
protocol = "tcp"
port = 11110
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "imap-smoke"
protocol = "tcp"
port = 1143
bind_address = "127.0.0.1"
enabled = true
emulate_response = true
"@ | Set-Content -Path $configPath -Encoding utf8

function Stop-NetTrap {
    if ($null -ne $script:process -and -not $script:process.HasExited) {
        Stop-Process -Id $script:process.Id -Force -ErrorAction SilentlyContinue
        $script:process.WaitForExit(5000)
    }
}

function Read-Exact($Stream, [int] $Count) {
    $buffer = [byte[]]::new($Count)
    $offset = 0
    while ($offset -lt $Count) {
        $read = $Stream.Read($buffer, $offset, $Count - $offset)
        if ($read -le 0) {
            throw "TCP stream closed before $Count bytes were received"
        }
        $offset += $read
    }
    return $buffer
}

try {
    $process = Start-Process -FilePath $BinaryPath -ArgumentList @(
        "run", "-c", $configPath
    ) -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru

    $http = $null
    for ($attempt = 0; $attempt -lt 40 -and $null -eq $http; $attempt++) {
        if ($process.HasExited) {
            throw "NetTrap exited before listener startup (code $($process.ExitCode))"
        }
        try {
            $http = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:18088/" `
                -Headers @{ Host = "example.test" } -TimeoutSec 1
        } catch {
            Start-Sleep -Milliseconds 250
        }
    }
    if ($null -eq $http -or $http.StatusCode -ne 200) {
        throw "HTTP listener smoke failed"
    }

    $httpV6Status = (& $curlPath --noproxy "*" --silent --show-error --max-time 2 `
        --output $httpV6BodyPath --write-out "%{http_code}" --header "Host: example.test" `
        "http://[::1]:18089/")
    if ($LASTEXITCODE -ne 0 -or $httpV6Status -ne "200") {
        throw "IPv6 HTTP listener smoke failed (status $httpV6Status)"
    }

    $query = [System.Collections.Generic.List[byte]]::new()
    $query.Add(0x12)
    $query.Add(0x34)
    $query.Add(0x01)
    $query.Add(0x00)
    $query.Add(0x00)
    $query.Add(0x01)
    $query.Add(0x00)
    $query.Add(0x00)
    $query.Add(0x00)
    $query.Add(0x00)
    $query.Add(0x00)
    $query.Add(0x00)
    foreach ($label in @("example", "com")) {
        $labelBytes = [System.Text.Encoding]::ASCII.GetBytes($label)
        $query.Add([byte]$labelBytes.Length)
        $query.AddRange($labelBytes)
    }
    $query.Add(0x00)
    $query.Add(0x00)
    $query.Add(0x01)
    $query.Add(0x00)
    $query.Add(0x01)

    $udp = [System.Net.Sockets.UdpClient]::new()
    try {
        $udp.Client.ReceiveTimeout = 5000
        $endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 53539)
        [void]$udp.Send($query.ToArray(), $query.Count, $endpoint)
        $response = $udp.Receive([ref]$endpoint)
    } finally {
        $udp.Dispose()
    }
    if ($response.Length -lt 12 -or ($response[2] -band 0x80) -eq 0) {
        throw "DNS listener smoke returned an invalid response"
    }

    $udpV6 = [System.Net.Sockets.UdpClient]::new([System.Net.Sockets.AddressFamily]::InterNetworkV6)
    try {
        $udpV6.Client.ReceiveTimeout = 5000
        $endpointV6 = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::IPv6Loopback, 53540)
        [void]$udpV6.Send($query.ToArray(), $query.Count, $endpointV6)
        $responseV6 = $udpV6.Receive([ref]$endpointV6)
    } finally {
        $udpV6.Dispose()
    }
    if ($responseV6.Length -lt 12 -or ($responseV6[2] -band 0x80) -eq 0) {
        throw "IPv6 DNS listener smoke returned an invalid response"
    }

    $dnsTcpFrame = [byte[]]::new($query.Count + 2)
    $dnsTcpFrame[0] = [byte]($query.Count -shr 8)
    $dnsTcpFrame[1] = [byte]$query.Count
    [Array]::Copy($query.ToArray(), 0, $dnsTcpFrame, 2, $query.Count)
    $dnsTcp = $null
    try {
        $connected = $false
        for ($attempt = 0; $attempt -lt 40 -and -not $connected; $attempt++) {
            $candidate = [System.Net.Sockets.TcpClient]::new()
            try {
                $candidate.ReceiveTimeout = 5000
                $candidate.Connect("127.0.0.1", 53541)
                $dnsTcp = $candidate
                $connected = $true
            } catch {
                $candidate.Dispose()
                Start-Sleep -Milliseconds 250
            }
        }
        if (-not $connected) {
            throw "DNS TCP listener did not become ready"
        }
        $dnsTcpStream = $dnsTcp.GetStream()
        $dnsTcpStream.ReadTimeout = 5000
        $dnsTcpStream.Write($dnsTcpFrame, 0, $dnsTcpFrame.Length)
        $dnsTcpStream.Flush()
        $dnsTcpLength = Read-Exact $dnsTcpStream 2
        $dnsTcpBodyLength = ($dnsTcpLength[0] -shl 8) -bor $dnsTcpLength[1]
        if ($dnsTcpBodyLength -lt 12) {
            throw "DNS TCP listener returned an invalid length"
        }
        $dnsTcpBody = Read-Exact $dnsTcpStream $dnsTcpBodyLength
        if (($dnsTcpBody[2] -band 0x80) -eq 0) {
            throw "DNS TCP listener response did not set QR"
        }
    } finally {
        if ($null -ne $dnsTcp) {
            $dnsTcp.Dispose()
        }
    }

    $tlsClient = [System.Net.Sockets.TcpClient]::new()
    try {
        $tlsClient.Connect("127.0.0.1", 18444)
        $tlsStream = [System.Net.Security.SslStream]::new(
            $tlsClient.GetStream(), $false,
            { param($sender, $certificate, $chain, $errors) return $true })
        $tlsStream.AuthenticateAsClient("example.test")
        if (-not $tlsStream.IsEncrypted -or -not $tlsStream.IsAuthenticated) {
            throw "TLS listener smoke did not complete an authenticated encrypted session"
        }
        $tlsStream.Dispose()
    } finally {
        $tlsClient.Dispose()
    }

    $sshClient = [System.Net.Sockets.TcpClient]::new()
    try {
        $sshClient.ReceiveTimeout = 5000
        $sshClient.Connect("127.0.0.1", 12222)
        $sshStream = $sshClient.GetStream()
        $sshStream.ReadTimeout = 5000
        $sshBuffer = [byte[]]::new(256)
        $sshCount = $sshStream.Read($sshBuffer, 0, $sshBuffer.Length)
        $sshBanner = [System.Text.Encoding]::ASCII.GetString($sshBuffer, 0, $sshCount)
        if ($sshCount -le 0 -or $sshBanner -notmatch '(?m)^SSH-2\.0-[^\r\n]+\r\n') {
            throw "SSH listener did not return a valid server banner"
        }
    } finally {
        $sshClient.Dispose()
    }

    $telnetClient = [System.Net.Sockets.TcpClient]::new()
    try {
        $telnetClient.ReceiveTimeout = 5000
        $telnetClient.Connect("127.0.0.1", 12323)
        $telnetStream = $telnetClient.GetStream()
        $telnetStream.ReadTimeout = 5000
        $telnetBuffer = [byte[]]::new(256)
        $telnetCount = $telnetStream.Read($telnetBuffer, 0, $telnetBuffer.Length)
        $telnetBanner = [System.Text.Encoding]::ASCII.GetString($telnetBuffer, 0, $telnetCount)
        if ($telnetCount -le 0 -or $telnetBanner -notmatch '(?i)login:\s*$') {
            throw "Telnet listener did not return a login prompt"
        }
    } finally {
        $telnetClient.Dispose()
    }

    "Subject: NetTrap Windows E2E`r`n`r`nclient delivery`r`n" |
        Set-Content -Path $messagePath -NoNewline -Encoding ascii
    $smtpResult = & $curlPath --noproxy "*" --silent --show-error --url "smtp://127.0.0.1:12526" `
        --mail-from "sender@example.test" --mail-rcpt "receiver@example.test" `
        --upload-file $messagePath 2>&1
    if ($LASTEXITCODE -ne 0) {
        throw "SMTP client delivery failed: $($smtpResult -join ' ')"
    }
    if ($null -eq (Get-ChildItem -Path $smtpDir -Filter "*.eml" -Recurse -File -ErrorAction SilentlyContinue)) {
        throw "SMTP listener did not persist the client message"
    }

    $ftpResult = & $curlPath --noproxy "*" --silent --show-error --user "malware:secret" `
        "ftp://127.0.0.1:12122/readme.txt" 2>&1
    if ($LASTEXITCODE -ne 0 -or ($ftpResult -join "`n").Trim() -ne "NetTrap default text file") {
        throw "FTP client download failed: $($ftpResult -join ' ')"
    }

    $pop3Result = & $curlPath --noproxy "*" --silent --show-error --user "malware:secret" `
        "pop3://127.0.0.1:11110/" 2>&1
    if ($LASTEXITCODE -ne 0 -or ($pop3Result -join "`n") -notmatch '(?m)^\d+\s+\d+$') {
        throw "POP3 client capability probe failed: $($pop3Result -join ' ')"
    }

    $imapResult = & $curlPath --noproxy "*" --silent --show-error --user "malware:secret" `
        "imap://127.0.0.1:1143/" 2>&1
    if ($LASTEXITCODE -ne 67 -or ($imapResult -join "`n") -notmatch "Access denied") {
        throw "IMAP client auth probe did not return the expected denial"
    }

    Stop-NetTrap
    if (-not (Test-Path -LiteralPath $eventsPath -PathType Leaf) -or
        (Get-Item -LiteralPath $eventsPath).Length -le 0) {
        throw "Windows listener smoke did not persist JSONL events"
    }

    Write-Host "PASS: Windows IPv4/IPv6 TCP/UDP plus SMTP/FTP/POP3/IMAP client parity smoke"
} finally {
    Stop-NetTrap
}

exit 0
