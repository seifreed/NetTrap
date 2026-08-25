param(
    [Parameter(Mandatory = $true)]
    [string] $BinaryPath
)

$ErrorActionPreference = "Stop"
$runnerTemp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } elseif ($env:TEMP) { $env:TEMP } else { [IO.Path]::GetTempPath() }
$workDir = Join-Path $runnerTemp "nettrap-protocol-matrix"
$configPath = Join-Path $workDir "config.toml"
$stdoutPath = Join-Path $workDir "stdout.log"
$stderrPath = Join-Path $workDir "stderr.log"
$process = $null

New-Item -ItemType Directory -Force -Path $workDir | Out-Null
@"
attribution_enabled = false
default_decision = "emulate"
pcap_enabled = false
output_format = "jsonl"

[[listeners]]
name = "dns"
protocol = "udp"
port = 53539
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "http"
protocol = "tcp"
port = 18088
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "smtp"
protocol = "tcp"
port = 12525
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "ftp"
protocol = "tcp"
port = 12121
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "pop3"
protocol = "tcp"
port = 11110
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "imap"
protocol = "tcp"
port = 10143
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "redis"
protocol = "tcp"
port = 16379
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "mqtt"
protocol = "tcp"
port = 18883
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "ldap"
protocol = "tcp"
port = 11389
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "postgres"
protocol = "tcp"
port = 15432
bind_address = "127.0.0.1"
enabled = true
emulate_response = true
"@ | Set-Content -Path $configPath -Encoding utf8

function Stop-NetTrap {
    if ($null -ne $script:process -and -not $script:process.HasExited) {
        Stop-Process -Id $script:process.Id -Force -ErrorAction SilentlyContinue
        [void]$script:process.WaitForExit(5000)
    }
}

function Wait-TcpPort([int] $Port) {
    for ($attempt = 0; $attempt -lt 40; $attempt++) {
        if ($process.HasExited) {
            throw "NetTrap exited before listener startup (code $($process.ExitCode))"
        }
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $client.Connect("127.0.0.1", $Port)
            return
        } catch {
            Start-Sleep -Milliseconds 250
        } finally {
            $client.Dispose()
        }
    }
    throw "TCP listener on port $Port did not become ready"
}

function Read-Bytes($Stream) {
    $buffer = [byte[]]::new(8192)
    try {
        $count = $Stream.Read($buffer, 0, $buffer.Length)
    } catch [System.IO.IOException] {
        return @()
    }
    if ($count -le 0) {
        return @()
    }
    return [byte[]]$buffer[0..($count - 1)]
}

function Invoke-TcpProbe([int] $Port, [byte[]] $Payload, [bool] $ServerFirst) {
    $client = [System.Net.Sockets.TcpClient]::new()
    $client.ReceiveTimeout = 5000
    try {
        $client.Connect("127.0.0.1", $Port)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        if ($ServerFirst) {
            $greeting = @(Read-Bytes $stream)
            if ($greeting.Count -eq 0) {
                throw "server-first listener on port $Port returned no greeting"
            }
        }
        if ($Payload.Length -gt 0) {
            $stream.Write($Payload, 0, $Payload.Length)
            $stream.Flush()
        }
        $response = @(Read-Bytes $stream)
        if ($response.Count -eq 0) {
            throw "TCP listener on port $Port returned no response"
        }
        return [byte[]]$response
    } finally {
        $client.Dispose()
    }
}

function Assert-AsciiResponse([string] $Name, [byte[]] $Response) {
    if ($Response.Length -eq 0) {
        throw "$Name returned an empty response"
    }
}

try {
    $process = Start-Process -FilePath $BinaryPath -ArgumentList @(
        "run", "-c", $configPath
    ) -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru

    foreach ($port in @(18088, 12525, 12121, 11110, 10143, 16379, 18883, 11389, 15432)) {
        Wait-TcpPort $port
    }

    $http = Invoke-WebRequest -UseBasicParsing -Uri "http://127.0.0.1:18088/" `
        -Headers @{ Host = "example.test" } -TimeoutSec 5
    if ($http.StatusCode -ne 200 -or $http.Content.Length -eq 0) {
        throw "HTTP listener returned an invalid response"
    }

    $dnsQuery = [byte[]](0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x07, 0x65, 0x78, 0x61, 0x6D, 0x70, 0x6C, 0x65, 0x03, 0x63, 0x6F, 0x6D, 0x00,
        0x00, 0x01, 0x00, 0x01)
    $udp = [System.Net.Sockets.UdpClient]::new()
    try {
        $udp.Client.ReceiveTimeout = 5000
        $endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, 53539)
        [void]$udp.Send($dnsQuery, $dnsQuery.Length, $endpoint)
        $dnsResponse = $udp.Receive([ref]$endpoint)
    } finally {
        $udp.Dispose()
    }
    if ($dnsResponse.Length -lt 12 -or ($dnsResponse[2] -band 0x80) -eq 0) {
        throw "DNS listener returned an invalid response"
    }

    $cases = @(
        @{ Name = "SMTP"; Port = 12525; ServerFirst = $true; Payload = [Text.Encoding]::ASCII.GetBytes("EHLO matrix.test`r`n") },
        @{ Name = "FTP"; Port = 12121; ServerFirst = $true; Payload = [Text.Encoding]::ASCII.GetBytes("SYST`r`n") },
        @{ Name = "POP3"; Port = 11110; ServerFirst = $true; Payload = [Text.Encoding]::ASCII.GetBytes("CAPA`r`n") },
        @{ Name = "IMAP"; Port = 10143; ServerFirst = $true; Payload = [Text.Encoding]::ASCII.GetBytes("a001 CAPABILITY`r`n") },
        @{ Name = "Redis"; Port = 16379; ServerFirst = $false; Payload = [Text.Encoding]::ASCII.GetBytes("*1`r`n`$4`r`nPING`r`n") },
        @{ Name = "MQTT"; Port = 18883; ServerFirst = $false; Payload = [byte[]](0x10, 0x0C, 0x00, 0x04, 0x4D, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3C, 0x00, 0x00) },
        @{ Name = "LDAP"; Port = 11389; ServerFirst = $false; Payload = [byte[]](0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00) },
        @{ Name = "PostgreSQL"; Port = 15432; ServerFirst = $false; Payload = [byte[]](0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00) }
    )
    foreach ($case in $cases) {
        $response = Invoke-TcpProbe $case.Port $case.Payload $case.ServerFirst
        Assert-AsciiResponse $case.Name $response
    }

    if ($process.HasExited) {
        throw "NetTrap exited during protocol matrix smoke (code $($process.ExitCode))"
    }
    Write-Host "PASS: Windows protocol matrix parity smoke (DNS, HTTP, SMTP, FTP, POP3, IMAP, Redis, MQTT, LDAP, PostgreSQL)"
} catch {
    $stderr = if (Test-Path $stderrPath) { Get-Content $stderrPath -Raw } else { "" }
    throw "$($_.Exception.Message)`n$stderr"
} finally {
    Stop-NetTrap
}
