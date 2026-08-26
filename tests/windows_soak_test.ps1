param(
    [Parameter(Mandatory = $true)]
    [string] $BinaryPath
)

$ErrorActionPreference = "Stop"
$durationText = if ($env:NETTRAP_SOAK_SECONDS) { $env:NETTRAP_SOAK_SECONDS } else { "60" }
$concurrencyText = if ($env:NETTRAP_SOAK_CONCURRENCY) { $env:NETTRAP_SOAK_CONCURRENCY } else { "8" }
$churnText = if ($env:NETTRAP_SOAK_CONNECTION_CHURN) { $env:NETTRAP_SOAK_CONNECTION_CHURN } else { "64" }
if ($durationText -notmatch '^[1-9][0-9]*$' -or [int]$durationText -gt 1800) {
    throw "NETTRAP_SOAK_SECONDS must be between 1 and 1800"
}
if ($concurrencyText -notmatch '^[1-9][0-9]*$' -or [int]$concurrencyText -gt 64) {
    throw "NETTRAP_SOAK_CONCURRENCY must be between 1 and 64"
}
if ($churnText -notmatch '^[1-9][0-9]*$' -or [int]$churnText -gt 256) {
    throw "NETTRAP_SOAK_CONNECTION_CHURN must be between 1 and 256"
}

$duration = [int]$durationText
$concurrency = [int]$concurrencyText
$churn = [int]$churnText
$temp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } else { [IO.Path]::GetTempPath() }
$workDir = Join-Path $temp "nettrap-windows-soak"
$config = Join-Path $workDir "config.toml"
$stopFlag = Join-Path $workDir "stop.flag"
$stdout = Join-Path $workDir "stdout.log"
$stderr = Join-Path $workDir "stderr.log"
$process = $null

New-Item -ItemType Directory -Force -Path $workDir | Out-Null
Remove-Item -LiteralPath $stopFlag -Force -ErrorAction SilentlyContinue
@"
attribution_enabled = false
default_decision = "emulate"
pcap_enabled = false
output_format = "jsonl"

[[listeners]]
name = "soak-http"
protocol = "tcp"
port = 18080
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "soak-dns"
protocol = "udp"
port = 18053
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "dns"
protocol = "tcp"
port = 18054
bind_address = "127.0.0.1"
enabled = true
emulate_response = true
"@ | Set-Content -LiteralPath $config -Encoding utf8

$http = [Text.Encoding]::ASCII.GetBytes(
    ('GET / HTTP/1.1' + [char]13 + [char]10 + 'Host: soak.example.test' +
        [char]13 + [char]10 + 'Connection: close' + [char]13 + [char]10 + [char]13 + [char]10))
$dns = [byte[]](0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01)
$bad = [byte[]]::new(4096)
for ($i = 0; $i -lt $bad.Length; $i++) { $bad[$i] = 0xff }

function Stop-NetTrap {
    if ($null -ne $script:process -and -not $script:process.HasExited) {
        New-Item -ItemType File -Force -Path $stopFlag | Out-Null
        if (-not $script:process.WaitForExit(15000)) {
            Stop-Process -Id $script:process.Id -Force -ErrorAction SilentlyContinue
        }
    }
}

function Assert-TcpListenersClosed([int[]] $Ports) {
    foreach ($port in $Ports) {
        $closed = $false
        for ($attempt = 0; $attempt -lt 20 -and -not $closed; $attempt++) {
            $client = [Net.Sockets.TcpClient]::new()
            try {
                $client.Connect("127.0.0.1", $port)
            } catch [System.Net.Sockets.SocketException] {
                $closed = $true
            } finally {
                $client.Dispose()
            }
            if (-not $closed) { Start-Sleep -Milliseconds 250 }
        }
        if (-not $closed) {
            throw "TCP listener on port $port remained open after shutdown"
        }
    }
}

function Wait-Tcp([int] $Port) {
    for ($i = 0; $i -lt 40; $i++) {
        if ($process.HasExited) { throw "NetTrap exited before listener startup" }
        $client = [Net.Sockets.TcpClient]::new()
        try { $client.Connect("127.0.0.1", $Port); return }
        catch { Start-Sleep -Milliseconds 250 }
        finally { $client.Dispose() }
    }
    throw "TCP listener on port $Port did not become ready"
}

function Reset-Connection([Net.Sockets.TcpClient] $Client) {
    if ($Client.Connected) {
        $Client.Client.LingerState = [Net.Sockets.LingerOption]::new($true, 0)
    }
}

function Invoke-Http {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.ReceiveTimeout = 5000
        $client.Connect("127.0.0.1", 18080)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $stream.Write($http, 0, $http.Length)
        $buffer = [byte[]]::new(256)
        $count = $stream.Read($buffer, 0, $buffer.Length)
        $text = [Text.Encoding]::ASCII.GetString($buffer, 0, $count)
        if ($count -eq 0 -or $text -notmatch '^HTTP/1\.[01] \d{3}') {
            throw "HTTP soak probe returned an invalid response"
        }
    } finally {
        Reset-Connection $client
        $client.Dispose()
    }
}

function Invoke-Dns {
    $udp = [Net.Sockets.UdpClient]::new()
    try {
        $udp.Client.ReceiveTimeout = 5000
        $endpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 18053)
        [void]$udp.Send($dns, $dns.Length, $endpoint)
        $response = $udp.Receive([ref]$endpoint)
        if ($response.Length -lt 12 -or ($response[2] -band 0x80) -eq 0) {
            throw "DNS UDP soak probe returned an invalid response"
        }
    } finally { $udp.Dispose() }
}

function Invoke-DnsTcp {
    $client = [Net.Sockets.TcpClient]::new()
    try {
        $client.ReceiveTimeout = 5000
        $client.Connect("127.0.0.1", 18054)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        $frame = [byte[]]::new($dns.Length + 2)
        $frame[0] = ($dns.Length -shr 8) -band 0xff
        $frame[1] = $dns.Length -band 0xff
        [Array]::Copy($dns, 0, $frame, 2, $dns.Length)
        $stream.Write($frame, 0, $frame.Length)
        $prefix = [byte[]]::new(2)
        $prefixRead = 0
        while ($prefixRead -lt $prefix.Length) {
            $read = $stream.Read($prefix, $prefixRead, $prefix.Length - $prefixRead)
            if ($read -le 0) { throw "DNS TCP prefix was truncated" }
            $prefixRead += $read
        }
        $length = ($prefix[0] -shl 8) -bor $prefix[1]
        if ($length -lt 12) { throw "DNS TCP response declared an invalid length" }
        $body = [byte[]]::new($length)
        $offset = 0
        while ($offset -lt $length) {
            $read = $stream.Read($body, $offset, $length - $offset)
            if ($read -le 0) { throw "DNS TCP response was truncated" }
            $offset += $read
        }
        if (($body[2] -band 0x80) -eq 0) {
            throw "DNS TCP response did not set QR (flags byte $($body[2]))"
        }
    } finally {
        Reset-Connection $client
        $client.Dispose()
    }
}

function Invoke-Churn([int] $Count) {
    $clients = [Collections.Generic.List[Net.Sockets.TcpClient]]::new()
    for ($i = 0; $i -lt $Count; $i++) {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $client.Connect("127.0.0.1", 18080)
            $stream = $client.GetStream()
            $stream.Write($http, 0, $http.Length)
            Reset-Connection $client
            [void]$clients.Add($client)
        } catch { $client.Dispose() }
    }
    return ,$clients
}

function Invoke-Malformed {
    $udp = [Net.Sockets.UdpClient]::new()
    try {
        for ($i = 0; $i -lt $concurrency; $i++) {
            $endpoint = [Net.IPEndPoint]::new([Net.IPAddress]::Loopback, 18053)
            [void]$udp.Send($bad, $bad.Length, $endpoint)
        }
    } finally { $udp.Dispose() }
    for ($i = 0; $i -lt $concurrency; $i++) {
        $client = [Net.Sockets.TcpClient]::new()
        try {
            $client.Connect("127.0.0.1", 18080)
            $client.GetStream().Write($bad, 0, $bad.Length)
        } catch {
        } finally {
            Reset-Connection $client
            $client.Dispose()
        }
    }
}

function Assert-Bounds([long] $WorkingSet, [long] $Handles) {
    $process.Refresh()
    if ($process.WorkingSet64 -gt ($WorkingSet + 128MB)) {
        throw "Windows hostile soak exceeded working-set bound"
    }
    if ($process.HandleCount -gt ($Handles + 256)) {
        throw "Windows hostile soak exceeded handle bound"
    }
}

try {
    $process = Start-Process -FilePath $BinaryPath -ArgumentList @(
        "--stop-flag", $stopFlag, "run", "-c", $config
    ) -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru
    Wait-Tcp 18080
    Wait-Tcp 18054
    Invoke-Http
    Invoke-Dns
    Invoke-DnsTcp
    $process.Refresh()
    $workingSet = $process.WorkingSet64
    $handles = $process.HandleCount
    $deadline = [DateTime]::UtcNow.AddSeconds($duration)
    $iterations = 0
    while ([DateTime]::UtcNow -lt $deadline) {
        Invoke-Http
        Invoke-Dns
        Invoke-DnsTcp
        $clients = Invoke-Churn $churn
        try { Start-Sleep -Milliseconds 100 }
        finally { foreach ($client in $clients) { $client.Dispose() } }
        Invoke-Malformed
        if ($process.HasExited) { throw "NetTrap exited during Windows hostile soak" }
        Assert-Bounds $workingSet $handles
        $iterations++
    }
    if ($iterations -eq 0) { throw "Windows hostile soak completed no iterations" }
    Stop-NetTrap
    Assert-TcpListenersClosed @(18080, 18054)
    Write-Host ("PASS: {0}s Windows hostile soak completed ({1} iterations, {2}-connection churn)" -f
        $duration, $iterations, $churn)
} catch {
    $details = if (Test-Path -LiteralPath $stderr) { Get-Content $stderr -Raw } else { "" }
    throw ("{0}{1}{2}" -f $_.Exception.Message, [Environment]::NewLine, $details)
} finally {
    Stop-NetTrap
    Remove-Item -LiteralPath $workDir -Recurse -Force -ErrorAction SilentlyContinue
}
