param(
    [Parameter(Mandatory = $true)]
    [string] $BinaryPath
)

$ErrorActionPreference = "Stop"
$workDir = Join-Path $env:RUNNER_TEMP "nettrap-listener-smoke"
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
"@ | Set-Content -Path $configPath -Encoding utf8

function Stop-NetTrap {
    if ($null -ne $script:process -and -not $script:process.HasExited) {
        Stop-Process -Id $script:process.Id -Force -ErrorAction SilentlyContinue
        $script:process.WaitForExit(5000)
    }
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

    Write-Host "PASS: Windows TCP/UDP listener parity smoke"
} finally {
    Stop-NetTrap
}
