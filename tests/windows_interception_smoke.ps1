param(
    [Parameter(Mandatory = $true)]
    [string] $BinaryPath
)

$ErrorActionPreference = "Stop"
$workDir = Join-Path $env:RUNNER_TEMP "nettrap-interception-smoke"
$configPath = Join-Path $workDir "config.toml"
$eventsPath = Join-Path $workDir "events.jsonl"
$stdoutPath = Join-Path $workDir "stdout.log"
$stderrPath = Join-Path $workDir "stderr.log"
$process = $null

New-Item -ItemType Directory -Force -Path $workDir | Out-Null
@"
attribution_enabled = false
default_decision = "emulate"
redirect_all_traffic = true
default_tcp_listener = "http-smoke"
default_udp_listener = "dns-smoke"
pcap_enabled = false
output_format = "jsonl"
output_path = "$($eventsPath.Replace('\', '/'))"

[[listeners]]
name = "http-smoke"
protocol = "tcp"
port = 18088
# WinDivert NAT injects rewritten packets into the inbound stack; wildcard
# listeners are required because Windows does not deliver these packets to a
# loopback-only socket.
bind_address = "0.0.0.0"
enabled = true
emulate_response = true

[[listeners]]
name = "dns-smoke"
protocol = "udp"
port = 53539
bind_address = "0.0.0.0"
enabled = true
emulate_response = true
"@ | Set-Content -Path $configPath -Encoding utf8

function Stop-NetTrap {
    if ($null -ne $script:process -and -not $script:process.HasExited) {
        Stop-Process -Id $script:process.Id -Force -ErrorAction SilentlyContinue
        $script:process.WaitForExit(5000)
    }
}

function Process-Output {
    @(
        if (Test-Path $stdoutPath) { Get-Content $stdoutPath -Raw }
        if (Test-Path $stderrPath) { Get-Content $stderrPath -Raw }
    ) -join "`n"
}

try {
    $process = Start-Process -FilePath $BinaryPath -ArgumentList @(
        "run", "--intercept", "-c", $configPath
    ) -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
    Start-Sleep -Seconds 3
    if ($process.HasExited) {
        $output = @(
            if (Test-Path $stdoutPath) { Get-Content $stdoutPath -Raw }
            if (Test-Path $stderrPath) { Get-Content $stderrPath -Raw }
        ) -join "`n"
        throw "Windows transparent interception exited during startup (code $($process.ExitCode)): $output"
    }

    $tcpOutput = & curl.exe --noproxy "*" --silent --show-error --connect-timeout 5 --max-time 10 `
        --header "Host: interception.test" http://198.51.100.1/ 2>&1
    if ($LASTEXITCODE -ne 0 -or $tcpOutput -notmatch "It Works") {
        throw "TCP traffic was not redirected to the local listener: $tcpOutput`n$(Process-Output)"
    }

    $dnsOutput = & nslookup.exe -timeout=3 -retry=0 example.test 198.51.100.1 2>&1
    if ($LASTEXITCODE -ne 0 -or $dnsOutput -notmatch "Address:\s+\d+\.\d+\.\d+\.\d+") {
        throw "UDP traffic was not redirected to the local DNS listener: $dnsOutput`n$(Process-Output)"
    }

    Stop-NetTrap
    if (-not (Test-Path -LiteralPath $eventsPath -PathType Leaf) -or
        (Get-Item -LiteralPath $eventsPath).Length -le 0) {
        throw "Interception did not persist any event records"
    }
    Write-Host "PASS: Windows transparent interception redirected TCP/UDP traffic and persisted events"
} finally {
    Stop-NetTrap
}
