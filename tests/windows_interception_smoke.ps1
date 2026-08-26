param(
    [Parameter(Mandatory = $true)]
    [string] $BinaryPath
)

$ErrorActionPreference = "Stop"
$workDir = Join-Path $env:RUNNER_TEMP "nettrap-interception-smoke"
$configPath = Join-Path $workDir "config.toml"
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

[[listeners]]
name = "http-smoke"
protocol = "tcp"
port = 18088
bind_address = "127.0.0.1"
enabled = true
emulate_response = true

[[listeners]]
name = "dns-smoke"
protocol = "udp"
port = 53539
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
        "run", "--intercept", "-c", $configPath
    ) -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru
    if (-not $process.WaitForExit(10000)) {
        Stop-NetTrap
        throw "Windows transparent interception did not fail closed"
    }
    $output = @(
        if (Test-Path $stdoutPath) { Get-Content $stdoutPath -Raw }
        if (Test-Path $stderrPath) { Get-Content $stderrPath -Raw }
    ) -join "`n"
    if ($process.ExitCode -eq 0 -or $output -notmatch "disabled|not supported|packet-preserving NAT") {
        throw "Windows transparent interception was not rejected safely (code $($process.ExitCode)): $output"
    }
    Write-Host "PASS: Windows transparent interception fails closed before opening WinDivert"
} finally {
    Stop-NetTrap
}
