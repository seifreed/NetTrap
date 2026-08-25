param(
    [Parameter(Mandatory = $true)]
    [string] $BinaryPath
)

$ErrorActionPreference = "Stop"
$workDir = Join-Path $env:RUNNER_TEMP "nettrap-interception-smoke"
$configPath = Join-Path $workDir "config.toml"
$stdoutPath = Join-Path $workDir "stdout.log"
$stderrPath = Join-Path $workDir "stderr.log"
$bodyPath = Join-Path $workDir "response.body"
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

    $statusCode = $null
    for ($attempt = 0; $attempt -lt 40 -and $null -eq $statusCode; $attempt++) {
        if ($process.HasExited) {
            throw "NetTrap exited before interception startup (code $($process.ExitCode))"
        }
        try {
            $statusCode = (& curl.exe --noproxy "*" --silent --show-error --max-time 2 `
                --output $bodyPath --write-out "%{http_code}" --header "Host: example.test" `
                "http://198.18.0.1/")
            if ($LASTEXITCODE -ne 0 -or $statusCode -ne "200") {
                $statusCode = $null
                Start-Sleep -Milliseconds 250
            }
        } catch {
            $statusCode = $null
            Start-Sleep -Milliseconds 250
        }
    }
    if ($statusCode -ne "200") {
        $stderr = if (Test-Path $stderrPath) { Get-Content $stderrPath -Raw } else { "" }
        throw "WinDivert interception did not redirect the HTTP request. $stderr"
    }

    $dnsAnswer = Resolve-DnsName -Name "example.test" -Type A -Server "198.18.0.1" -DnsOnly -QuickTimeout
    if (-not ($dnsAnswer | Where-Object { $_.IPAddress -match '^\d+(\.\d+){3}$' })) {
        throw "WinDivert interception did not redirect the UDP DNS request"
    }

    if ($process.HasExited) {
        throw "NetTrap exited after interception smoke (code $($process.ExitCode))"
    }
    Write-Host "PASS: Windows WinDivert TCP/UDP interception smoke"
} finally {
    Stop-NetTrap
}
