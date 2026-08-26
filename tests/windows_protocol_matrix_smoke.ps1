param(
    [Parameter(Mandatory = $true)]
    [string] $BinaryPath
)

$ErrorActionPreference = "Stop"
$runnerTemp = if ($env:RUNNER_TEMP) { $env:RUNNER_TEMP } elseif ($env:TEMP) { $env:TEMP } else { [IO.Path]::GetTempPath() }
$workDir = Join-Path $runnerTemp "nettrap-protocol-matrix"
$configPath = Join-Path $workDir "config.toml"
$eventLogPath = Join-Path $workDir "events.jsonl"
$stdoutPath = Join-Path $workDir "stdout.log"
$stderrPath = Join-Path $workDir "stderr.log"
$process = $null
$manifestPath = Join-Path $PSScriptRoot "protocol_matrix_manifest.txt"
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) {
    throw "protocol matrix manifest is missing: $manifestPath"
}
$manifestRows = @(
    Get-Content -LiteralPath $manifestPath |
        Where-Object { $_.Trim() -and -not $_.TrimStart().StartsWith("#") } |
        ForEach-Object {
            $fields = $_ -split '\s+'
            if ($fields.Count -ne 3 -or $fields[0] -notin @("tcp", "udp") -or
                $fields[2] -notin @("response", "capture")) {
                throw "invalid protocol matrix manifest row: $_"
            }
            [pscustomobject]@{ Transport = $fields[0]; Name = $fields[1]; Mode = $fields[2] }
        }
)
$tcpRows = @($manifestRows | Where-Object Transport -eq "tcp")
$udpRows = @($manifestRows | Where-Object Transport -eq "udp")
if ($tcpRows.Count -eq 0 -or $udpRows.Count -eq 0) {
    throw "protocol matrix manifest must define TCP and UDP handlers"
}
if ($tcpRows.Count -ne 30 -or $udpRows.Count -ne 14) {
    throw "protocol matrix manifest must define 30 TCP and 14 UDP handlers"
}
if (@($tcpRows.Name | Sort-Object -Unique).Count -ne $tcpRows.Count -or
    @($udpRows.Name | Sort-Object -Unique).Count -ne $udpRows.Count) {
    throw "protocol matrix manifest contains duplicate handlers"
}
$repeatText = if ($env:NETTRAP_MATRIX_REPEAT) { $env:NETTRAP_MATRIX_REPEAT } else { "1" }
if ($repeatText -notmatch '^[1-9][0-9]*$' -or [int]$repeatText -gt 32) {
    throw "NETTRAP_MATRIX_REPEAT must be between 1 and 32"
}
$repeat = [int]$repeatText
$durationText = if ($env:NETTRAP_MATRIX_DURATION_SECONDS) { $env:NETTRAP_MATRIX_DURATION_SECONDS } else { "0" }
if ($durationText -notmatch '^[0-9]+$' -or [int]$durationText -gt 1800) {
    throw "NETTRAP_MATRIX_DURATION_SECONDS must be between 0 and 1800"
}
$durationSeconds = [int]$durationText

$tcpNames = @($tcpRows.Name)
$udpNames = @($udpRows.Name)
$expectedEventListeners = @($tcpNames) + @($udpNames | ForEach-Object { "$_-udp" })
$tcpCaptureOnly = @($tcpRows | Where-Object Mode -eq "capture" | ForEach-Object Name)
$udpCaptureOnly = @($udpRows | Where-Object Mode -eq "capture" | ForEach-Object Name)
$tcpObservedResponses = [System.Collections.Generic.List[string]]::new()
$udpObservedResponses = [System.Collections.Generic.List[string]]::new()
$tcpResponses = 0
$udpResponses = 0
$tcpPorts = @{}
$udpPorts = @{}

New-Item -ItemType Directory -Force -Path $workDir | Out-Null

$config = [System.Collections.Generic.List[string]]::new()
[void]$config.Add("attribution_enabled = false")
[void]$config.Add('default_decision = "emulate"')
[void]$config.Add("pcap_enabled = false")
[void]$config.Add('output_format = "jsonl"')
[void]$config.Add(('output_path = "{0}"' -f $eventLogPath.Replace('\', '/')))

$port = 19000
foreach ($name in $tcpNames) {
    $tcpPorts[$name] = $port
    [void]$config.Add("")
    [void]$config.Add("[[listeners]]")
    [void]$config.Add("name = `"$name`"")
    [void]$config.Add('protocol = "tcp"')
    [void]$config.Add("port = $port")
    [void]$config.Add('bind_address = "127.0.0.1"')
    [void]$config.Add("enabled = true")
    [void]$config.Add("emulate_response = true")
    $port++
}
foreach ($name in $udpNames) {
    $listenerName = "$name-udp"
    $udpPorts[$name] = $port
    [void]$config.Add("")
    [void]$config.Add("[[listeners]]")
    [void]$config.Add("name = `"$listenerName`"")
    [void]$config.Add('protocol = "udp"')
    [void]$config.Add("port = $port")
    [void]$config.Add('bind_address = "127.0.0.1"')
    [void]$config.Add("enabled = true")
    [void]$config.Add("emulate_response = true")
    $port++
}
$config | Set-Content -Path $configPath -Encoding utf8

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
        return [byte[]]::new(0)
    }
    if ($count -le 0) {
        return [byte[]]::new(0)
    }
    return [byte[]]$buffer[0..($count - 1)]
}

function Invoke-TcpProbe([string] $Name, [int] $Port, [byte[]] $Payload, [bool] $ServerFirst, [bool] $ExpectResponse) {
    $client = [System.Net.Sockets.TcpClient]::new()
    $client.ReceiveTimeout = 5000
    try {
        $client.Connect("127.0.0.1", $Port)
        $stream = $client.GetStream()
        $stream.ReadTimeout = 5000
        if ($ServerFirst) {
            $greeting = Read-Bytes $stream
            if ($ExpectResponse -and $greeting.Length -eq 0) {
                throw "server-first listener on port $Port returned no greeting"
            }
            if ($Payload.Length -eq 0) {
                if ($ExpectResponse -and -not $script:tcpObservedResponses.Contains($Name)) {
                    [void]$script:tcpObservedResponses.Add($Name)
                }
                if ($ExpectResponse) {
                    $script:tcpResponses++
                }
                return
            }
        }
        if ($Payload.Length -gt 0) {
            $stream.Write($Payload, 0, $Payload.Length)
            $stream.Flush()
        }
        if (-not $ExpectResponse) {
            return
        }
        $response = Read-Bytes $stream
        if ($response.Length -eq 0) {
            throw "TCP listener on port $Port returned no response"
        }
        if (-not $script:tcpObservedResponses.Contains($Name)) {
            [void]$script:tcpObservedResponses.Add($Name)
        }
        $script:tcpResponses++
    } finally {
        $client.Dispose()
    }
}

function Invoke-UdpProbe([string] $Name, [int] $Port, [byte[]] $Payload, [bool] $ExpectResponse) {
    $udp = [System.Net.Sockets.UdpClient]::new()
    try {
        $udp.Client.ReceiveTimeout = 5000
        $endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, $Port)
        [void]$udp.Send($Payload, $Payload.Length, $endpoint)
        if (-not $ExpectResponse) {
            return
        }
        $response = $udp.Receive([ref]$endpoint)
        if ($response.Length -eq 0) {
            throw "UDP listener on port $Port returned no response"
        }
        if (-not $script:udpObservedResponses.Contains($Name)) {
            [void]$script:udpObservedResponses.Add($Name)
        }
        $script:udpResponses++
    } finally {
        $udp.Dispose()
    }
}

function Assert-ResourceBounds([long] $WorkingSetBaseline, [long] $HandleBaseline) {
    $process.Refresh()
    if ($process.WorkingSet64 -gt ($WorkingSetBaseline + 128MB)) {
        throw "Windows protocol matrix exceeded RSS bound ($($process.WorkingSet64), baseline $WorkingSetBaseline)"
    }
    if ($process.HandleCount -gt ($HandleBaseline + 256)) {
        throw "Windows protocol matrix exceeded handle bound ($($process.HandleCount), baseline $HandleBaseline)"
    }
}

function Invoke-TcpMalformedBurst([object[]] $Ports) {
    $payload = [byte[]]::new(4096)
    for ($index = 0; $index -lt $payload.Length; $index++) {
        $payload[$index] = 0xff
    }
    foreach ($port in $Ports) {
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $connect = $client.ConnectAsync("127.0.0.1", [int]$port)
            if (-not $connect.Wait(250)) {
                continue
            }
            $stream = $client.GetStream()
            $stream.Write($payload, 0, $payload.Length)
            $stream.Flush()
        } catch [System.Net.Sockets.SocketException] {
        } catch [System.AggregateException] {
        } catch [System.IO.IOException] {
        } finally {
            $client.Dispose()
        }
    }
}

function Invoke-UdpMalformedBurst([object[]] $Ports) {
    $payload = [byte[]]::new(4096)
    for ($index = 0; $index -lt $payload.Length; $index++) {
        $payload[$index] = 0xff
    }
    $udp = [System.Net.Sockets.UdpClient]::new()
    try {
        foreach ($port in $Ports) {
            $endpoint = [System.Net.IPEndPoint]::new([System.Net.IPAddress]::Loopback, [int]$port)
            try {
                [void]$udp.Send($payload, $payload.Length, $endpoint)
            } catch [System.Net.Sockets.SocketException] {
            }
        }
    } finally {
        $udp.Dispose()
    }
}

function Get-TcpPayload([string] $Name) {
    switch ($Name) {
        "dns" { return [byte[]](0x00, 0x1d, 0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01) }
        "http" { return [Text.Encoding]::ASCII.GetBytes("GET / HTTP/1.1`r`nHost: matrix.test`r`nConnection: close`r`n`r`n") }
        "smtp" { return [Text.Encoding]::ASCII.GetBytes("EHLO matrix.test`r`nQUIT`r`n") }
        "ftp" { return [Text.Encoding]::ASCII.GetBytes("SYST`r`nQUIT`r`n") }
        "pop3" { return [Text.Encoding]::ASCII.GetBytes("CAPA`r`nQUIT`r`n") }
        "imap" { return [Text.Encoding]::ASCII.GetBytes("a001 CAPABILITY`r`na002 LOGOUT`r`n") }
        "irc" { return [Text.Encoding]::ASCII.GetBytes("NICK matrix`r`nUSER matrix 0 * :matrix`r`n") }
        "telnet" { return [byte[]](0xff, 0xfb, 0x01, 0xff, 0xfb, 0x03) }
        "finger" { return [Text.Encoding]::ASCII.GetBytes("root`r`n") }
        "ident" { return [Text.Encoding]::ASCII.GetBytes("40000 , 80`r`n") }
        "daytime" { return [byte[]]::new(0) }
        "time" { return [byte[]]::new(0) }
        "chargen" { return [byte[]]::new(0) }
        "quotd" { return [byte[]]::new(0) }
        "ssh" { return [byte[]]::new(0) }
        "mysql" { return [byte[]]::new(0) }
        "syslogrecv" { return [Text.Encoding]::ASCII.GetBytes("<34>1 2026-01-01T00:00:00Z host app 1 ID47 - smoke`n") }
        "rdp" { return [byte[]](0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00, 0x00) }
        "smb" {
            $smb2 = [byte[]]::new(68)
            $smb2[0] = 0xfe; $smb2[1] = 0x53; $smb2[2] = 0x4d; $smb2[3] = 0x42
            $smb2[4] = 0x40
            $messageId = [byte[]](0xf0, 0xde, 0xbc, 0x9a, 0x78, 0x56, 0x34, 0x12)
            [Array]::Copy($messageId, 0, $smb2, 24, $messageId.Length)
            $packet = [byte[]]::new(72)
            $packet[3] = 0x44
            [Array]::Copy($smb2, 0, $packet, 4, $smb2.Length)
            return $packet
        }
        "redis" { return [Text.Encoding]::ASCII.GetBytes("*1`r`n`$4`r`nPING`r`n") }
        "ldap" { return [byte[]](0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00) }
        "socks" { return [byte[]](0x05, 0x01, 0x00) }
        "memcached" { return [Text.Encoding]::ASCII.GetBytes("version`r`n") }
        "mqtt" { return [byte[]](0x10, 0x0c, 0x00, 0x04, 0x4d, 0x51, 0x54, 0x54, 0x04, 0x02, 0x00, 0x3c, 0x00, 0x00) }
        "tls" { return [byte[]](0x16, 0x03, 0x01, 0x00, 0x00) }
        "upnp" { return [Text.Encoding]::ASCII.GetBytes("GET /desc.xml HTTP/1.1`r`nHost: matrix.test`r`nConnection: close`r`n`r`n") }
        "nkn" {
            $payload = [Text.Encoding]::ASCII.GetBytes('{"jsonrpc":"2.0","method":"getnodestate","id":7}')
            return $payload + [byte[]](0x0a)
        }
        "postgres" { return [byte[]](0x00, 0x00, 0x00, 0x08, 0x00, 0x03, 0x00, 0x00) }
        default { return [Text.Encoding]::ASCII.GetBytes("probe`r`n") }
    }
}

function Get-UdpPayload([string] $Name) {
    switch ($Name) {
        "dns" { return [byte[]](0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00, 0x00, 0x01, 0x00, 0x01) }
        "tftp" { return [byte[]](0x00, 0x01, 0x73, 0x6d, 0x6f, 0x6b, 0x65, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x6f, 0x63, 0x74, 0x65, 0x74, 0x00) }
        "snmp" { return [byte[]](0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70, 0x75, 0x62, 0x6c, 0x69, 0x63, 0xa0, 0x19, 0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00) }
        "sip" { return [Text.Encoding]::ASCII.GetBytes("OPTIONS sip:matrix.test SIP/2.0`r`nVia: SIP/2.0/UDP 127.0.0.1:5060;branch=z9hG4bK-matrix`r`nFrom: <sip:matrix@matrix.test>;tag=matrix`r`nTo: <sip:matrix@matrix.test>`r`nCall-ID: matrix-call`r`nCSeq: 1 OPTIONS`r`nContent-Length: 0`r`n`r`n") }
        "ntp" { $payload = [byte[]]::new(48); $payload[0] = 0x1b; return $payload }
        "coap" { return [byte[]](0x41, 0x01, 0x12, 0x34, 0xaa) }
        "quic" { return [byte[]](0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00) }
        "upnp" { return [Text.Encoding]::ASCII.GetBytes("M-SEARCH * HTTP/1.1`r`nHOST: 239.255.255.250:1900`r`nMAN: `"ssdp:discover`"`r`nMX: 1`r`nST: ssdp:all`r`n`r`n") }
        "daytime" { return [byte[]](0x0a) }
        "time" { return [byte[]](0x0a) }
        "chargen" { return [byte[]](0x0a) }
        "quotd" { return [byte[]](0x0a) }
        "syslogrecv" { return [byte[]](0x0a) }
        default { return [Text.Encoding]::ASCII.GetBytes("probe`n") }
    }
}

function Is-ServerFirst([string] $Name) {
    return @("daytime", "time", "chargen", "quotd") -contains $Name
}

try {
    $process = Start-Process -FilePath $BinaryPath -ArgumentList @(
        "run", "-c", $configPath
    ) -RedirectStandardOutput $stdoutPath -RedirectStandardError $stderrPath -PassThru

    foreach ($portValue in $tcpPorts.Values) {
        Wait-TcpPort $portValue
    }

    $process.Refresh()
    $workingSetBaseline = $process.WorkingSet64
    $handleBaseline = $process.HandleCount
    $deadline = [DateTime]::UtcNow.AddSeconds($durationSeconds)
    $round = 1
    while ($round -le $repeat -or ($durationSeconds -gt 0 -and [DateTime]::UtcNow -lt $deadline)) {
        foreach ($name in $tcpNames) {
            $expectResponse = $tcpCaptureOnly -notcontains $name
            $payload = [byte[]](Get-TcpPayload $name)
            Invoke-TcpProbe $name $tcpPorts[$name] $payload (Is-ServerFirst $name) $expectResponse
        }

        foreach ($name in $udpNames) {
            $expectResponse = $udpCaptureOnly -notcontains $name
            $payload = [byte[]](Get-UdpPayload $name)
            Invoke-UdpProbe $name $udpPorts[$name] $payload $expectResponse
        }

        Invoke-TcpMalformedBurst @($tcpPorts.Values)
        Invoke-UdpMalformedBurst @($udpPorts.Values)

        $malformedHttp = [Text.Encoding]::ASCII.GetBytes(
            ("GET /" + ("A" * 4096) + " HTTP/1.1`r`nHost: matrix.test`r`n`r`n"))
        Invoke-TcpProbe "http" $tcpPorts["http"] $malformedHttp $false $false
        Invoke-UdpProbe "dns" $udpPorts["dns"] ([byte[]](0xff, 0x00, 0xff, 0x00)) $false

        if ($process.HasExited) {
            throw "NetTrap exited during Windows protocol matrix round $round (code $($process.ExitCode))"
        }
        Assert-ResourceBounds $workingSetBaseline $handleBaseline
        $round++
    }
    $roundsCompleted = $round - 1

    if ($process.HasExited) {
        throw "NetTrap exited during protocol matrix smoke (code $($process.ExitCode))"
    }
    if (-not (Test-Path -LiteralPath $eventLogPath -PathType Leaf)) {
        throw "event log is missing: $eventLogPath"
    }
    $seenEventListeners = [System.Collections.Generic.HashSet[string]]::new()
    $lineNumber = 0
    foreach ($line in Get-Content -LiteralPath $eventLogPath) {
        $lineNumber++
        try {
            $event = $line | ConvertFrom-Json -ErrorAction Stop
        } catch {
            throw "invalid event JSON on line $lineNumber`: $($_.Exception.Message)"
        }
        if ($event.listener -is [string]) {
            [void]$seenEventListeners.Add($event.listener)
        }
    }
    $missingEventListeners = @($expectedEventListeners | Where-Object { -not $seenEventListeners.Contains($_) })
    if ($missingEventListeners.Count -gt 0) {
        throw "event log is missing listeners: $($missingEventListeners -join ', ')"
    }
    if ($env:NETTRAP_MATRIX_REPORT) {
        @(
            "schema=3"
            "tcp_handlers=$($tcpNames.Count)"
            "udp_handlers=$($udpNames.Count)"
            "tcp_responses=$tcpResponses"
            "udp_responses=$udpResponses"
            "tcp_observed_responses=$($tcpObservedResponses -join ',')"
            "udp_observed_responses=$($udpObservedResponses -join ',')"
            "tcp_malformed_probes=$($tcpNames.Count * $roundsCompleted)"
            "udp_malformed_probes=$($udpNames.Count * $roundsCompleted)"
            "tcp_names=$($tcpNames -join ',')"
            "udp_names=$($udpNames -join ',')"
            "tcp_capture_only=$($tcpCaptureOnly -join ',')"
            "udp_capture_only=$($udpCaptureOnly -join ',')"
            "event_listeners=$($expectedEventListeners -join ',')"
        ) | Set-Content -LiteralPath $env:NETTRAP_MATRIX_REPORT -Encoding utf8
    }
    Write-Host "PASS: Windows protocol matrix parity smoke ($($tcpNames.Count) TCP, $($udpNames.Count) UDP handlers; $tcpResponses TCP, $udpResponses UDP responses; $roundsCompleted round(s))"
} catch {
    $stderr = if (Test-Path $stderrPath) { Get-Content $stderrPath -Raw } else { "" }
    throw "$($_.Exception.Message)`n$stderr"
} finally {
    Stop-NetTrap
}
