param(
    [Parameter(Mandatory = $true)]
    [string[]] $BinaryPath
)

$ErrorActionPreference = "Stop"
if (-not $env:NETTRAP_WINDOWS_PFX_BASE64) {
    throw "NETTRAP_WINDOWS_PFX_BASE64 is required for native Windows signing"
}
if (-not $env:NETTRAP_WINDOWS_PFX_PASSWORD) {
    throw "NETTRAP_WINDOWS_PFX_PASSWORD is required for native Windows signing"
}

$signtoolCommand = Get-Command signtool.exe -ErrorAction SilentlyContinue
if ($null -ne $signtoolCommand) {
    $signtool = $signtoolCommand.Source
} else {
    $kitsRoot = Join-Path ${env:ProgramFiles(x86)} "Windows Kits\10\bin"
    $signtoolPath = Get-ChildItem -Path $kitsRoot -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending |
        Select-Object -First 1
    if ($null -eq $signtoolPath) {
        throw "signtool.exe was not found"
    }
    $signtool = $signtoolPath.FullName
}

$pfxPath = Join-Path ([IO.Path]::GetTempPath()) ("nettrap-signing-" + [guid]::NewGuid() + ".pfx")
try {
    [IO.File]::WriteAllBytes($pfxPath, [Convert]::FromBase64String($env:NETTRAP_WINDOWS_PFX_BASE64))
    $timestampUrl = if ($env:NETTRAP_WINDOWS_TIMESTAMP_URL) {
        $env:NETTRAP_WINDOWS_TIMESTAMP_URL
    } else {
        "https://timestamp.digicert.com"
    }
    foreach ($path in $BinaryPath) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Windows signing input is missing: $path"
        }
        & $signtool sign /fd SHA256 /td SHA256 /tr $timestampUrl /f $pfxPath `
            /p $env:NETTRAP_WINDOWS_PFX_PASSWORD /a $path
        if ($LASTEXITCODE -ne 0) {
            throw "signtool failed for $path (exit code $LASTEXITCODE)"
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.Status -ne "Valid") {
            throw "Authenticode verification failed for ${path}: $($signature.Status)"
        }
    }
} finally {
    Remove-Item -LiteralPath $pfxPath -Force -ErrorAction SilentlyContinue
}
