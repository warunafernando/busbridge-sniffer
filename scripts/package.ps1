# Build a release and lay it out as something shippable.
#
# What goes in: the two executables, the extensions they discover beside them,
# the golden corpus (so an installed copy can be checked against the same data
# the tests use), and a manifest saying exactly what this build was made from.
#
# The manifest is the update strategy's foundation: a copy that cannot say what
# version it is cannot be told whether it needs updating.
param(
    [string]$Out = "dist",
    [switch]$SkipBuild,
    [switch]$NoZip
)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# The version comes from the workspace manifest rather than being typed here,
# so a package can never claim a version the code does not have.
$version = (Select-String -Path "Cargo.toml" -Pattern '^version\s*=\s*"(.+)"' |
            Select-Object -First 1).Matches[0].Groups[1].Value
if (-not $version) { throw "no version in Cargo.toml" }

Write-Output "packaging sniffer $version"

if (-not $SkipBuild) {
    # Release: the debug build draws a large capture perceptibly slower, and
    # what ships should be what was measured.
    cargo build --release --workspace
    if ($LASTEXITCODE -ne 0) { throw "the release build failed" }

    # A package that has not passed its own tests is not a package.
    cargo test --release --workspace
    if ($LASTEXITCODE -ne 0) { throw "the tests failed; not packaging" }
}

$stage = Join-Path $Out "sniffer-$version"
if (Test-Path $stage) { Remove-Item -Recurse -Force $stage }
New-Item -ItemType Directory -Force $stage | Out-Null

foreach ($exe in @("sniffer.exe", "sniffer-ui.exe")) {
    $from = Join-Path "target\release" $exe
    if (-not (Test-Path $from)) { throw "$from is missing" }
    Copy-Item $from $stage
}

# Beside the executables, which is the first place the host looks for them.
Copy-Item -Recurse "extensions" (Join-Path $stage "extensions")
# Python bytecode caches are build output, not part of an extension.
Get-ChildItem -Path (Join-Path $stage "extensions") -Recurse -Directory `
    -Filter "__pycache__" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force

New-Item -ItemType Directory -Force (Join-Path $stage "tests") | Out-Null
Copy-Item -Recurse "tests\golden" (Join-Path $stage "tests\golden")
Copy-Item "README.md" $stage

# What this build is, so an installed copy can answer that question.
$commit = "unknown"
try {
    $commit = (git rev-parse --short HEAD 2>$null)
    if ($LASTEXITCODE -ne 0) { $commit = "not a git checkout" }
} catch { $commit = "not a git checkout" }

$rustc = (rustc --version)
$manifest = [ordered]@{
    product     = "sniffer"
    version     = $version
    built_utc   = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    built_by    = "$env:USERNAME on $env:COMPUTERNAME"
    commit      = $commit
    rustc       = $rustc
    host        = "windows-x86_64"
    executables = @("sniffer.exe", "sniffer-ui.exe")
    notes       = @(
        "Capturing from hardware needs the BUSBRIDGE board's own USB cable; the ST-LINK cable carries debug only.",
        "The extensions run Python, which has to be on PATH. Everything else here needs nothing installed.",
        "Nothing checks for updates by itself. `sniffer version` prints what this copy is; compare it with the release you have."
    )
}
$manifest | ConvertTo-Json -Depth 4 |
    Out-File -FilePath (Join-Path $stage "build.json") -Encoding utf8

# A checksum per file, so a copy can be verified after being moved about.
$sums = Get-ChildItem -Path $stage -Recurse -File | ForEach-Object {
    $relative = $_.FullName.Substring($stage.Length + 1)
    "{0}  {1}" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash.ToLower(), $relative
}
$sums | Out-File -FilePath (Join-Path $stage "sha256.txt") -Encoding utf8

if (-not $NoZip) {
    $zip = Join-Path $Out "sniffer-$version-windows-x86_64.zip"
    if (Test-Path $zip) { Remove-Item -Force $zip }
    Compress-Archive -Path (Join-Path $stage "*") -DestinationPath $zip
    Write-Output "wrote $zip"
}

$size = (Get-ChildItem -Recurse -File $stage | Measure-Object -Property Length -Sum).Sum
Write-Output "staged $stage ($([math]::Round($size / 1MB, 1)) MB)"
Write-Output "manifest:"
Get-Content (Join-Path $stage "build.json")
