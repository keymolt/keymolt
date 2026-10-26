# Installs the keymolt release this skill was written for into %LOCALAPPDATA%\keymolt, after checking its SHA-256.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # the progress bar makes Invoke-WebRequest very slow in Windows PowerShell
$version = 'v0.1.3' # the release workflow checks this matches the tag

$arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'arm64' } else { 'amd64' }
$file = "keymolt_windows_$arch.exe"
$url = "https://github.com/keymolt/keymolt/releases/download/$version"
$dir = Join-Path $env:LOCALAPPDATA 'keymolt'

$tmp = Join-Path ([IO.Path]::GetTempPath()) ([IO.Path]::GetRandomFileName())
New-Item -ItemType Directory $tmp | Out-Null
try {
    Invoke-WebRequest -UseBasicParsing "$url/$file" -OutFile "$tmp\$file"
    Invoke-WebRequest -UseBasicParsing "$url/checksums.txt" -OutFile "$tmp\checksums.txt"
    $want = Get-Content "$tmp\checksums.txt" | ForEach-Object { $f = -split $_; if ($f[1] -eq $file) { $f[0] } }
    $got = (Get-FileHash "$tmp\$file" -Algorithm SHA256).Hash
    if (-not $want -or $got -ne $want) { throw "checksum mismatch for ${file}: not installed" }
    New-Item -ItemType Directory -Force $dir | Out-Null
    Move-Item -Force "$tmp\$file" "$dir\keymolt.exe"
} finally {
    Remove-Item -Recurse -Force $tmp
}
"installed keymolt $version to $dir\keymolt.exe"

# through the registry, so entries such as %USERPROFILE%\bin stay unexpanded
$userPath = (Get-Item HKCU:\Environment).GetValue('Path', '', 'DoNotExpandEnvironmentNames')
if (($userPath -split ';') -notcontains $dir) {
    New-ItemProperty HKCU:\Environment Path -PropertyType ExpandString -Value (($userPath.TrimEnd(';') + ";$dir").TrimStart(';')) -Force | Out-Null
    # setting any user variable tells Windows to reload them, so new terminals see the new PATH
    [Environment]::SetEnvironmentVariable('KEYMOLT_INSTALL', '1', 'User')
    [Environment]::SetEnvironmentVariable('KEYMOLT_INSTALL', $null, 'User')
    "added $dir to your PATH: open a new terminal"
}
$other = Get-Command keymolt -ErrorAction SilentlyContinue
if ($other -and $other.Source -ne "$dir\keymolt.exe") { "note: $($other.Source) comes first on your PATH" }
