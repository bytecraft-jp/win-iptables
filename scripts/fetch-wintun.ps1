# Wintun (https://www.wintun.net/) の署名済み DLL を取得し、ビルド出力先に配置する
param([string]$Arch = "amd64")
$ErrorActionPreference = "Stop"
$ver = "0.14.1"
$sha256 = "07C256185D6EE3652E09FA55C0B673E2624B565E02C4B9091C79CA7D2F24EF51"
$root = Split-Path -Parent $PSScriptRoot
$zip = Join-Path $env:TEMP "wintun-$ver.zip"

Invoke-WebRequest "https://www.wintun.net/builds/wintun-$ver.zip" -OutFile $zip
$actual = (Get-FileHash $zip -Algorithm SHA256).Hash
if ($actual -ne $sha256) { throw "SHA256 不一致: $actual" }

$tmp = Join-Path $env:TEMP "wintun-$ver"
Expand-Archive $zip -DestinationPath $tmp -Force
$dll = Join-Path $tmp "wintun\bin\$Arch\wintun.dll"
foreach ($d in @("vendor", "target\debug", "target\release")) {
    $dest = Join-Path $root $d
    New-Item -ItemType Directory -Force $dest | Out-Null
    Copy-Item $dll $dest -Force
}
Write-Host "wintun.dll ($Arch) を vendor/ と target/{debug,release}/ に配置しました"
