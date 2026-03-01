param(
  [string]$HostAlias = "<ROUTER_SSH>",
  [string]$RemoteTmpDir = "/opt/root/tmp",
  [string]$PackagePath = ""
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

if ([string]::IsNullOrWhiteSpace($PackagePath)) {
  $latest = Get-ChildItem (Join-Path $repoRoot ".build") -Filter "magitrickle_*_entware_aarch64-3.10_kn.ipk" |
    Sort-Object LastWriteTime -Descending |
    Select-Object -First 1

  if (-not $latest) {
    throw "No aarch64-3.10_kn package found in .build"
  }

  $PackagePath = $latest.FullName
} else {
  $PackagePath = (Resolve-Path $PackagePath).Path
}

$packageName = [System.IO.Path]::GetFileName($PackagePath)
$remotePackagePath = "$RemoteTmpDir/$packageName"

Write-Host "Using package: $PackagePath"
Write-Host "Uploading to $HostAlias`:$remotePackagePath"

ssh $HostAlias "mkdir -p $RemoteTmpDir"
scp -O $PackagePath "${HostAlias}:$RemoteTmpDir/"

Write-Host "Installing package on $HostAlias"
ssh $HostAlias "opkg install --force-reinstall $remotePackagePath && /opt/etc/init.d/S99magitrickle status"
