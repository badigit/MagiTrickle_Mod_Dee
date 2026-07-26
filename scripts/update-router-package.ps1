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
ssh $HostAlias "opkg install --force-reinstall $remotePackagePath"

# mt-cub: opkg-постинст перезапускает демон синхронно (stop; start), но при
# медленном teardown (много ipset-групп под нагрузкой) старый процесс мог
# оказаться ещё формально живым в момент проверки сразу после install -
# такая проверка печатала "alive", хотя через ~45с демон умирал насовсем.
# Поэтому здесь проверяем PID сразу (для информации) и повторно - через
# $VerifySeconds после установки, требуя реального живого процесса на момент
# последней проверки, а не мгновенного снимка состояния.
function Get-RemoteDaemonPid {
  [string]$out = ssh $HostAlias "pidof magitrickled 2>/dev/null"
  $out.Trim()
}

$immediatePid = Get-RemoteDaemonPid
if ([string]::IsNullOrWhiteSpace($immediatePid)) {
  Write-Host "Immediately after install: daemon NOT running" -ForegroundColor Red
} else {
  Write-Host "Immediately after install: pid=$immediatePid"
}

$verifySeconds = 45
$pollInterval = 5
Write-Host "Verifying the daemon survives past the restart window (${verifySeconds}s)..."

$elapsed = 0
$lastPid = $null
while ($elapsed -lt $verifySeconds) {
  Start-Sleep -Seconds $pollInterval
  $elapsed += $pollInterval
  $lastPid = Get-RemoteDaemonPid
  if ([string]::IsNullOrWhiteSpace($lastPid)) {
    Write-Host "[+${elapsed}s] daemon is DOWN" -ForegroundColor Red
  } else {
    Write-Host "[+${elapsed}s] daemon alive, pid=$lastPid"
  }
}

if ([string]::IsNullOrWhiteSpace($lastPid)) {
  Write-Host "DEPLOY FAILED: magitrickled is not running ${verifySeconds}s after install." -ForegroundColor Red
  exit 1
}

Write-Host "Deploy confirmed: magitrickled alive (pid=$lastPid) ${verifySeconds}s after install." -ForegroundColor Green
