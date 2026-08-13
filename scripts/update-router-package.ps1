param(
  [string]$HostAlias = $(if ($env:ROUTER_SSH) { $env:ROUTER_SSH } else { throw "не задан ROUTER_SSH (ssh-алиас или user@адрес) — задай env или передай -HostAlias" }),
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

# mt-2jb: падение демона после деплоя воспроизводится редко, а причина нигде
# не сохранялась - демон запускается с выводом в /dev/null. Включаем файловый
# лог (флаг-файл, см. run_daemon в init.d) ТОЛЬКО на время деплоя: постоянная
# запись жгла бы флеш (zerolog пишет строку на каждый DNS-запрос). Если демон
# переживёт проверку - лог и флаг удаляются; если умрёт - остаются для разбора.
$debugFlag = "/opt/var/lib/magitrickle/debug-log"
$debugLog = "/opt/var/log/magitrickle.log"
ssh $HostAlias "touch $debugFlag; rm -f $debugLog" | Out-Null

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
  Write-Host "--- tail of $debugLog (kept on the router for analysis) ---" -ForegroundColor Yellow
  ssh $HostAlias "tail -n 40 $debugLog 2>/dev/null"
  exit 1
}

# Демон выжил - диагностический лог больше не нужен, флеш не жжём.
ssh $HostAlias "rm -f $debugFlag $debugLog" | Out-Null

Write-Host "Deploy confirmed: magitrickled alive (pid=$lastPid) ${verifySeconds}s after install." -ForegroundColor Green
