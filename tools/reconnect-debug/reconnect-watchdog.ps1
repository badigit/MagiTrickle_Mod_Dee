<#
.SYNOPSIS
  reconnect-watchdog.ps1 — непрерывная ловушка перемежающегося реконнекта (always-on).
  Крутится на ПК сутками; при ПЕРВОМ фейле проксируемого таргета авто-снимает живую улику
  с роутера (conntrack к этому IP: REDIRECT→mihomo или direct? + mihomo /connections) и пишет
  bookmark. Решающее различение MT-vs-mihomo фиксируется в МОМЕНТ события, без няньки.

.DESCRIPTION
  - Гарантирует, что на роутере поднят reconnect-watchdog.sh (rolling conntrack + mihomo-poll).
  - Каждые IntervalSec зондирует проксируемые таргеты (fresh-resolve→TCP-connect, 2 попытки).
  - Состояние "spell": фейл attempt-1 проксируемого таргета → начало; снимок+bookmark+beep.
    Полный round без фейлов → конец spell (фиксируется длительность).
  - На роутере улика уже копится (ct-*.log), снимок добавляет точечное состояние в момент T.

  Файлы (OutDir):
    bookmarks.tsv         — utc, router_epoch, target, ip, a1, a2, event
    event-<ts>-<tgt>.txt  — снимок роутера в момент фейла (conntrack/mihomo)
    heartbeat.log         — периодические "жив, всё ок" + старт/стоп spell

.EXAMPLE
  .\reconnect-watchdog.ps1                       # дефолты, до Ctrl+C
  .\reconnect-watchdog.ps1 -IntervalSec 3 -Proxied api.anthropic.com,telegram.org
#>
[CmdletBinding()]
param(
  [string[]]$Proxied = @('api.anthropic.com','claude.ai','telegram.org'),
  [string]$Control = 'yandex.ru',
  [int]$Port = 443,
  [double]$IntervalSec = 3.0,
  [int]$ConnectTimeoutMs = 4000,
  [string]$RouterHost = '',        # ssh-цель роутера (root@<IP> или алиас) — задай через start-watchdog.cmd
  [int]$RouterSshPort = 222,
  [string]$RouterScriptLocal = "$PSScriptRoot\reconnect-watchdog.sh",
  [string]$RouterSrc = '',         # IP клиента для -s фильтра на роутере (пусто = весь трафик)
  [string]$OutDir = "$PSScriptRoot\..\..\.tmp\reconnect-watchdog",
  [int]$ReSnapshotSec = 60,  # повторный снимок, если spell длится дольше
  [int]$RunMinutes = 0       # 0 = бесконечно; >0 = самостоп через N минут (для оконного слежения)
)
$ErrorActionPreference = 'Continue'
if (-not $RouterHost) { Write-Error 'Задай -RouterHost (ssh-цель роутера, напр. root@<IP>) — обычно через свой start-watchdog.cmd (см. start-watchdog.cmd.example)'; exit 1 }
$ssh = 'C:\Windows\System32\OpenSSH\ssh.exe'; if (-not (Test-Path $ssh)) { $ssh = 'ssh' }
$scp = 'C:\Windows\System32\OpenSSH\scp.exe'; if (-not (Test-Path $scp)) { $scp = 'scp' }
# BatchMode=yes — НИКОГДА не висеть на password/host-key промпте (detached-процесс без TTY).
# pubkey через ssh-agent работает; при недоступности agent — быстрый фейл, не зависание.
$sshOpts = @('-o','BatchMode=yes','-o','ConnectTimeout=10')
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$bm = Join-Path $OutDir 'bookmarks.tsv'
$hb = Join-Path $OutDir 'heartbeat.log'
if (-not (Test-Path $bm)) { Set-Content $bm "utc`trouter_epoch`ttarget`tip`ta1`ta2`tevent" }

function Log-HB($msg) {
  $line = "{0}  {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $msg
  Add-Content $hb $line; Write-Host $line -ForegroundColor DarkGray
}

# --- 1. роутерный демон: ВСЕГДА заливаем (идемпотентно), стартуем если не запущен ---
# детект через ps|grep '[r]econnect...' (bracket — не матчит сам checker; pgrep -f этим страдал).
& $scp @sshOpts -O -P $RouterSshPort $RouterScriptLocal "${RouterHost}:/opt/bin/reconnect-watchdog.sh" 2>&1 | Out-Null
$dcheck = "ps w | grep '[r]econnect-watchdog.sh' | grep -v grep | head -1"
$running = (& $ssh @sshOpts -p $RouterSshPort $RouterHost $dcheck) 2>$null
if (-not $running) {
  Log-HB "router daemon не запущен — стартую"
  & $ssh @sshOpts -p $RouterSshPort $RouterHost "chmod +x /opt/bin/reconnect-watchdog.sh; (/opt/bin/reconnect-watchdog.sh -s $RouterSrc </dev/null >/tmp/rw.log 2>&1 &)" 2>&1 | Out-Null
  Start-Sleep -Seconds 2
  $running = (& $ssh @sshOpts -p $RouterSshPort $RouterHost $dcheck) 2>$null
}
Log-HB "router daemon: $(if ($running) { ($running -replace '\s+',' ').Trim() } else { 'НЕ ПОДНЯЛСЯ' })"

# --- clock offset ---
$offset = 0.0
try {
  $b = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $re = (& $ssh @sshOpts -p $RouterSshPort $RouterHost 'date +%s') 2>$null
  $a = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  if ($re) { $offset = [double]$re - (($b+$a)/2000.0) }
} catch {}
Log-HB ("router_offset_s={0:N2}  proxied={1}  interval={2}s" -f $offset, ($Proxied -join ','), $IntervalSec)

function Resolve-First($name) {
  try { return @(Resolve-DnsName -Name $name -Type A -DnsOnly -ErrorAction Stop |
                 Where-Object { $_.IPAddress } | Select-Object -Expand IPAddress) } catch { return @() }
}
function Test-Tcp($ip,$port,$toMs) {
  $c = New-Object Net.Sockets.TcpClient
  try {
    $iar = $c.BeginConnect($ip,$port,$null,$null)
    if ($iar.AsyncWaitHandle.WaitOne($toMs,$false) -and $c.Connected) { $c.EndConnect($iar); return $true }
    return $false
  } catch { return $false } finally { $c.Close() }
}
function Snapshot($target,$ip,$tag) {
  $ts = Get-Date -Format 'yyyyMMdd-HHmmss'
  $f = Join-Path $OutDir ("event-{0}-{1}-{2}.txt" -f $ts,($target -replace '\.','_'),$tag)
  # без вложенных кавычек/jq-фильтров (хрупко PS->ssh): интерполируем только $ip/$RouterSrc.
  $cmd = "echo '=== router_epoch ==='; date +%s; " +
         "echo '=== conntrack -> $ip (reply sport=5001=proxied, 443=direct) ==='; conntrack -L -d $ip 2>/dev/null; " +
         "echo '=== SYN_SENT :443 from $RouterSrc ==='; conntrack -L -s $RouterSrc 2>/dev/null | grep dport=443 | grep SYN_SENT | head -20; " +
         "echo '=== mihomo conns mentioning $ip ==='; curl -s --max-time 3 http://127.0.0.1:9090/connections 2>/dev/null | tr ',' '\n' | grep -i $ip | head -20; " +
         "echo '=== inner-stats ==='; curl -s --max-time 3 http://127.0.0.1:9090/connections/inner-stats 2>/dev/null; " +
         "echo '=== current rolling ct file ==='; ls -1t /opt/var/log/reconnect-watchdog/ct-*.log 2>/dev/null | head -1; " +
         "echo '=== recent ct к $ip (ловит мёртвый attempt-1 из rolling-лога до ротации) ==='; grep '$ip' `$(ls -1t /opt/var/log/reconnect-watchdog/ct-*.log 2>/dev/null | head -1) 2>/dev/null | tail -60"
  (& $ssh @sshOpts -p $RouterSshPort $RouterHost $cmd) 2>&1 | Set-Content $f
  return $f
}

Write-Host "[watchdog] жив. OutDir=$OutDir  Ctrl+C для остановки." -ForegroundColor Cyan
$inSpell = $false; $spellStart = $null; $lastSnap = $null; $lastHB = Get-Date; $round = 0
$startAt = Get-Date
try {
  while ($true) {
    if ($RunMinutes -gt 0 -and ((Get-Date) - $startAt).TotalMinutes -ge $RunMinutes) { Log-HB "RunMinutes=$RunMinutes достигнут — штатный стоп"; break }
    $round++
    $anyFail = $false; $failInfo = $null
    foreach ($t in $Proxied) {
      # @(...) ОБЯЗАТЕЛЕН на месте вызова: PowerShell разворачивает одноэлементный массив
      # при возврате из функции → без @() $ips стал бы скаляр-строкой, а $ips[0]='1' (первый символ).
      $ips = @(Resolve-First $t)
      $ip = if ($ips.Count -gt 0) { $ips[0] } else { '' }
      $a1 = if ($ip) { Test-Tcp $ip $Port $ConnectTimeoutMs } else { $false }
      $a2 = $true
      if (-not $a1) {
        Start-Sleep -Milliseconds 150
        $a2 = if ($ip) { Test-Tcp $ip $Port $ConnectTimeoutMs } else { $false }
        $anyFail = $true
        if (-not $failInfo) { $failInfo = @{ t=$t; ip=$ip; a1=$a1; a2=$a2 } }
      }
    }

    $nowUtc = (Get-Date).ToUniversalTime().ToString('o')
    $rEpoch = [int]([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() + $offset)

    if ($anyFail) {
      $fi = $failInfo
      $a1s = if ($fi.a1) {'ok'} else {'FAIL'}; $a2s = if ($fi.a2) {'ok'} else {'FAIL'}
      if (-not $inSpell) {
        $inSpell = $true; $spellStart = Get-Date; $lastSnap = Get-Date
        [console]::beep(900,300)
        Write-Host ("[ALERT] {0} reconnect: {1} ip={2} a1={3} a2={4}" -f $nowUtc,$fi.t,$fi.ip,$a1s,$a2s) -ForegroundColor Red
        $snap = Snapshot $fi.t $fi.ip 'start'
        Add-Content $bm ("{0}`t{1}`t{2}`t{3}`t{4}`t{5}`tSPELL-START snap={6}" -f $nowUtc,$rEpoch,$fi.t,$fi.ip,$a1s,$a2s,(Split-Path $snap -Leaf))
        Log-HB "SPELL-START $($fi.t) ip=$($fi.ip) — снимок: $(Split-Path $snap -Leaf)"
      } else {
        Add-Content $bm ("{0}`t{1}`t{2}`t{3}`t{4}`t{5}`tspell-cont" -f $nowUtc,$rEpoch,$fi.t,$fi.ip,$a1s,$a2s)
        if (((Get-Date) - $lastSnap).TotalSeconds -ge $ReSnapshotSec) {
          $lastSnap = Get-Date; $snap = Snapshot $fi.t $fi.ip 'cont'
          Log-HB "spell продолжается, доп.снимок: $(Split-Path $snap -Leaf)"
        }
      }
    } else {
      if ($inSpell) {
        $dur = [int]((Get-Date) - $spellStart).TotalSeconds
        $inSpell = $false
        Add-Content $bm ("{0}`t{1}`t-`t-`t-`t-`tSPELL-END dur=${dur}s" -f $nowUtc,$rEpoch)
        Log-HB "SPELL-END длительность=${dur}s"
        [console]::beep(500,150)
      }
    }

    if (((Get-Date) - $lastHB).TotalSeconds -ge 300) {
      $lastHB = Get-Date; Log-HB ("ok (round=$round, spell=$inSpell)")
    }
    Start-Sleep -Seconds $IntervalSec
  }
}
finally { Log-HB "watchdog остановлен (round=$round)" }
