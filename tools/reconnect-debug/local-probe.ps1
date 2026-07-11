<#
.SYNOPSIS
  local-probe.ps1 — детерминированно воспроизводит и измеряет сигнатуру
  "первый коннект падает, второй проходит" с ПК (трафик идёт через роутер→MT→mihomo).

.DESCRIPTION
  Для каждого таргета в каждой итерации:
    1. Clear-DnsClientCache (чистим локальный кэш, чтобы резолв шёл на роутер/MT).
    2. На КАЖДОЙ попытке заново резолвим (Resolve-DnsName) — фиксируем IP + латентность.
       => Если IP отличается между попыткой 1 и 2 — это DNS-layer (H1: stale connPool/cache).
    3. Сразу TCP-connect к resolved IP:Port с коротким таймаутом — фиксируем успех/латентность.
       => Если IP тот же, но 1я попытка фейл / 2я ок — это routing/tunnel (H2/H3/H4),
          уточняется по conntrack mark на роутере (router-capture.sh).
  Пишет TSV для оффлайн-корреляции (correlate.py) + цветной лог в консоль.

  Запускать ПАРАЛЛЕЛЬНО с router-capture.sh. Перед стартом зафиксируй UTC обоих часов
  (скрипт сам тянет время роутера через -RouterHost для вычисления offset).

.EXAMPLE
  .\local-probe.ps1 -For 120 -RouterHost root@<ROUTER_IP>
  .\local-probe.ps1 -Targets api.anthropic.com,claude.ai,telegram.org -For 0
#>
[CmdletBinding()]
param(
  [string[]]$Targets = @('api.anthropic.com','claude.ai','telegram.org','yandex.ru'),
  [int]$Port = 443,
  [int]$For = 120,                 # секунд; 0 = до Ctrl+C
  [double]$IntervalSec = 2.0,      # пауза между итерациями
  [int]$ConnectTimeoutMs = 3000,
  [int]$MaxAttempts = 3,           # попыток коннекта на таргет (ловим "на N-й раз ок")
  [string]$OutDir = '.',
  [string]$RouterHost = '',        # напр. root@<ROUTER_IP> — для вычисления clock offset
  [int]$RouterSshPort = 222
)

$ErrorActionPreference = 'Continue'
$ts  = Get-Date -Format 'yyyyMMdd-HHmmss'
$tsv = Join-Path $OutDir "probe-$ts.tsv"

# --- clock offset ПК <-> роутер (для корреляции с conntrack.log) ---
$offsetNote = 'router_offset: <not measured>'
if ($RouterHost) {
  try {
    $ssh = 'C:\Windows\System32\OpenSSH\ssh.exe'
    if (-not (Test-Path $ssh)) { $ssh = 'ssh' }
    $pcBefore = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    $routerEpoch = (& $ssh -p $RouterSshPort $RouterHost 'date +%s') 2>$null
    $pcAfter = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
    if ($routerEpoch) {
      $pcMid = ($pcBefore + $pcAfter) / 2000.0
      $offset = [double]$routerEpoch - $pcMid
      $offsetNote = "router_offset_s: $([math]::Round($offset,2))  (router_epoch=$routerEpoch pc_mid=$([math]::Round($pcMid,2)))"
    }
  } catch { $offsetNote = "router_offset: <ssh failed: $_>" }
}

# заголовок TSV
$header = @(
  'iso_utc','epoch_ms','target','attempt','resolved_ips','resolve_ms',
  'connect_ip','connect_result','connect_ms','iteration_verdict'
) -join "`t"
Set-Content -Path $tsv -Value "# $offsetNote"
Add-Content -Path $tsv -Value "# targets: $($Targets -join ',')  port: $Port"
Add-Content -Path $tsv -Value $header

Write-Host "[probe] out=$tsv  for=${For}s  targets=$($Targets -join ',')" -ForegroundColor Cyan
Write-Host "[probe] $offsetNote" -ForegroundColor DarkGray

function Test-TcpConnect {
  param([string]$Ip,[int]$Port,[int]$TimeoutMs)
  $sw = [System.Diagnostics.Stopwatch]::StartNew()
  $client = New-Object System.Net.Sockets.TcpClient
  try {
    $iar = $client.BeginConnect($Ip, $Port, $null, $null)
    $ok  = $iar.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
    if ($ok -and $client.Connected) {
      $client.EndConnect($iar)
      $sw.Stop(); return @{ ok=$true; ms=$sw.ElapsedMilliseconds; err='' }
    }
    $sw.Stop(); return @{ ok=$false; ms=$sw.ElapsedMilliseconds; err='timeout/refused' }
  } catch {
    $sw.Stop(); return @{ ok=$false; ms=$sw.ElapsedMilliseconds; err=$_.Exception.Message }
  } finally { $client.Close() }
}

$deadline = if ($For -gt 0) { (Get-Date).AddSeconds($For) } else { [DateTime]::MaxValue }
$iter = 0

try {
  while ((Get-Date) -lt $deadline) {
    $iter++
    foreach ($t in $Targets) {
      $winAttempt = 0
      for ($a = 1; $a -le $MaxAttempts; $a++) {
        try { Clear-DnsClientCache -ErrorAction SilentlyContinue } catch {}
        $now = [DateTimeOffset]::UtcNow
        $rsw = [System.Diagnostics.Stopwatch]::StartNew()
        $ips = @()
        try {
          # @(...) ОБЯЗАТЕЛЕН: при одном A-записи Select -Expand даёт скаляр-строку,
          # и $ips[0] вернул бы первый СИМВОЛ ('1' из "160..."), а не IP. Форсим массив.
          $ips = @(Resolve-DnsName -Name $t -Type A -DnsOnly -ErrorAction Stop |
                  Where-Object { $_.IPAddress } | Select-Object -Expand IPAddress)
        } catch {}
        $rsw.Stop()
        $ip = if ($ips.Count -gt 0) { $ips[0] } else { '' }

        $c = if ($ip) { Test-TcpConnect -Ip $ip -Port $Port -TimeoutMs $ConnectTimeoutMs } `
                  else { @{ ok=$false; ms=0; err='no-dns' } }

        $verdict = ''
        if ($c.ok) {
          $winAttempt = $a
          $verdict = if ($a -eq 1) { 'OK-1st' } else { "OK-${a}th(RECONNECT)" }
        }

        $row = @(
          $now.ToString('o'),
          $now.ToUnixTimeMilliseconds(),
          $t, $a,
          ($ips -join ','),
          $rsw.ElapsedMilliseconds,
          $ip,
          $(if ($c.ok) {'success'} else {"fail:$($c.err)"}),
          $c.ms,
          $verdict
        ) -join "`t"
        Add-Content -Path $tsv -Value $row

        if ($c.ok) { break }
      }

      # консольный итог по таргету
      if ($winAttempt -eq 1) {
        Write-Host ("  {0,-22} OK (1st)  " -f $t) -ForegroundColor Green
      } elseif ($winAttempt -gt 1) {
        Write-Host ("  {0,-22} RECONNECT — ok на попытке {1}" -f $t,$winAttempt) -ForegroundColor Yellow
      } else {
        Write-Host ("  {0,-22} FAIL (все {1} попытки)" -f $t,$MaxAttempts) -ForegroundColor Red
      }
    }
    Write-Host ("[probe] iter $iter @ {0:HH:mm:ss}" -f (Get-Date)) -ForegroundColor DarkGray
    Start-Sleep -Seconds $IntervalSec
  }
}
finally {
  Write-Host "[probe] готово: $tsv" -ForegroundColor Cyan
}
