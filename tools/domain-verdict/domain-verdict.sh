#!/bin/sh
# domain-verdict.sh — вердикт по одному домену/URL: виноват ли НАШ роутинг
# (MagiTrickle + mihomo) в том, что он не открывается, или ломается снаружи.
#
# Запускается НА РОУТЕРЕ (Keenetic/Entware, BusyBox sh). Строго read-only:
# ничего не меняет ни в конфигах, ни в ipset, ни в маршрутах.
#
# Что делает за один проход:
#   1) DNS: резолв через локальный резолвер роутера и через публичный (1.1.1.1) — сверка.
#   2) MT: POST /api/v1/lookup (rule_hits + ipset_hits) по домену и по всем его IP.
#   3) ipset: прямой перебор всех сетов роутера на каждый IP (правда о ipset, не через API).
#   4) direct: curl мимо прокси — по URL и по каждому IP (443 и 80).
#   5) proxy: тот же URL через mihomo http-прокси — работает ли путь через туннель.
#   6) WAN-съём: tcpdump на WAN-интерфейсе во время direct-попытки — уходит ли SYN,
#      что приходит в ответ (SYN-ACK / RST / тишина) и с каким TTL. Для сравнения
#      снимается TTL живого ответа эталонного хоста (по умолчанию ya.ru).
#   7) conntrack: есть ли записи по IP.
#   8) VERDICT: дерево решений — «наш роутинг» / «не наш» / «DNS» / «сервер лёг».
#
# Использование (на роутере):
#   domain-verdict.sh <домен|URL> [--ref <эталонный-хост>]
#
# Обычно вызывается обёрткой с рабочей машины (см. скилл domain-verdict):
#   bash tools/domain-verdict/verdict.sh <домен|URL>
#
# Зависимости на роутере: curl, tcpdump, ipset, nslookup (busybox). jq не нужен.

PATH=/opt/sbin:/opt/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

TARGET=""
REF_HOST="ya.ru"
MT_API="${MT_API:-http://127.0.0.1:8080}"
WINNER=""; WIN_NAME=""; WIN_WHY=""; WIN_PENDING=no
PROXY="${PROXY:-http://127.0.0.1:7890}"

# цель можно передать аргументом или переменными окружения DV_TARGET / DV_REF
# (env-путь используется обёрткой: busybox sh не всегда принимает `sh -s -- args`)
while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF_HOST="$2"; shift 2 ;;
    -*) echo "неизвестный флаг: $1" >&2; exit 2 ;;
    *) TARGET="$1"; shift ;;
  esac
done
if [ -z "$TARGET" ] && [ -n "${DV_TARGET:-}" ]; then TARGET="$DV_TARGET"; fi
if [ -n "${DV_REF:-}" ]; then REF_HOST="$DV_REF"; fi

if [ -z "$TARGET" ]; then
  echo "использование: domain-verdict.sh <домен|URL> [--ref <хост>]" >&2
  exit 2
fi

# --- разбор цели: URL -> хост + полный URL ------------------------------------
case "$TARGET" in
  http://*|https://*)
    URL="$TARGET"
    HOST=`echo "$TARGET" | sed -e 's#^[a-z]*://##' -e 's#[/?].*$##' -e 's#:[0-9]*$##'`
    ;;
  *)
    HOST="$TARGET"
    URL="https://$TARGET/"
    ;;
esac

echo "# domain-verdict"
echo "target: $TARGET"
echo "host:   $HOST"
echo "url:    $URL"
echo "ref:    $REF_HOST"
echo

# --- 1. DNS -------------------------------------------------------------------
echo "## dns"
resolve() {
  # busybox-nslookup печатает и "Address 1: 1.2.3.4", и "Address 1: 1.2.3.4 name" —
  # имя в хвосте опционально (иначе теряются все хосты с PTR-подобным выводом);
  # IPv6-строки отбрасываем: дальше вся диагностика про IPv4-путь
  nslookup "$1" "$2" 2>/dev/null \
    | sed -n '/^Name:/,$p' \
    | sed -n 's/^Address[ 0-9]*:[[:space:]]*\([0-9][0-9.]*\).*$/\1/p' \
    | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'
}
IPS_LOCAL=`resolve "$HOST" 127.0.0.1`
IPS_PUB=`resolve "$HOST" 1.1.1.1`
echo "local(127.0.0.1): `echo $IPS_LOCAL`"
echo "public(1.1.1.1):  `echo $IPS_PUB`"
CNAME=`nslookup "$HOST" 127.0.0.1 2>/dev/null | sed -n 's/^Aliases:[[:space:]]*//p'`
if [ -n "$CNAME" ]; then echo "aliases: $CNAME"; fi
IPS="$IPS_LOCAL"
if [ -z "$IPS" ]; then IPS="$IPS_PUB"; fi
DNS_MISMATCH=no
if [ -n "$IPS_LOCAL" ] && [ -n "$IPS_PUB" ] && [ "$IPS_LOCAL" != "$IPS_PUB" ]; then
  DNS_MISMATCH=yes
  echo "note: локальный и публичный резолверы дали РАЗНЫЕ адреса"
fi
echo

# --- 2. MagiTrickle /lookup ---------------------------------------------------
echo "## magitrickle rules (/api/v1/lookup)"
Q=`printf '"%s"' "$HOST"`
for ip in $IPS; do Q="$Q,`printf '"%s"' "$ip"`"; done
LOOKUP=`curl -s -m 10 -X POST "$MT_API/api/v1/lookup" -H 'Content-Type: application/json' -d "{\"queries\":[$Q],\"check_ipset\":true}" 2>/dev/null`
if [ -z "$LOOKUP" ]; then
  echo "MT API недоступен ($MT_API) — вердикт по правилам строится только по ipset"
  MT_HIT=unknown
else
  echo "$LOOKUP" | sed 's/},{/},\n{/g'
  if echo "$LOOKUP" | grep -q '"rule_hits":\[[^]]' || echo "$LOOKUP" | grep -q '"ipset_hits":\[[^]]'; then
    MT_HIT=yes
  else
    MT_HIT=no
  fi
  # winner появился в mt-ztg: демон сам называет победителя арбитража — теми же
  # правилами, которыми ходит трафик. Берём вердикт ПЕРВОГО запроса (это сам
  # домен; IP идут следом). На прошивке без mt-ztg поля нет, и вердикт ниже
  # строится по совпадениям, как раньше.
  # Привязка к своему query обязательна: в ответе несколько результатов (домен
  # и его IP), а жадная `.*` без якоря утащила бы winner ПОСЛЕДНЕГО из них —
  # для домена показывался бы ipset-first от IP-запроса.
  WINNER=`echo "$LOOKUP" | sed -n 's/.*"query":"'"$HOST"'","winner":{\([^}]*\)}.*/\1/p' | head -n1`
  if [ -n "$WINNER" ]; then
    WIN_NAME=`echo "$WINNER" | sed -n 's/.*"group_name":"\([^"]*\)".*/\1/p'`
    WIN_WHY=`echo "$WINNER" | sed -n 's/.*"why":"\([^"]*\)".*/\1/p'`
    case "$WINNER" in *'"pending":true'*) WIN_PENDING=yes ;; *) WIN_PENDING=no ;; esac
    echo "winner: группа \"$WIN_NAME\" (why=$WIN_WHY, pending=$WIN_PENDING)"
    MT_HIT=yes
  fi
fi
echo "rule/ipset hits by API: $MT_HIT"
echo

# --- 3. ipset прямым перебором ------------------------------------------------
echo "## ipset (прямой перебор всех сетов)"
IPSET_HIT=no
SETS=`ipset list -n 2>/dev/null`
if [ -z "$SETS" ]; then
  echo "ipset недоступен"
  IPSET_HIT=unknown
else
  # имена сетов MT — mt_<group-id>_*; переводим id в человеческое имя группы
  GROUPS=`curl -s -m 8 "$MT_API/api/v1/groups" 2>/dev/null`
  group_of() {
    gid=`echo "$1" | sed -n 's/^mt_\([0-9a-f]*\)_.*/\1/p'`
    [ -n "$gid" ] || return 0
    echo "$GROUPS" | sed 's/},{/}\
{/g' | grep "\"id\":\"$gid\"" \
      | sed -n 's/.*"name":"\([^"]*\)".*"interface":"\([^"]*\)".*/ -> группа "\1" (interface=\2)/p' | head -n1
  }
  for ip in $IPS; do
    for s in $SETS; do
      case "`ipset test "$s" "$ip" 2>&1`" in
        *" is in "*) echo "HIT: $ip в сете $s`group_of "$s"`"; IPSET_HIT=yes ;;
      esac
    done
  done
  if [ "$IPSET_HIT" = no ]; then
    echo "ни один IP не найден ни в одном из `echo "$SETS" | wc -l` сетов"
  fi
fi
echo

# --- 4. direct ----------------------------------------------------------------
echo "## direct (мимо прокси, с роутера)"
CURL_FMT='code=%{http_code} conn=%{time_connect} tls=%{time_appconnect} total=%{time_total} ip=%{remote_ip}\n'
DIRECT_URL_CODE=`curl -s -o /dev/null -m 15 -w '%{http_code}' "$URL" 2>/dev/null`
printf 'url:  '; curl -s -o /dev/null -m 15 -w "$CURL_FMT" "$URL" 2>&1
for ip in $IPS; do
  printf 'ip %s:443  ' "$ip"; curl -s -o /dev/null -m 8 -k -w "$CURL_FMT" "https://$ip/" 2>&1
  printf 'ip %s:80   ' "$ip"; curl -s -o /dev/null -m 8 -w "$CURL_FMT" "http://$ip/" 2>&1
done
printf 'ref %s: ' "$REF_HOST"
REF_OUT=`curl -s -o /dev/null -m 10 -w "$CURL_FMT" "https://$REF_HOST/" 2>&1`
echo "$REF_OUT"
REF_CODE=`echo "$REF_OUT" | sed -n 's/^code=\([0-9]*\).*/\1/p'`
echo

# --- 5. proxy -----------------------------------------------------------------
echo "## proxy (через mihomo $PROXY)"
printf 'url:  '
PROXY_OUT=`curl -s -o /dev/null -m 25 -x "$PROXY" -w "$CURL_FMT" "$URL" 2>&1`
echo "$PROXY_OUT"
PROXY_CODE=`echo "$PROXY_OUT" | sed -n 's/^code=\([0-9]*\).*/\1/p'`
echo

# --- 6. WAN-съём --------------------------------------------------------------
echo "## wan capture (tcpdump на WAN во время direct-попытки)"
WAN=`awk '$2=="00000000" && $8=="00000000" {print $1; exit}' /proc/net/route 2>/dev/null`
if [ -z "$WAN" ]; then WAN=`awk 'NR==2{print $1}' /proc/net/route 2>/dev/null`; fi
echo "wan iface: ${WAN:-<не определён>}"
FIRST_IP=`echo "$IPS" | head -n1`
CAP=/tmp/domain-verdict-cap.$$
SYN_SEEN=no; RST_SEEN=no; SYNACK_SEEN=no; RST_TTL=""; REF_TTL=""
if [ -n "$WAN" ] && [ -n "$FIRST_IP" ]; then
  REF_IP=`resolve "$REF_HOST" 127.0.0.1 | head -n1`
  # склейка: tcpdump -v печатает IP-заголовок (с ttl) и флаги TCP на разных строках
  pairs_of() { awk '/ttl [0-9]+/{ttl=$0; if ((getline nxt) > 0) print ttl" || "nxt}' "$1" 2>/dev/null; }
  # эталон снимаем отдельным коротким захватом, иначе его пакеты не попадают в лимит -c
  if [ -n "$REF_IP" ]; then
    tcpdump -i "$WAN" -n -v -c 4 -S "host $REF_IP and tcp port 443" >"$CAP.ref" 2>/dev/null &
    TR=$!
    sleep 2
    # --resolve, чтобы curl пошёл именно на тот IP, который мы фильтруем
    # (у эталона обычно несколько A-записей, иначе его пакеты в захват не попадают)
    curl -s -o /dev/null -m 6 --resolve "$REF_HOST:443:$REF_IP" "https://$REF_HOST/" >/dev/null 2>&1
    sleep 2
    kill $TR 2>/dev/null
    REF_TTL=`pairs_of "$CAP.ref" | grep "$REF_IP\..*> .*Flags \[S\." | sed -n 's/.*ttl \([0-9]*\).*/\1/p' | head -n1`
    rm -f "$CAP.ref"
  fi
  tcpdump -i "$WAN" -n -v -c 10 -S "host $FIRST_IP" >"$CAP" 2>/dev/null &
  TP=$!
  sleep 2
  curl -s -o /dev/null -m 6 -k "https://$FIRST_IP/" >/dev/null 2>&1
  sleep 3
  kill $TP 2>/dev/null
  wait 2>/dev/null
  PAIRS=`pairs_of "$CAP"`
  echo "$PAIRS" | grep "$FIRST_IP" | sed -e 's/^.*ttl \([0-9]*\).*|| /ttl=\1 /' -e 's/, cksum [^,]*,/,/' | head -n 6
  echo "$PAIRS" | grep -q "> $FIRST_IP.*Flags \[S\]" && SYN_SEEN=yes
  echo "$PAIRS" | grep -q "$FIRST_IP\..*> .*Flags \[R" && RST_SEEN=yes
  echo "$PAIRS" | grep -q "$FIRST_IP\..*> .*Flags \[S\." && SYNACK_SEEN=yes
  RST_TTL=`echo "$PAIRS" | grep "$FIRST_IP\..*> .*Flags \[R" | sed -n 's/.*ttl \([0-9]*\).*/\1/p' | head -n1`
  rm -f "$CAP"
  echo "syn_out=$SYN_SEEN synack_in=$SYNACK_SEEN rst_in=$RST_SEEN rst_ttl=${RST_TTL:-n/a} ref_ttl=${REF_TTL:-n/a} (ref=$REF_HOST)"
else
  echo "съём пропущен (нет WAN-интерфейса или домен не разрешился)"
fi
echo

# --- 7. conntrack -------------------------------------------------------------
echo "## conntrack"
for ip in $IPS; do
  N=`grep -c "$ip" /proc/net/nf_conntrack 2>/dev/null`
  echo "$ip: ${N:-0} записей"
done
echo

# --- 8. вердикт ---------------------------------------------------------------
echo "## VERDICT"
# критерий — состоялось ли соединение, а не «красивый» ли HTTP-код:
# 404/403 значит путь до сервера жив (ошибка прикладная), а code=000 — соединения нет
http_answered() {
  case "$1" in ""|000) return 1 ;; *) return 0 ;; esac
}
OK_DIRECT=no
http_answered "$DIRECT_URL_CODE" && OK_DIRECT=yes
OK_PROXY=no
http_answered "$PROXY_CODE" && OK_PROXY=yes
OURS=no
if [ "$MT_HIT" = yes ] || [ "$IPSET_HIT" = yes ]; then OURS=yes; fi

if [ -z "$IPS" ]; then
  echo "DNS: домен не резолвится ни локально, ни через 1.1.1.1."
  echo "-> Слой DNS, не роутинг: смотреть резолвер (mihomo :6868 / DNS-hook MT) и авторитет домена."
elif [ "$OURS" = no ] && [ "$OK_DIRECT" = yes ]; then
  echo "НАШ РОУТИНГ НЕ ПРИ ЧЁМ. Правил на домен нет, IP не в ipset (значит direct), и direct РАБОТАЕТ: сервер ответил (code=$DIRECT_URL_CODE)."
  echo "-> Если у клиента всё равно не открывается: причина выше роутера (клиент, его DNS, приложение) либо проблема уже прошла."
elif [ "$OURS" = no ] && [ "$OK_DIRECT" = no ] && [ "$OK_PROXY" = yes ]; then
  echo "НАШ РОУТИНГ НЕ ПРИ ЧЁМ, но direct-путь снаружи не работает."
  echo "   Правил на домен нет, IP не в ipset — direct тут ожидаемое поведение."
  echo "   direct: неудача (code=$DIRECT_URL_CODE), через прокси: OK (code=$PROXY_CODE)."
  if [ "$SYN_SEEN" = yes ] && [ "$RST_SEEN" = yes ]; then
    echo "   На WAN: SYN уходит, в ответ RST — обрыв внешний, не локальный."
    if [ -n "$RST_TTL" ] && [ -n "$REF_TTL" ] && [ "$RST_TTL" -gt "$REF_TTL" ] 2>/dev/null; then
      echo "   TTL RST=$RST_TTL против TTL живого ответа $REF_HOST=$REF_TTL: RST рождается ближе конечного сервера"
      echo "   -> похоже на инъекцию RST провайдером/DPI, а не на отказ самого сервера."
    fi
  elif [ "$SYN_SEEN" = yes ] && [ "$RST_SEEN" = no ] && [ "$SYNACK_SEEN" = no ]; then
    echo "   На WAN: SYN уходит, ответа нет — тихий дроп по пути."
  fi
  echo "-> Чтобы заработало: добавить правило на \"$HOST\" в проксируемую группу MT."
elif [ "$OURS" = no ] && [ "$OK_DIRECT" = no ] && [ "$OK_PROXY" = no ]; then
  echo "НАШ РОУТИНГ НЕ ПРИ ЧЁМ (правил нет, IP не в ipset), но домен не открывается ни direct, ни через прокси."
  if [ -z "$REF_CODE" ] || [ "$REF_CODE" = 000 ]; then
    echo "   Эталон $REF_HOST тоже недоступен -> сначала проверить сам канал/WAN; диагностика по домену пока бессмысленна."
  else
    echo "   Эталон $REF_HOST доступен -> похоже, лежит сам сервис/CDN. Сторона сервера."
  fi
else
  if [ -n "$WIN_NAME" ]; then
    echo "НАШ РОУТИНГ УЧАСТВУЕТ: арбитраж MT выигрывает группа \"$WIN_NAME\" (why=$WIN_WHY)."
    if [ "$WIN_PENDING" = yes ]; then
      echo "   pending: правило совпало, но IP ещё не в ipset — прямо сейчас трафик идёт МИМО этой группы."
    fi
  else
    echo "НАШ РОУТИНГ УЧАСТВУЕТ: есть совпадение с правилом MT и/или IP лежит в ipset (см. секции выше)."
  fi
  echo "   direct: code=$DIRECT_URL_CODE, через прокси: code=$PROXY_CODE."
  if [ "$OK_PROXY" = no ]; then
    echo "-> Проксируемый путь неисправен: смотреть группу и ноду mihomo (/connections, логи, health-check)."
  else
    echo "-> Прокси-путь жив; если у клиента не работает — проверить попадание клиента в правила группы и directPriority."
  fi
fi
if [ "$DNS_MISMATCH" = yes ]; then
  echo "ВНИМАНИЕ: локальный и публичный резолверы разошлись по адресам — учесть при трактовке."
fi
