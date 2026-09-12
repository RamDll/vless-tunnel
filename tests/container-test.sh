#!/usr/bin/env bash
#===============================================================================
#  Интеграционный тест vless-tunnel в Docker ("контейнерный стенд").
#
#  БЕЗОПАСНОСТЬ: контейнер получает СВОЙ network namespace (docker bridge) и
#  только CAP_NET_ADMIN/CAP_NET_RAW. Флаги --net=host и --privileged НЕ
#  используются, поэтому iptables, ip rule и таблицы маршрутизации ХОСТА
#  не затрагиваются: сломается туннель — отвалится связь только у контейнера.
#
#  Что проверяется:
#    1) разбор ссылки и сборка config.json/state.json самим скриптом;
#    2) запуск ядра с tproxy-inbound под пользователем vless с ambient
#       CAP_NET_ADMIN — так же, как это делает systemd на хосте;
#    3) контроль ДО правил: прозрачный запрос идёт мимо туннеля;
#    4) _tproxy up: MARK -> ip rule/table 100 -> loopback -> TPROXY;
#    5) прозрачный TCP и прозрачный UDP/DNS через туннель;
#    6) SOCKS5 10808 и HTTP 10809;
#    7) идемпотентность: повторный up не плодит правила;
#    8) kill-switch: при упавшем ядре прозрачный трафик НЕ утекает напрямую;
#    9) _tproxy down: правила сняты, связь восстановлена.
#
#  Запуск:
#    bash tests/container-test.sh
#    LINK='vless://...' EXPECT_IP=1.2.3.4 bash tests/container-test.sh
#    KEEP=1 bash tests/container-test.sh          # оставить контейнер для отладки
#===============================================================================
set -Eeuo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
VLT="$SCRIPT_DIR/vless-tunnel.sh"
IMAGE="${IMAGE:-ubuntu:24.04}"
NAME="${NAME:-vless-tunnel-test}"
LINK="${LINK:-}"
EXPECT_IP="${EXPECT_IP:-}"
KEEP="${KEEP:-no}"
UUID="11111111-1111-1111-1111-111111111111"

say()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
ok()   { printf '  \033[32m[ok]\033[0m %s\n' "$*"; }
bad()  { printf '  \033[31m[x]\033[0m %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }
FAILED=0
check() { if [ "$2" = "0" ]; then ok "$1"; else bad "$1"; FAILED=1; fi; }
dex()  { docker exec "$NAME" "$@"; }
dexi() { docker exec -i "$NAME" "$@"; }

cleanup() {
  if [ "$KEEP" = "yes" ]; then printf '\nконтейнер оставлен: docker exec -it %s bash\n' "$NAME"
  else docker rm -f "$NAME" >/dev/null 2>&1 || true; fi
}
trap cleanup EXIT

[ -f "$VLT" ] || { bad "не найден $VLT"; exit 1; }
command -v docker >/dev/null || { bad "docker не найден"; exit 1; }
HOST_CORE=$(ls -1 "$SCRIPT_DIR/.work/core/xray" 2>/dev/null || true)
[ -n "$HOST_CORE" ] || HOST_CORE=$(ls -1 /opt/vless-tunnel/bin/xray-v* 2>/dev/null | head -1 || true)
if [ -z "$HOST_CORE" ]; then
  say "0. ядра нет — скачиваю в воркспейс (на хосте ничего не меняю)"
  mkdir -p "$SCRIPT_DIR/.work/core"
  V=$(curl -fsSLI -o /dev/null -w '%{url_effective}' --max-time 25 https://github.com/XTLS/Xray-core/releases/latest | sed 's|.*/tag/||')
  curl -sSL -o "$SCRIPT_DIR/.work/x.zip" "https://github.com/XTLS/Xray-core/releases/download/${V:-v26.3.27}/Xray-linux-64.zip"
  unzip -oq "$SCRIPT_DIR/.work/x.zip" -d "$SCRIPT_DIR/.work/core"
  chmod +x "$SCRIPT_DIR/.work/core/xray"
  HOST_CORE="$SCRIPT_DIR/.work/core/xray"
fi

say "1. контейнер: отдельный netns, только NET_ADMIN (без --net=host/--privileged)"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" --cap-add=NET_ADMIN --cap-add=NET_RAW \
  -v "$HOST_CORE:/opt/xray:ro" --entrypoint sleep "$IMAGE" infinity >/dev/null
note "$(dex sh -c '. /etc/os-release; echo $PRETTY_NAME')  |  $(dex /opt/xray version | head -1)"
note "network=$(docker inspect -f '{{.HostConfig.NetworkMode}}' "$NAME") caps=$(docker inspect -f '{{.HostConfig.CapAdd}}' "$NAME")"
docker cp "$VLT" "$NAME:/root/vless-tunnel.sh" >/dev/null

say "1b. зависимости: отчёт на ЧИСТОЙ системе и автоустановка"
OUT=$(dex bash /root/vless-tunnel.sh deps 2>&1 || true)
RC=$(dex bash -c 'bash /root/vless-tunnel.sh deps >/dev/null 2>&1; echo $?')
printf '%s' "$OUT" | grep -q "curl — ОТСУТСТВУЕТ" \
  && ok "на чистом образе видит отсутствие curl" \
  || { bad "не заметил отсутствие curl: $(printf '%s' "$OUT" | head -2 | tr '\n' ' ')"; FAILED=1; }
[ "$RC" != "0" ] && ok "код возврата ≠ 0 (нехватка обязательного)" \
  || { bad "deps вернула 0, хотя пакетов нет"; FAILED=1; }
OUT2=$(dex bash /root/vless-tunnel.sh deps --install 2>&1 || true)
printf '%s' "$OUT2" | grep -q "устанавливаю пакеты" \
  && ok "автоустановка запущена (apt)" \
  || { bad "автоустановка не запустилась"; FAILED=1; }
if printf '%s' "$OUT2" | grep -q "curl — есть" && printf '%s' "$OUT2" | grep -q "iptables — есть"; then
  ok "после автоустановки curl/iptables/python3 на месте"
else
  bad "пакеты не установились: $(printf '%s' "$OUT2" | tail -3 | tr '\n' ' ')"; FAILED=1
fi
printf '%s' "$OUT2" | grep -q "systemctl — ОТСУТСТВУЕТ" \
  && ok "отсутствие systemd в контейнере честно показано" || true

say "2. остальные зависимости и служебные пользователи"
dex bash -c 'export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq >/dev/null 2>&1
  apt-get install -y -qq curl python3 iptables iproute2 ca-certificates util-linux openssl procps sudo >/dev/null 2>&1
  id -u vless >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --comment "vless-tunnel service user" vless
  id -u vlserver >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin vlserver' >/dev/null
ok "установлено: $(dex iptables --version), $(dex python3 -V 2>&1), vless uid=$(dex id -u vless)"
dex bash -c 'sed -n "/^py_backend() {/,/^PYEOF\$/p" /root/vless-tunnel.sh | sed "1,2d;\$d" > /root/py.py'
ok "python-бэкенд извлечён из скрипта ($(dex sh -c 'wc -l < /root/py.py') строк)"

say "3. подготовка стенда"
PIN=""
if [ -n "$LINK" ]; then
  note "режим: реальный сервер из LINK"
  TEST_LINK="$LINK"; SERVER_IPS=""
else
  note "режим: локальный VLESS-сервер внутри контейнера"
  dexi bash -s <<INNER
set -e
mkdir -p /srv/vless && cd /srv/vless
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out cert.pem -days 2 -subj "/CN=localhost" >/dev/null 2>&1
cat > server.json <<EOF
{ "log": {"loglevel":"info","access":"/srv/vless/access.log"},
  "inbounds":[{"tag":"in","listen":"127.0.0.1","port":8443,"protocol":"vless",
    "settings":{"clients":[{"id":"$UUID"}],"decryption":"none"},
    "streamSettings":{"network":"tcp","security":"tls",
      "tlsSettings":{"certificates":[{"certificateFile":"/srv/vless/cert.pem","keyFile":"/srv/vless/key.pem"}]}}}],
  "outbounds":[{"protocol":"freedom"}] }
EOF
/opt/xray run -test -c server.json >/dev/null
chown -R vlserver:vlserver /srv/vless
chmod 0640 /srv/vless/key.pem && chmod 0644 /srv/vless/cert.pem /srv/vless/server.json
setsid setpriv --reuid=vlserver --regid=vlserver --init-groups /opt/xray run -c server.json >server.log 2>&1 </dev/null &
sleep 2
ss -Hltn | grep -q ":8443" && echo "    локальный VLESS-сервер слушает 127.0.0.1:8443" || { echo "    сервер не поднялся"; tail -3 server.log; exit 1; }
INNER
  PIN=$(dex python3 /root/py.py cert-pin 127.0.0.1 8443 localhost)
  note "отпечаток сертификата сервера: ${PIN:0:20}…"
  TEST_LINK="vless://$UUID@localhost:8443?type=tcp&security=tls&sni=localhost&allowInsecure=1"
  SERVER_IPS="127.0.0.1"
  EXCL_USERS="vlserver"   # «удалённый» сервер не должен перехватываться (иначе петля)
fi

say "4. конфиг и запуск клиента (vless + ambient CAP_NET_ADMIN)"
dex bash -c 'mkdir -p /etc/vless-tunnel'
dex env VLESS_LINK="$TEST_LINK" VLESS_OUT_CONFIG=/etc/vless-tunnel/config.json \
    VLESS_OUT_STATE=/etc/vless-tunnel/state.json VLESS_SERVER_IPS="${SERVER_IPS:-}" \
    VLESS_CORE_VERSION=v26.3.27 VLESS_CORE_FAMILY=modern VLESS_CERT_PIN="${PIN:-}" \
    VLESS_SOCKS_PORT=10808 VLESS_HTTP_PORT=10809 VLESS_TPROXY_PORT=12345 \
    VLESS_LOG_LEVEL=warning VLESS_EXCLUDE_USERS="${EXCL_USERS:-}" python3 /root/py.py make >/dev/null
dex bash -c 'chmod 0644 /etc/vless-tunnel/*.json'
ok "config.json/state.json собраны генератором скрипта"
dex /opt/xray run -test -c /etc/vless-tunnel/config.json >/dev/null && ok "ядро приняло конфиг"
dex bash -c 'setsid setpriv --reuid=vless --regid=vless --init-groups \
    --inh-caps +net_admin --ambient-caps +net_admin \
    /opt/xray run -c /etc/vless-tunnel/config.json >/root/cli.log 2>&1 </dev/null & sleep 2'
if dex sh -c 'ss -Hltn | grep -qE ":(10808|10809|12345)"'; then
  ok "клиент поднялся и слушает 10808/10809/12345"
else
  bad "клиент не поднялся:"; dex tail -6 /root/cli.log | sed 's/^/      /'; FAILED=1
fi

acc() { dex sh -c '[ -f /srv/vless/access.log ] && wc -l < /srv/vless/access.log || echo 0'; }
say "5. контроль ДО правил: прозрачный запрос идёт МИМО туннеля"
B=$(acc); C=$(dex curl -s --max-time 15 -o /dev/null -w '%{http_code}' https://example.com 2>/dev/null) || true; C=${C:-000}; A=$(acc)
note "curl https://example.com → код $C, новых записей в логе сервера: $((A-B))"
check "без правил трафик не попадает в туннель" "$([ $((A-B)) -eq 0 ] && echo 0 || echo 1)"

say "6. _tproxy up"
dex bash /root/vless-tunnel.sh _tproxy up >/dev/null && ok "правила применены"
R1=$(dex sh -c 'ip rule show | grep -c fwmark || true'); J1=$(dex sh -c 'iptables -t mangle -S PREROUTING | grep -c VLESS_TPROXY || true')
note "ip rule fwmark: $R1 | jump-правил в PREROUTING: $J1"
dex sh -c 'iptables -t mangle -S OUTPUT | sed "s/^/      /"'
dex sh -c 'iptables -t mangle -S VLESS_TPROXY | sed "s/^/      /"'
dex sh -c 'ip rule show | sed "s/^/      /"'
dex sh -c 'iptables -t mangle -S VLESS_MARK | sed "s/^/      /"'
check "в OUTPUT помечается TCP"  "$(dex sh -c 'iptables -t mangle -S VLESS_MARK' | grep -q -- '-p tcp -j MARK' && echo 0 || echo 1)"
check "в OUTPUT помечается UDP"  "$(dex sh -c 'iptables -t mangle -S VLESS_MARK' | grep -q -- '-p udp -j MARK' && echo 0 || echo 1)"
check "TPROXY ловит TCP"         "$(dex sh -c 'iptables -t mangle -S VLESS_TPROXY' | grep -q -- '-p tcp .*TPROXY' && echo 0 || echo 1)"
check "TPROXY ловит UDP"         "$(dex sh -c 'iptables -t mangle -S VLESS_TPROXY' | grep -q -- '-p udp .*TPROXY' && echo 0 || echo 1)"
check "nat/REDIRECT не используется" "$([ "$(dex sh -c 'iptables -t nat -S 2>/dev/null | grep -c VLESS')" = "0" ] && echo 0 || echo 1)"

say "7. прозрачный трафик через туннель"
B=$(acc); C=$(dex curl -s --max-time 25 -o /dev/null -w '%{http_code}' https://example.com 2>/dev/null) || true; C=${C:-000}; sleep 1; A=$(acc)
note "curl https://example.com → код $C, новых записей в логе сервера: $((A-B))"
if [ -n "$LINK" ]; then
  IP=$(dex curl -s --max-time 25 https://api.ipify.org || true)
  note "внешний IP через туннель: ${IP:-НЕТ}"
  [ -n "$EXPECT_IP" ] && check "внешний IP = $EXPECT_IP" "$([ "$IP" = "$EXPECT_IP" ] && echo 0 || echo 1)"
else
  check "прозрачный TCP идёт через туннель (код $C и рост лога сервера)" \
    "$([ $((A-B)) -gt 0 ] && [ "$C" != "000" ] && echo 0 || echo 1)"
fi

if dexi python3 - <<'PY'
import socket, struct, random, sys
tid = random.randint(0, 65535)
hdr = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
qd = b"".join(bytes([len(p)]) + p.encode() for p in "example.com".split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(8)
try:
    s.sendto(hdr + qd, ("9.9.9.9", 53)); d, _ = s.recvfrom(4096)
    sys.exit(0 if len(d) > 12 else 1)
except Exception:
    sys.exit(1)
PY
then ok "прозрачный UDP/DNS через TPROXY"; else bad "прозрачный UDP/DNS не прошёл"; FAILED=1; fi

S=$(dex curl -s --max-time 20 --socks5-hostname 127.0.0.1:10808 https://api.ipify.org 2>/dev/null) || true
H=$(dex curl -s --max-time 20 -x http://127.0.0.1:10809 https://api.ipify.org 2>/dev/null) || true
note "SOCKS5 10808 → ${S:-НЕ РАБОТАЕТ} | HTTP 10809 → ${H:-НЕ РАБОТАЕТ}"
check "локальные прокси работают" "$([ -n "$S" ] && [ -n "$H" ] && echo 0 || echo 1)"

say "8. идемпотентность: повторный _tproxy up"
dex bash /root/vless-tunnel.sh _tproxy up >/dev/null
R2=$(dex sh -c 'ip rule show | grep -c fwmark || true'); J2=$(dex sh -c 'iptables -t mangle -S PREROUTING | grep -c VLESS_TPROXY || true')
note "ip rule: $R1 → $R2 | jump-правил: $J1 → $J2"
check "правила не размножились" "$([ "$R1" = "$R2" ] && [ "$J1" = "$J2" ] && echo 0 || echo 1)"

say "9. kill-switch: гасим ядро — прозрачный трафик не должен утечь напрямую"
dex sh -c 'pkill -x xray || true'; sleep 1
C=$(dex curl -s --max-time 12 -o /dev/null -w '%{http_code}' https://example.com 2>/dev/null) || true; C=${C:-000}
note "curl при мёртвом ядре → код $C (000 = соединения нет, утечки нет)"
check "утечки напрямую нет" "$([ "$C" = "000" ] && echo 0 || echo 1)"

say "10. _tproxy down: правила сняты, связь восстановлена"
dex bash /root/vless-tunnel.sh _tproxy down >/dev/null && ok "правила сняты"
note "ip rule fwmark после down: $(dex sh -c 'ip rule show | grep -c fwmark || true')  |  цепочек VLESS: $(dex sh -c 'iptables -t mangle -S | grep -c VLESS || true')"
C=$(dex curl -s --max-time 15 -o /dev/null -w '%{http_code}' https://example.com || echo 000)
note "curl после down → код $C"
check "связь в контейнере восстановлена" "$([ "$C" != "000" ] && echo 0 || echo 1)"

if [ -z "$LINK" ] && [ "${INSTALL_TEST:-yes}" = "yes" ]; then
  say "11. установщик: фолбэк на уже установленное ядро при недоступном GitHub"
  dex bash -c 'mkdir -p /opt/vless-tunnel/bin
    cp /opt/xray /opt/vless-tunnel/bin/xray-v26.3.27
    ln -sf xray-v26.3.27 /opt/vless-tunnel/bin/xray
    printf "#!/bin/sh\necho \"\$@\" >> /tmp/systemctl.calls\nexit 0\n" > /usr/local/bin/systemctl && chmod +x /usr/local/bin/systemctl' >/dev/null
  OUT=$(dex env TESTLINK="$TEST_LINK" bash -c     'bash /root/vless-tunnel.sh install --force --yes --gh-proxy http://127.0.0.1:9/ --link "$TESTLINK" 2>&1 || true')
  if printf '%s' "$OUT" | grep -q "оставляю установленное ядро"; then
    ok "GitHub недоступен — установщик взял уже установленное ядро и не упал"
  else
    bad "фолбэк ядра не сработал"; FAILED=1
  fi
  printf '%s' "$OUT" | grep -E '^(==>|\[ok\]|\[!\]|\[x\])' | tail -8 | sed 's/^/      /'
  note "(в контейнере systemctl подменён заглушкой — проверяются только шаги до/вокруг службы)"
fi

if [ -z "$LINK" ] && [ "${INSTALL_TEST:-yes}" = "yes" ]; then
  say "12. защита от потери интернета: 'on' при мёртвом туннеле сам снимает перехват"
  dex sh -c 'pkill -x xray || true'; sleep 1
  OUT=$(dex bash -c 'bash /root/vless-tunnel.sh on 2>&1; echo "RC=$?"')
  printf '%s' "$OUT" | grep -q "выключаю перехват" && ok "скрипт предупредил и выключил перехват" || { bad "автоотключение не сработало"; FAILED=1; }
  printf '%s' "$OUT" | grep -q "RC=0" && { bad "'on' вернул успех при нерабочем туннеле"; FAILED=1; } || ok "'on' вернул ошибку (как и должен)"
  printf '%s' "$OUT" | grep -E '^(\[ok\]|\[!\]|\[x\])' | tail -3 | sed 's/^/      /'
fi

if [ -z "$LINK" ] && [ "${INSTALL_TEST:-yes}" = "yes" ]; then
  say "13. --no-start: установка не должна применять правила и трогать интернет"
  dex bash -c 'bash /root/vless-tunnel.sh _tproxy down >/dev/null 2>&1 || true'
  OUT=$(dex env TESTLINK="$TEST_LINK" bash -c \
    'bash /root/vless-tunnel.sh install --force --yes --no-start --link "$TESTLINK" 2>&1 || true')
  R=$(dex sh -c 'ip rule show | grep -c fwmark || true'); C=$(dex sh -c 'iptables -t mangle -S | grep -c VLESS || true')
  CODE=$(dex curl -s --max-time 15 -o /dev/null -w '%{http_code}' https://example.com 2>/dev/null) || true; CODE=${CODE:-000}
  note "после install --no-start: ip rule=$R, цепочек VLESS=$C, curl → код $CODE"
  check "--no-start не применяет правила" "$([ "$R" = "0" ] && [ "$C" = "0" ] && echo 0 || echo 1)"
  check "интернет остался прямым" "$([ "$CODE" != "000" ] && echo 0 || echo 1)"
  printf '%s' "$OUT" | grep -q "НЕ запущена (--no-start)" && ok "скрипт так и сообщил" || { bad "нет сообщения о --no-start"; FAILED=1; }
fi

if [ -z "$LINK" ] && [ "${INSTALL_TEST:-yes}" = "yes" ]; then
  say "14. интерактивный ввод ссылки через pty (приглашение не должно попасть в конфиг)"
  OUT=$(docker exec -i -e TESTLINK="$TEST_LINK" "$NAME" python3 - <<'PYEOF' 2>&1 || true
import os, pty, sys, time, select
link = os.environ["TESTLINK"]
pid, fd = pty.fork()
if pid == 0:
    os.execvp("bash", ["bash", "/root/vless-tunnel.sh", "install", "--force", "--dry-run", "--yes"])
time.sleep(1.0)
os.write(fd, (link + "\n").encode())
out = b""; deadline = time.time() + 90
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 2)
    if not r: break
    try: d = os.read(fd, 65536)
    except OSError: break
    if not d: break
    out += d
sys.stdout.write(out.decode(errors="replace"))
PYEOF
)
  CFG=$(printf '%s' "$OUT" | sed -n '/config.json (dry-run)/,/конец config.json/p')
  if [ -z "$CFG" ]; then
    bad "dry-run не вывел конфиг"; FAILED=1
    note "первые строки вывода:"; printf '%s' "$OUT" | head -6 | sed 's/^/      /'
    note "последние строки вывода:"; printf '%s' "$OUT" | tail -12 | sed 's/^/      /'
  else
    printf '%s' "$CFG" | grep -q '"id": "11111111-1111-1111-1111-111111111111"' \
      && ok "в конфиг попал правильный UUID (текст приглашения не утёк)" || { bad "UUID в конфиге неверный"; FAILED=1; }
    printf '%s' "$CFG" | grep -q '"address": "localhost"' \
      && ok "адрес сервера в конфиге правильный" || { bad "адрес сервера неверный"; FAILED=1; }
    printf '%s' "$OUT" | grep -q "установленное ядро приняло конфигурацию" \
      && ok "ядро приняло конфиг (формат .json определяется)" || { bad "ядро не подтвердило конфиг"; FAILED=1; }
  fi
fi

if [ -z "$LINK" ] && [ "${INSTALL_TEST:-yes}" = "yes" ]; then
  say "15. незавершённая установка: нет unit-файла — install доводит дело до конца, on ругается понятно"
  dex bash -c 'rm -f /etc/systemd/system/vless-tunnel.service'
  OUT=$(dex env TESTLINK="$TEST_LINK" bash -c \
    'bash /root/vless-tunnel.sh install --no-start --yes --link "$TESTLINK" 2>&1 || true')
  printf '%s' "$OUT" | grep -q "показываю меню" \
    && { bad "ушёл в меню вместо доведения установки"; FAILED=1; } || ok "не ушёл в меню"
  printf '%s' "$OUT" | grep -q "незавершённая установка" \
    && ok "предупредил про незавершённую установку" || { bad "нет предупреждения"; FAILED=1; }
  dex test -f /etc/systemd/system/vless-tunnel.service \
    && ok "unit-файл создан" || { bad "unit-файл не создан"; FAILED=1; }
  dex bash -c 'rm -f /etc/systemd/system/vless-tunnel.service'
  OUT2=$(dex bash -c 'bash /root/vless-tunnel.sh on 2>&1 || true')
  printf '%s' "$OUT2" | grep -q "служба не установлена" \
    && ok "'on' даёт понятное сообщение вместо сырой ошибки systemctl" \
    || { bad "'on' выдал: $(printf '%s' "$OUT2" | head -1)"; FAILED=1; }
fi

if [ -z "$LINK" ] && [ "${INSTALL_TEST:-yes}" = "yes" ]; then
  say "16. многострочная вставка: отчёт сервера, ссылка внутри текста"
  OUT=$(docker exec -i -e TESTLINK="$TEST_LINK" "$NAME" python3 - <<'PYEOF' 2>&1 || true
import os, pty, sys, time, select
link = os.environ["TESTLINK"]
blob = ("xray-auto-install \u2014 VLESS + XHTTP + Reality + Vision + PQC\n"
        "\u0421\u0435\u0440\u0432\u0435\u0440: 95.128.157.141\n"
        "== \u0421\u0441\u044b\u043b\u043a\u0430 ==\n" + link + "\n"
        "== \u0412\u0430\u0436\u043d\u043e ==\n- \u043d\u0443\u0436\u0435\u043d \u043a\u043b\u0438\u0435\u043d\u0442 \u0441 PQC\n")
pid, fd = pty.fork()
if pid == 0:
    os.execvp("bash", ["bash", "/root/vless-tunnel.sh", "install", "--force", "--dry-run", "--yes"])
time.sleep(1.0)
os.write(fd, blob.encode())
out = b""; deadline = time.time() + 90
while time.time() < deadline:
    r, _, _ = select.select([fd], [], [], 2)
    if not r: break
    try: d = os.read(fd, 65536)
    except OSError: break
    if not d: break
    out += d
sys.stdout.write(out.decode(errors="replace"))
PYEOF
)
  CFG=$(printf '%s' "$OUT" | sed -n '/config.json (dry-run)/,/конец config.json/p')
  if [ -z "$CFG" ]; then bad "конфиг не собран из многострочной вставки"; FAILED=1; else
    printf '%s' "$CFG" | grep -q '"id": "11111111-1111-1111-1111-111111111111"' \
      && ok "UUID верный" || { bad "UUID неверный"; FAILED=1; }
    printf '%s' "$CFG" | grep -q '"address": "localhost"' \
      && ok "адрес верный" || { bad "адрес неверный"; FAILED=1; }
    printf '%s' "$OUT" | grep -q "ядро приняло конфигурацию" \
      && ok "ядро приняло конфиг" || { bad "ядро не подтвердило конфиг"; FAILED=1; }
  fi
fi

if [ -z "$LINK" ] && [ "${INSTALL_TEST:-yes}" = "yes" ]; then
  say "17. автозапуск: по умолчанию НЕ включается, --autostart включает, autostart off снимает"
  dex bash -c 'rm -f /tmp/systemctl.calls'
  dex env TESTLINK="$TEST_LINK" bash -c \
    'bash /root/vless-tunnel.sh install --force --no-start --yes --link "$TESTLINK" >/dev/null 2>&1 || true'
  if dex sh -c 'grep -q "enable vless-tunnel.service" /tmp/systemctl.calls 2>/dev/null'; then
    bad "установка включила автозапуск, хотя по умолчанию не должна"; FAILED=1
  else ok "по умолчанию автозапуск не включается (только ручной запуск)"; fi
  dex bash -c 'rm -f /tmp/systemctl.calls'
  dex env TESTLINK="$TEST_LINK" bash -c \
    'bash /root/vless-tunnel.sh install --force --no-start --yes --autostart --link "$TESTLINK" >/dev/null 2>&1 || true'
  dex sh -c 'grep -q "enable vless-tunnel.service" /tmp/systemctl.calls 2>/dev/null' \
    && ok "флаг --autostart включает автозапуск" || { bad "--autostart не сработал"; FAILED=1; }
  dex bash -c 'rm -f /tmp/systemctl.calls'
  dex bash -c 'bash /root/vless-tunnel.sh autostart off >/dev/null 2>&1 || true'
  dex sh -c 'grep -q "disable vless-tunnel.service" /tmp/systemctl.calls 2>/dev/null' \
    && ok "команда autostart off снимает автозапуск" || { bad "autostart off не сработал"; FAILED=1; }
fi

say "18. --link-stdin принимает многострочную вставку целиком (как из GUI)"
BLOB="xray-auto-install \u2014 \u043e\u0442\u0447\u0451\u0442
\u0421\u0435\u0440\u0432\u0435\u0440: 95.128.157.141
== \u0421\u0441\u044b\u043b\u043a\u0430 ==
$TEST_LINK
== \u0412\u0430\u0436\u043d\u043e ==
- \u0442\u0435\u043a\u0441\u0442"
for flag in --link-stdin --stdin; do
  OUT=$(printf '%s\n' "$BLOB" | dexi bash /root/vless-tunnel.sh link-check "$flag" 2>&1 || true)
  printf '%s' "$OUT" | grep -q "localhost:8443" \
    && ok "флаг $flag: ссылка найдена в многострочном тексте" \
    || { bad "флаг $flag не разобрал: $(printf '%s' "$OUT" | head -2 | tr '\n' ' ')"; FAILED=1; }
done
printf '%s' "$OUT" | grep -qE 'Транспорт: (tcp|xhttp|ws|grpc)' \
  && ok "транспорт определён верно" || { bad "транспорт неверный"; FAILED=1; }

say "19*. все команды, которые вызывает GUI, распознаются парсером"
SWEEP_FAIL=0
run_cmd() { # $1 = описание, дальше команда
  local desc="$1"; shift
  local out; out=$(dex bash -c "bash /root/vless-tunnel.sh $* 2>&1 || true")
  if printf '%s' "$out" | grep -qE 'неизвестн(ая|ый) (опция|команда)'; then
    bad "$desc → $(printf '%s' "$out" | head -1)"; SWEEP_FAIL=1
  else
    ok "$desc"
  fi
}
run_cmd "status --json"                 "status --json"
run_cmd "logs --lines 5"                "logs --lines 5"
OUT_DOC=$(dex bash -c "bash /root/vless-tunnel.sh doctor 2>&1 || true")
if printf '%s' "$OUT_DOC" | grep -q "неизвестн"; then
  bad "doctor → $(printf '%s' "$OUT_DOC" | head -1)"; SWEEP_FAIL=1
else ok "doctor"; fi
printf '%s' "$OUT_DOC" | grep -q "ВЕРДИКТ:" \
  && ok "doctor: выдаёт итоговый вердикт" \
  || { bad "doctor: нет вердикта"; SWEEP_FAIL=1; }
printf '%s' "$OUT_DOC" | grep -qE "правил перехвата НЕТ|выключен, правил нет|не работает" \
  && ok "doctor: вердикт учитывает состояние правил" || true
run_cmd "autostart status"              "autostart status"
OUT_UC=$(dex bash -c "bash /root/vless-tunnel.sh update-core --gh-proxy http://127.0.0.1:9/ 2>&1 || true")
if printf '%s' "$OUT_UC" | grep -q "неизвестн"; then
  bad "update-core → $(printf '%s' "$OUT_UC" | head -1)"; SWEEP_FAIL=1
else ok "update-core (gh недоступен)"; fi
printf '%s' "$OUT_UC" | grep -q "возвращаю прежнее ядро" \
  && ok "update-core: при нерабочем туннеле вернул прежнее ядро" \
  || { bad "update-core: откат не сработал: $(printf '%s' "$OUT_UC" | grep -E '^\[|ядро' | tail -2 | tr '\n' ' ')"; SWEEP_FAIL=1; }
run_cmd "set-link --link-stdin"         "set-link --link-stdin < /dev/null"
[ "$SWEEP_FAIL" = "0" ] || FAILED=1

say "19b. GUI: кнопки вместо списка + текст вывода доходит до окна (заглушка zenity)"
dex bash -c 'cat > /usr/local/bin/zenity <<"ZEOF"
#!/bin/sh
echo "$*" >> /tmp/zenity.calls
case "$*" in
  *--help-general*) printf "  --extra-button=ТЕКСТ  Добавляет дополнительную кнопку\n"; exit 0 ;;
  *--forms*)
    n=$(grep -c -- "--forms" /tmp/zenity.calls 2>/dev/null)
    if [ "$n" -le 1 ]; then echo "Диагностика"; exit 0; fi   # выбор действия
    exit 1 ;;                                                 # дальше — отмена
  *--question*)
    n=$(grep -c -- "--question" /tmp/zenity.calls 2>/dev/null)
    if [ "$n" -le 1 ]; then exit 2; fi   # первый раз — кнопка «Действия…»
    exit 1 ;;                            # потом — «Закрыть»
  *--text-info*) cat > /tmp/zenity.stdin; exit 0 ;;
  *--progress*)  cat > /dev/null; exit 0 ;;
  *) exit 1 ;;
esac
ZEOF
chmod +x /usr/local/bin/zenity; rm -f /tmp/zenity.calls /tmp/zenity.stdin'
dex bash -c 'timeout 120 bash /root/vless-tunnel.sh gui >/tmp/gui.out 2>&1 || true'
if dex test -s /tmp/zenity.stdin; then ok "окно получило текст (не пустое)"
else bad "окно пустое: $(dex sh -c 'tail -2 /tmp/gui.out' | tr '\n' ' ')"; FAILED=1; fi
if dex sh -c 'grep -q "ВЕРДИКТ:" /tmp/zenity.stdin'; then ok "в окне — реальный вывод диагностики"
else bad "в окне нет вывода диагностики"; FAILED=1; fi

say "20. полный откат: uninstall убирает всё, что поставил скрипт"
dex bash -c 'bash /root/vless-tunnel.sh uninstall --yes' >/dev/null 2>&1 || true
LEFT=0
for p in /etc/systemd/system/vless-tunnel.service \
         /etc/systemd/system/vless-tunnel-watchdog.service \
         /etc/systemd/system/vless-tunnel-watchdog.timer \
         /etc/vless-tunnel /opt/vless-tunnel /usr/local/bin/vless-tunnel \
         /usr/share/applications/vless-tunnel.desktop; do
  if dex test -e "$p"; then bad "осталось: $p"; FAILED=1; LEFT=1; fi
done
[ "$LEFT" = "0" ] && ok "службы, таймеры, конфиг, ядро, логи, ярлык — удалены"
if dex id -u vless >/dev/null 2>&1; then bad "системный пользователь vless остался"; FAILED=1
else ok "системный пользователь vless удалён"; fi
R=$(dex sh -c 'ip rule show | grep -c fwmark || true')
[ "$R" = "0" ] && ok "правила policy routing сняты" || { bad "остались ip rule: $R"; FAILED=1; }
CODE=$(dex curl -s --max-time 15 -o /dev/null -w '%{http_code}' https://example.com 2>/dev/null) || true; CODE=${CODE:-000}
[ "$CODE" != "000" ] && ok "интернет в контейнере работает" || { bad "интернет пропал"; FAILED=1; }

printf '\n==================== ИТОГ ====================\n'
if [ "$FAILED" -eq 0 ]; then printf '\033[32mВСЕ ПРОВЕРКИ ПРОЙДЕНЫ\033[0m\n'; else printf '\033[31mЕСТЬ ПАДЕНИЯ\033[0m\n'; fi
printf 'хост не затронут: iptables/ip rule жили только внутри netns контейнера\n'
exit "$FAILED"
