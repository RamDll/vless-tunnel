#!/usr/bin/env bash
#===============================================================================
#  vless-tunnel — прозрачное проксирование ВСЕГО трафика Ubuntu через VLESS
#  (Xray-core): TCP + UDP/QUIC, HTTP-прокси и SOCKS5, автозапуск, GUI-кнопка.
#-------------------------------------------------------------------------------
#  Возможности:
#    * при первом запуске спрашивает ссылку vless:// и настраивает всё с нуля;
#    * при повторном запуске видит, что уже установлено, и предлагает вставить
#      другую ссылку на сервер (пункт меню «Сменить сервер»);
#    * после установки управление (вкл/выкл/смена сервера) выполняется БЕЗ
#      пароля sudo — пишется точечное правило /etc/sudoers.d/vless-tunnel;
#    * поддержка транспортов: tcp/raw, ws, grpc, httpupgrade, xhttp/splithttp
#      (в т.ч. HTTP/2 и HTTP/3=QUIC), а также legacy HTTP/2 и QUIC (через
#      автоматическую установку совместимого ядра Xray v1.8.24);
#    * обязательная поддержка HTTP и QUIC: локальные HTTP- и SOCKS5-прокси +
#      прозрачный перехват TCP и UDP (QUIC/HTTP-3 идёт через туннель);
#    * защита от утечек: DNS заворачивается во встроенный DNS Xray (DoH через
#      туннель), IPv4+IPv6, kill-switch «по построению» (при падении Xray
#      пакеты уходят в никуда, а не напрямую).
#
#  Запуск:   sudo ./vless-tunnel.sh          (установка / меню)
#            sudo ./vless-tunnel.sh install
#            vless-tunnel status|on|off|toggle|test|gui
#
#  Удаление: sudo vless-tunnel uninstall
#===============================================================================
set -Eeuo pipefail

readonly APP="vless-tunnel"
readonly APP_VERSION="1.2.4"
readonly APP_BUILD="2026-09-12"
readonly PREFIX_DIR="/opt/vless-tunnel"
readonly BIN_DIR="$PREFIX_DIR/bin"
readonly ETC_DIR="/etc/vless-tunnel"
readonly LOG_DIR="/var/log/vless-tunnel"
# Where the systemd units, sudoers rule and desktop file all point at.
# If we're already running from a recognised installed location (the .deb
# puts the script at /usr/bin/vless-tunnel; a from-source install ends up
# at /usr/local/bin/vless-tunnel), stay there — copying ourselves to the
# other one would leave two copies on disk, with the service/sudoers/self-
# update all pinned to whichever one happened to be created first. A future
# `apt upgrade` only refreshes /usr/bin, so the copy actually executed by
# the running service would silently keep running the old code forever.
_self_resolved=$(readlink -f "$0" 2>/dev/null || printf '%s' "$0")
case "$_self_resolved" in
  "/usr/bin/$APP"|"/usr/local/bin/$APP") SELF_PATH="$_self_resolved" ;;
  *) SELF_PATH="/usr/local/bin/$APP" ;;
esac
readonly SELF_PATH
unset _self_resolved
readonly STATE_FILE="$ETC_DIR/state.json"
readonly CONFIG_FILE="$ETC_DIR/config.json"
readonly SVC_NAME="vless-tunnel"
readonly SVC_UNIT="/etc/systemd/system/${SVC_NAME}.service"
readonly WD_UNIT="/etc/systemd/system/${SVC_NAME}-watchdog.service"
readonly WD_TIMER="/etc/systemd/system/${SVC_NAME}-watchdog.timer"
readonly SUDOERS_FILE="/etc/sudoers.d/vless-tunnel"
readonly DESKTOP_FILE="/usr/share/applications/vless-tunnel.desktop"
readonly RULES_MARKER="/run/vless-tunnel/net"
readonly SVC_USER="vless"
readonly LEGACY_CORE_VERSION="v1.8.24"     # последнее ядро с legacy HTTP/2 + QUIC
readonly DEF_SOCKS_PORT=10808
readonly DEF_HTTP_PORT=10809
readonly DEF_TPROXY_PORT=12345
readonly DEF_LOG_LEVEL="warning"
# Single source of truth for "private/LAN, don't proxy" ranges (RFC 1918 +
# friends). Consumed directly by tproxy_up()'s iptables rules below, and
# passed to the Python backend via env (see py_backend()) so the routing
# config it writes can't silently drift from what iptables actually excludes.
readonly PRIVATE_CIDRS_V4="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4"
readonly PRIVATE_CIDRS_V6="::1/128 fc00::/7 fe80::/10 ff00::/8"
readonly NATIVE_GUI_PY="/usr/lib/vless-tunnel/vless-tunnel-gui.py"   # ставится .deb-пакетом
readonly VENDOR_CORE="/usr/lib/vless-tunnel/xray"                    # ядро, зашитое в .deb

#-------------------------------------------------------------------------------
#  Цвета / логирование
#-------------------------------------------------------------------------------
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  C_RST=$'\033[0m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'
  C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[36m'; C_BLD=$'\033[1m'
else
  C_RST=""; C_DIM=""; C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_BLD=""
fi

log()  { printf '%s\n' "$*"; }
info() { printf '%s==>%s %s\n' "$C_BLU" "$C_RST" "$*"; }
step() { printf '%s==>%s %s\n' "$C_BLD$C_BLU" "$C_RST" "$*"; }
ok()   { printf '%s[ok]%s %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '%s[!]%s %s\n' "$C_YEL" "$C_RST" "$*" >&2; }
err()  { printf '%s[x]%s %s\n' "$C_RED" "$C_RST" "$*" >&2; }
die()  { err "$*"; exit 1; }
hr()   { printf '%s\n' "${C_DIM}------------------------------------------------------------${C_RST}"; }

#-------------------------------------------------------------------------------
#  Опции (по умолчанию)
#-------------------------------------------------------------------------------
OPT_LINK=""
OPT_LINK_STDIN="no"
OPT_YES="no"
OPT_FORCE="no"
OPT_AUTOSTART="no"        # по умолчанию только ручной запуск (кнопкой)
OPT_KEEP_CONFIG="no"
OPT_PURGE_USER="yes"      # при удалении убирать и системного пользователя (полный откат)
OPT_KEEP_USER="no"
OPT_SOCKS_PORT="$DEF_SOCKS_PORT"
OPT_HTTP_PORT="$DEF_HTTP_PORT"
OPT_TPROXY_PORT="$DEF_TPROXY_PORT"
OPT_EXCLUDE_LAN="yes"          # не заворачивать в туннель частные сети (LAN)
OPT_IPV6_MODE="proxy"          # proxy | block
OPT_DIRECT_DNS="1.1.1.1,8.8.8.8"
OPT_CORE_VERSION=""            # пусто = выбрать автоматически
OPT_FROM_FILE=""
OPT_GH_PROXY="${VLESS_GH_PROXY:-}"
OPT_ALLOW_USERS=""
OPT_LOG_LEVEL="$DEF_LOG_LEVEL"
OPT_ACCESS_LOG="no"
OPT_EXCLUDE_USERS=""        # доп. пользователи, чей трафик не перехватывать
OPT_VISION_UDP443="yes"     # vision + UDP/443 (QUIC) — иначе QUIC отбрасывается
OPT_WATCHDOG="yes"
OPT_MUX="no"
OPT_JSON="no"
OPT_LINES="40"
OPT_DRY_RUN="no"
OPT_NO_START="no"      # установить, но не запускать службу
OPT_CMD=""
CALC_CERT_PIN=""
USER_CREATED="no"
TPROXY_ACTION="up"
FORCE_CORE="no"
AUTOSTART_ACTION="status"
OPT_DEPS_INSTALL="no"
TUNNEL_EXIT_IP=""

#-------------------------------------------------------------------------------
#  Утилиты
#-------------------------------------------------------------------------------
have() { command -v "$1" >/dev/null 2>&1; }

require_root() { [ "$(id -u)" -eq 0 ] || die "нужны права root"; }

confirm() { # confirm "вопрос" [default(y/n)]
  local q="$1" def="${2:-y}" ans
  [ "$OPT_YES" = "yes" ] && return 0
  [ -t 0 ] || { [ "$def" = "y" ]; return $?; }
  if [ "$def" = "y" ]; then printf '%s [Y/n]: ' "$q"; else printf '%s [y/N]: ' "$q"; fi
  read -r ans || ans=""
  ans="${ans,,}"
  if [ -z "$ans" ]; then [ "$def" = "y" ]; return $?; fi
  [ "$ans" = "y" ] || [ "$ans" = "yes" ] || [ "$ans" = "д" ] || [ "$ans" = "да" ]
}

svc_active()  { systemctl is-active --quiet "$SVC_NAME.service" 2>/dev/null; }
svc_enabled() { systemctl is-enabled --quiet "$SVC_NAME.service" 2>/dev/null; }
svc_exists()  { [ -f "$SVC_UNIT" ]; }
installed()   { [ -f "$STATE_FILE" ] && [ -x "$BIN_DIR/xray" ]; }

uid_of_user() { id -u "$1" 2>/dev/null || echo "0"; }

#-------------------------------------------------------------------------------
#  Совместимость с уже установленными Xray/sing-box/VPN и чужими правилами
#-------------------------------------------------------------------------------
port_in_use() { # $1 = порт
  ss -Hltnu 2>/dev/null | awk '{print $5}' | grep -qE "[:.]$1\$"
}

check_ports_free() {
  # Службу НЕ останавливаем: если порт занят ею же — это нормально, она
  # перезапустится в самом конце установки. Так падение установки больше не
  # оставляет машину без работающего туннеля.
  local own_socks="" own_http="" own_tproxy=""
  if [ -f "$STATE_FILE" ] && svc_active; then
    own_socks=$(state_get socks_port)
    own_http=$(state_get http_port)
    own_tproxy=$(state_get tproxy_port)
  fi
  local busy=() mine=() spec label rest p own
  for spec in "socks:$OPT_SOCKS_PORT:$own_socks" \
              "http:$OPT_HTTP_PORT:$own_http" \
              "tproxy:$OPT_TPROXY_PORT:$own_tproxy"; do
    label="${spec%%:*}"; rest="${spec#*:}"; p="${rest%%:*}"; own="${rest#*:}"
    port_in_use "$p" || continue
    if [ -n "$own" ] && [ "$p" = "$own" ]; then
      mine+=("$label=$p")
    else
      busy+=("$label=$p")
    fi
  done
  if [ "${#busy[@]}" -gt 0 ]; then
    err "нужные порты уже заняты: ${busy[*]}"
    ss -Hltnup 2>/dev/null | grep -E ":($OPT_SOCKS_PORT|$OPT_HTTP_PORT|$OPT_TPROXY_PORT)\b" >&2 || true
    err "выберите другие порты: --socks-port / --http-port / --tproxy-port"
    return 1
  fi
  if [ "${#mine[@]}" -gt 0 ]; then
    info "порты ${mine[*]} заняты текущим $APP — это ожидаемо, служба перезапустится в конце"
  fi
  return 0
}

detect_conflicts() {
  # Возвращает 1, если найдены признаки другого туннеля/прозрачного прокси
  local found=0 svc ifs cidr
  for svc in xray sing-box v2ray mihomo clash hysteria trojan wg-quick@wg0 openvpn openvpn@client; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
      warn "активна чужая служба '$svc' — два полных туннеля на одной машине конфликтуют"
      found=1
    fi
  done
  ifs=$(ip -o link show 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1 \
        | grep -E '^(tun|utun|tap|wg|sing|xray|nebula|ppp)' | tr '\n' ' ')
  if [ -n "$ifs" ]; then
    warn "подняты туннельные интерфейсы: $ifs — их трафик будет перехвачен"
    found=1
  fi
  if ip route show default 2>/dev/null | grep -qE ' dev (tun|utun|tap|wg|sing|xray)'; then
    warn "маршрут по умолчанию уже идёт в туннель: $(ip route show default | head -1)"
    found=1
  fi
  if iptables -t mangle -S 2>/dev/null | grep -iE 'TPROXY' | grep -qv "$CHAIN_TPROXY"; then
    warn "в iptables (mangle) уже есть чужие правила TPROXY"
    found=1
  fi
  if iptables -t nat -S 2>/dev/null | grep -q -- '-j REDIRECT'; then
    warn "в iptables (nat) уже есть чужие правила REDIRECT"
    found=1
  fi
  if nft list ruleset 2>/dev/null | grep -qiE 'tproxy|redirect to :[0-9]+'; then
    warn "в nftables найдены правила прозрачного прокси (TPROXY/redirect)"
    found=1
  fi
  local our_mark our_table foreign_rules
  our_mark=$(state_get fwmark 2>/dev/null || true); our_mark="${our_mark:-0x1}"
  our_table=$(state_get rt_table 2>/dev/null || true); our_table="${our_table:-100}"
  foreign_rules=$(ip rule show 2>/dev/null | grep 'fwmark' \
    | grep -vE "fwmark ${our_mark}([^0-9a-f]|\$)" || true)
  if [ -n "$foreign_rules" ]; then
    warn "уже есть чужой policy routing по fwmark: $(printf '%s' "$foreign_rules" | tr '\n' ';')"
    found=1
  fi
  for cidr in 100 101 102; do
    [ "$cidr" = "$our_table" ] && continue
    if ip route show table "$cidr" 2>/dev/null | grep -q 'local default dev lo'; then
      warn "таблица маршрутизации $cidr уже используется чужим TPROXY (local default dev lo)"
      found=1
    fi
  done
  return $([ "$found" -eq 0 ] && echo 0 || echo 1)
}

pick_fwmark_table() {
  # Печатает "0xN TABLE", выбирая свободные fwmark и таблицу маршрутизации
  local rules i hex table
  rules=$(ip rule show 2>/dev/null || true)
  for i in $(seq 1 255); do
    hex=$(printf '0x%x' "$i")
    if ! printf '%s\n' "$rules" | grep -Eq "fwmark ${hex}([^0-9a-f]|\$)"; then
      for table in $(seq 100 130); do
        if ! printf '%s\n' "$rules" | grep -Eq "lookup ${table}([^0-9]|\$)"; then
          if ! ip route show table "$table" 2>/dev/null | grep -q .; then
            printf '%s %s\n' "$hex" "$table"
            return 0
          fi
        fi
      done
    fi
  done
  printf '0x1 100\n'
}

read_net_params() { # fwmark/таблица: из state, иначе свободные
  FWMARK=$(state_get fwmark 2>/dev/null || true)
  RT_TABLE=$(state_get rt_table 2>/dev/null || true)
  case "$FWMARK" in 0x[0-9a-fA-F]*) ;; *) FWMARK="" ;; esac
  case "$RT_TABLE" in ''|*[!0-9]*) RT_TABLE="" ;; esac
  if [ -z "$FWMARK" ] || [ -z "$RT_TABLE" ]; then
    read -r FWMARK RT_TABLE <<< "$(pick_fwmark_table)"
  fi
}

write_rules_marker() {
  install -d -m 0755 "$(dirname "$RULES_MARKER")" 2>/dev/null || true
  printf 'FWMARK=%s\nRT_TABLE=%s\n' "$FWMARK" "$RT_TABLE" > "$RULES_MARKER"
}

clear_rules_marker() { rm -f "$RULES_MARKER"; }

marker_value() { awk -F= -v k="$1" '$1==k{print $2}' "$RULES_MARKER" 2>/dev/null; }

#-------------------------------------------------------------------------------
#  Python-бэкенд: разбор ссылки vless://, сборка config.json/state.json
#-------------------------------------------------------------------------------
py_backend() {
  VLESS_PRIVATE4="$PRIVATE_CIDRS_V4" VLESS_PRIVATE6="$PRIVATE_CIDRS_V6" python3 - "$@" <<'PYEOF'
# -*- coding: utf-8 -*-
import json, os, re, sys, urllib.parse, datetime

# Passed in by py_backend() from the bash-side PRIVATE_CIDRS_V4/V6 constants
# — the single source of truth also used by tproxy_up()'s iptables rules,
# so this list can't silently drift from what iptables actually excludes.
PRIVATE4 = os.environ["VLESS_PRIVATE4"].split()
PRIVATE6 = os.environ["VLESS_PRIVATE6"].split()

NETWORKS = ("tcp", "raw", "ws", "grpc", "http", "h2", "quic", "kcp",
            "httpupgrade", "xhttp", "splithttp")


def die(msg, code=2):
    sys.stderr.write("ошибка: %s\n" % msg)
    sys.exit(code)


def is_ip(s):
    try:
        import ipaddress
        ipaddress.ip_address(s)
        return True
    except Exception:
        return False


def split_hostport(hp):
    hp = (hp or "").strip()
    if hp.startswith("["):
        i = hp.find("]")
        if i < 0:
            die("некорректный IPv6-адрес в ссылке")
        host, rest = hp[1:i], hp[i + 1:]
        port = rest[1:] if rest.startswith(":") else ""
    elif hp.count(":") >= 2:
        host, port = hp, ""
    elif ":" in hp:
        host, _, port = hp.rpartition(":")
    else:
        host, port = hp, ""
    return urllib.parse.unquote(host).strip(), port.strip()


def parse_link(link):
    raw = (link or "").strip().strip('"').strip("'")
    # если вместе со ссылкой вставили лишний текст (например, строку приглашения),
    # берём последний «токен», который начинается с vless://
    toks = re.split(r"\s+", raw)
    url_safe = re.compile(r"^[A-Za-z0-9\-._~%!$&'()*+,;=:@/?\[\]#]+$")
    cands = []
    for i, t in enumerate(toks):
        if not re.match(r"(?i)^vless://", t):
            continue
        acc = t
        # ссылку могло разорвать переносом строки — склеиваем только URL-подобные хвосты
        for k in range(i + 1, min(i + 3, len(toks))):
            if not url_safe.match(toks[k]) or not toks[k]:
                break
            if not re.match(r"^[A-Za-z0-9]", toks[k]):   # продолжение ссылки, а не «==» / «---»
                break
            if re.match(r"(?i)^vless://", toks[k]):   # не приклеиваем вторую ссылку
                break
            acc += toks[k]
        cands.append(acc)
    link = max(cands, key=len) if cands else raw
    m = re.search(r"(?i)vless://", link)
    if m and m.start() > 0:
        link = link[m.start():]
    link = "".join(link.split())
    if not link:
        die("пустая ссылка")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", link, re.I):
        # пользователь вставил ссылку без схемы (uuid@host:port?...)
        if "@" in link:
            link = "vless://" + link
    if not re.match(r"^vless://", link, re.I):
        die("ожидается ссылка, начинающаяся с vless://")
    if re.match(r"^vless://\s*$", link, re.I):
        die("ссылка пустая")
    body = link[len("vless://"):]
    frag = ""
    if "#" in body:
        body, frag = body.split("#", 1)
    frag = urllib.parse.unquote(frag).strip()
    qs = ""
    if "?" in body:
        body, qs = body.split("?", 1)
    if "@" not in body:
        die("в ссылке нет части «UUID@хост:порт»")
    userinfo, hostport = body.rsplit("@", 1)
    uuid = urllib.parse.unquote(userinfo).strip()
    host, port_s = split_hostport(hostport)
    if not uuid:
        die("в ссылке не указан UUID")
    if not host:
        die("в ссылке не указан адрес сервера")
    try:
        port = int(port_s or 443)
    except ValueError:
        die("некорректный порт: %r" % port_s)
    if not 1 <= port <= 65535:
        die("порт вне диапазона: %d" % port)
    q = {}
    for k, v in urllib.parse.parse_qsl(qs, keep_blank_values=True):
        q[k.strip().lower()] = v

    net = (q.get("type") or q.get("network") or "tcp").strip().lower()
    if net in ("h2", "http2"):
        net = "http"
    if net == "":
        net = "tcp"
    if net not in NETWORKS:
        die("неизвестный транспорт type=%s (поддерживаются: %s)" % (net, ", ".join(sorted(set(NETWORKS)))))

    security = (q.get("security") or "none").strip().lower()
    if security in ("", "auto", "none"):
        security = "none"
    if security == "xtls":
        security = "tls"          # legacy xtls-rprx-direct больше не существует
    if security not in ("none", "tls", "reality"):
        die("неизвестный security=%s (ожидается none, tls или reality)" % security)

    alpn = [a for a in re.split(r"[,\s]+", q.get("alpn", "")) if a]
    p = {
        "link": link,
        "name": frag,
        "uuid": uuid,
        "host": host,
        "port": port,
        "host_is_ip": is_ip(host),
        "network": net,
        "security": security,
        "encryption": (q.get("encryption") or "none").strip() or "none",
        "flow": (q.get("flow") or "").strip(),
        "sni": (q.get("sni") or "").strip(),
        "alpn": alpn,
        "fp": (q.get("fp") or "").strip(),
        "pbk": (q.get("pbk") or "").strip(),
        "sid": (q.get("sid") or "").strip(),
        "spx": (q.get("spx") or "").strip(),
        "pqv": (q.get("pqv") or "").strip(),
        "path": (q.get("path") or "").strip(),
        "host_header": (q.get("host") or "").strip(),
        "service": (q.get("servicename") or "").strip(),
        "mode": (q.get("mode") or "").strip().lower(),
        "header_type": (q.get("headertype") or "").strip().lower(),
        "quic_security": (q.get("quicsecurity") or "none").strip() or "none",
        "key": (q.get("key") or "").strip(),
        "seed": (q.get("seed") or "").strip(),
        "extra": (q.get("extra") or "").strip(),
        "allow_insecure": (q.get("allowinsecure") or "").strip().lower() in ("1", "true", "yes", "on"),
        "ech": (q.get("ech") or "").strip(),
        "mux": (q.get("mux") or "").strip().lower() in ("1", "true", "yes", "on"),
        "query": q,
    }
    if security == "reality":
        if not p["pbk"]:
            die("в ссылке security=reality, но не указан publicKey (pbk)")
        if net not in ("tcp", "raw", "http", "xhttp", "splithttp", "grpc"):
            die("REALITY не поддерживается с транспортом %s (только tcp, xhttp, h2, grpc)" % net)
    if p["flow"] not in ("", "xtls-rprx-vision", "xtls-rprx-vision-udp443"):
        die("неизвестный flow=%s (поддерживаются xtls-rprx-vision и xtls-rprx-vision-udp443)" % p["flow"])
    if p["flow"] and security == "none":
        die("flow=%s требует security=tls или security=reality" % p["flow"])
    return p


def legacy_reasons(p):
    """Транспорты, удалённые из современных Xray — нужно ядро v1.8.24."""
    r = []
    if p["network"] == "http":
        r.append("legacy HTTP/2 (type=http)")
    if p["network"] == "quic":
        r.append("legacy QUIC (type=quic)")
    if p["network"] == "kcp" and (p["header_type"] not in ("", "none") or p["seed"]):
        r.append("mKCP header/seed")
    return r


def build_stream(p, o=None):
    o = o or {}
    net = p["network"]
    if net == "raw":
        net = "tcp"
    st = {"network": net}
    host_hdr = p["host_header"] or p["sni"]

    if net == "tcp":
        if p["header_type"] == "http":
            req = {"path": [p["path"] or "/"], "headers": {}}
            if p["host_header"]:
                req["headers"]["Host"] = [p["host_header"]]
            st["tcpSettings"] = {"header": {"type": "http", "request": req}}
    elif net == "ws":
        s = {}
        if p["path"]:
            s["path"] = p["path"]
        if host_hdr:
            s["host"] = host_hdr
        st["wsSettings"] = s
    elif net == "grpc":
        s = {}
        if p["service"]:
            s["serviceName"] = p["service"]
        if p["mode"] == "multi":
            s["multiMode"] = True
        st["grpcSettings"] = s
    elif net == "http":
        s = {}
        if host_hdr:
            s["host"] = [x for x in host_hdr.split(",") if x]
        if p["path"]:
            s["path"] = p["path"]
        st["httpSettings"] = s
    elif net == "quic":
        st["quicSettings"] = {
            "security": p["quic_security"] or "none",
            "key": p["key"],
            "header": {"type": p["header_type"] or "none"},
        }
    elif net == "kcp":
        s = {}
        if p["header_type"] and p["header_type"] != "none":
            s["header"] = {"type": p["header_type"]}
        if p["seed"]:
            s["seed"] = p["seed"]
        st["kcpSettings"] = s
    elif net == "httpupgrade":
        s = {}
        if p["path"]:
            s["path"] = p["path"]
        if host_hdr:
            s["host"] = host_hdr
        st["httpupgradeSettings"] = s
    elif net in ("xhttp", "splithttp"):
        s = {}
        if p["path"]:
            s["path"] = p["path"]
        if host_hdr:
            s["host"] = host_hdr
        if p["mode"]:
            s["mode"] = p["mode"]
        if p["extra"]:
            try:
                extra = json.loads(p["extra"])
                if isinstance(extra, dict):
                    s["extra"] = extra
            except Exception:
                sys.stderr.write("предупреждение: параметр extra не разобран как JSON, пропущен\n")
        st["xhttpSettings" if net == "xhttp" else "splithttpSettings"] = s

    if p["security"] == "reality":
        rs = {
            "serverName": p["sni"] or p["host_header"] or p["host"],
            "fingerprint": p["fp"] or "chrome",
            "publicKey": p["pbk"],
            "shortId": p["sid"],
            "spiderX": p["spx"] or "/",
        }
        if p["pqv"]:
            rs["mldsa65Verify"] = p["pqv"]
        st["security"] = "reality"
        st["realitySettings"] = rs
    elif p["security"] == "tls":
        ts = {"serverName": p["sni"] or p["host_header"] or p["host"]}
        if p["fp"]:
            ts["fingerprint"] = p["fp"]
        if p["alpn"]:
            ts["alpn"] = p["alpn"]
        if p["allow_insecure"]:
            if o.get("core_family") == "legacy":
                ts["allowInsecure"] = True
            elif o.get("cert_pin"):
                ts["pinnedPeerCertSha256"] = o["cert_pin"]
            else:
                sys.stderr.write(
                    "предупреждение: в ссылке allowInsecure=1, но в новом Xray этот параметр\n"
                    "удалён. Не удалось получить отпечаток сертификата сервера — если у сервера\n"
                    "самоподписанный сертификат, соединение может не установиться.\n")
        if p["ech"]:
            ts["echConfigList"] = p["ech"]
        st["security"] = "tls"
        st["tlsSettings"] = ts
    else:
        st["security"] = "none"
    return st


def sniffing():
    return {"enabled": True, "destOverride": ["http", "tls", "quic"], "routeOnly": False}


def effective_flow(p, o):
    """Xray с flow=xtls-rprx-vision сам отклоняет UDP/443 (QUIC).
    Суффикс -udp443 — чисто клиентский флаг (сервер видит xtls-rprx-vision),
    без него QUIC/HTTP-3 через туннель работать не будет."""
    flow = p["flow"]
    if flow == "xtls-rprx-vision" and o.get("vision_udp443", True):
        return "xtls-rprx-vision-udp443"
    return flow


def build_config(p, o):
    server = p["host"]
    stream = build_stream(p, o)

    flow = effective_flow(p, o)
    user = {"id": p["uuid"], "encryption": p["encryption"] or "none"}
    if flow:
        user["flow"] = flow
    proxy_out = {
        "tag": "proxy",
        "protocol": "vless",
        "settings": {"vnext": [{"address": server, "port": p["port"], "users": [user]}]},
        "streamSettings": stream,
    }
    if o["mux"] and not flow:
        proxy_out["mux"] = {"enabled": True, "concurrency": 8}
    else:
        proxy_out["mux"] = {"enabled": False}

    inbounds = [
        {
            "tag": "socks-in", "listen": "127.0.0.1", "port": o["socks_port"],
            "protocol": "socks",
            "settings": {"auth": "noauth", "udp": True, "address": "127.0.0.1"},
            "sniffing": sniffing(),
        },
        {
            "tag": "http-in", "listen": "127.0.0.1", "port": o["http_port"],
            "protocol": "http",
            "settings": {"allowTransparent": False},
            "sniffing": sniffing(),
        },
        {
            "tag": "tproxy-in", "listen": "127.0.0.1", "port": o["tproxy_port"],
            "protocol": "dokodemo-door",
            "settings": {"network": "tcp,udp", "followRedirect": True},
            "streamSettings": {"sockopt": {"tproxy": "tproxy"}},
            "sniffing": sniffing(),
        },
    ]

    outbounds = [
        proxy_out,
        {"tag": "direct", "protocol": "freedom", "settings": {"domainStrategy": "UseIP"}},
        {"tag": "block", "protocol": "blackhole", "settings": {}},
        {"tag": "dns-out", "protocol": "dns", "settings": {}},
    ]

    rules = []
    direct_tags, proxy_tags = [], []
    for i, ip in enumerate(o["direct_dns"]):
        direct_tags.append("dns-direct-%d" % i)
    proxy_tags = ["dns-proxy-1", "dns-proxy-2"]
    # 1-2. Запросы самого встроенного DNS Xray: домен сервера — напрямую,
    #      остальное — DoH через туннель (порядок важен, чтобы не было петли).
    if direct_tags and not p["host_is_ip"]:
        rules.append({"type": "field", "inboundTag": direct_tags, "outboundTag": "direct"})
    rules.append({"type": "field", "inboundTag": proxy_tags, "outboundTag": "proxy"})
    # 3. Все DNS-запросы приложений — во встроенный DNS Xray (без утечек).
    rules.append({"type": "field", "port": "53", "outboundTag": "dns-out"})

    server_ips = [ip for ip in o["server_ips"] if ip]
    if not p["host_is_ip"]:
        rules.append({"type": "field", "domain": ["full:" + server], "outboundTag": "direct"})
    if server_ips:
        rules.append({"type": "field", "ip": server_ips, "outboundTag": "direct"})
    if o["exclude_lan"]:
        rules.append({"type": "field", "ip": PRIVATE4 + PRIVATE6, "outboundTag": "direct"})
    rules.append({"type": "field", "network": "tcp,udp", "outboundTag": "proxy"})

    dns_servers = []
    if not p["host_is_ip"]:
        for i, ip in enumerate(o["direct_dns"]):
            dns_servers.append({
                "tag": "dns-direct-%d" % i,
                "address": ip,
                "domains": ["full:" + server],
                "skipFallback": True,
            })
    dns_servers.append({"tag": "dns-proxy-1", "address": "https://1.1.1.1/dns-query",
                        "skipFallback": False})
    dns_servers.append({"tag": "dns-proxy-2", "address": "https://8.8.8.8/dns-query",
                        "skipFallback": False})

    log_cfg = {"loglevel": o["log_level"], "dnsLog": False}
    if o["access_log"]:
        log_cfg["access"] = os.path.join(o["log_dir"], "access.log")
        log_cfg["error"] = os.path.join(o["log_dir"], "error.log")

    return {
        "log": log_cfg,
        "dns": {"servers": dns_servers, "queryStrategy": "UseIP", "disableFallback": False},
        "inbounds": inbounds,
        "outbounds": outbounds,
        "routing": {"domainStrategy": "IPIfNonMatch", "rules": rules},
    }


def build_state(p, o, core_version, core_family):
    return {
        "schema": 1,
        "installed_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "link": p["link"],
        "name": p["name"],
        "server": p["host"],
        "server_port": p["port"],
        "server_is_ip": p["host_is_ip"],
        "server_ips": o["server_ips"],
        "network": p["network"],
        "security": p["security"],
        "sni": p["sni"] or p["host_header"],
        "flow": effective_flow(p, o),
        "flow_link": p["flow"],
        "core_version": core_version,
        "core_family": core_family,
        "socks_port": o["socks_port"],
        "http_port": o["http_port"],
        "tproxy_port": o["tproxy_port"],
        "exclude_lan": o["exclude_lan"],
        "ipv6_mode": o["ipv6_mode"],
        "direct_dns": o["direct_dns"],
        "mux": o["mux"],
        "log_level": o["log_level"],
        "access_log": o["access_log"],
        "watchdog": o["watchdog"],
        "svc_user": o["svc_user"],
        "svc_user_created": o["svc_user_created"],
        "exclude_users": o["exclude_users"],
        "fwmark": o["fwmark"],
        "rt_table": o["rt_table"],
    }


def env_bool(name, default=False):
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def read_opts():
    return {
        "socks_port": int(os.environ.get("VLESS_SOCKS_PORT", "10808")),
        "http_port": int(os.environ.get("VLESS_HTTP_PORT", "10809")),
        "tproxy_port": int(os.environ.get("VLESS_TPROXY_PORT", "12345")),
        "exclude_lan": env_bool("VLESS_EXCLUDE_LAN", True),
        "ipv6_mode": os.environ.get("VLESS_IPV6_MODE", "proxy"),
        "direct_dns": [x for x in re.split(r"[,\s]+", os.environ.get("VLESS_DIRECT_DNS", "1.1.1.1")) if x],
        "server_ips": [x for x in re.split(r"[,\s]+", os.environ.get("VLESS_SERVER_IPS", "")) if x],
        "exclude_users": [x for x in re.split(r"[,\s]+", os.environ.get("VLESS_EXCLUDE_USERS", "")) if x],
        "mux": env_bool("VLESS_MUX", False),
        "log_level": os.environ.get("VLESS_LOG_LEVEL", "warning"),
        "access_log": env_bool("VLESS_ACCESS_LOG", False),
        "watchdog": env_bool("VLESS_WATCHDOG", True),
        "log_dir": os.environ.get("VLESS_LOG_DIR", "/var/log/vless-tunnel"),
        "svc_user": os.environ.get("VLESS_SVC_USER", "vless"),
        "core_family": os.environ.get("VLESS_CORE_FAMILY", "modern"),
        "cert_pin": os.environ.get("VLESS_CERT_PIN", "").strip(),
        "fwmark": os.environ.get("VLESS_FWMARK", "0x1").strip() or "0x1",
        "rt_table": os.environ.get("VLESS_RT_TABLE", "100").strip() or "100",
        "svc_user_created": env_bool("VLESS_USER_CREATED", True),
        "vision_udp443": env_bool("VLESS_VISION_UDP443", True),
    }


def summary(p):
    fam = "legacy" if legacy_reasons(p) else "modern"
    lines = [
        "NETWORK=%s" % p["network"],
        "SECURITY=%s" % p["security"],
        "SERVER=%s" % p["host"],
        "SERVER_PORT=%d" % p["port"],
        "SERVER_IS_IP=%s" % ("true" if p["host_is_ip"] else "false"),
        "NAME=%s" % p["name"].replace("\n", " "),
        "SNI=%s" % (p["sni"] or p["host_header"]),
        "FLOW=%s" % p["flow"],
        "CORE_FAMILY=%s" % fam,
        "LEGACY_REASON=%s" % ("+".join(legacy_reasons(p))),
        "ALLOW_INSECURE=%s" % ("true" if p["allow_insecure"] else "false"),
    ]
    return "\n".join(lines)


def cmd_parse():
    if len(sys.argv) > 2:
        link = sys.argv[2]
    else:
        link = sys.stdin.read()
    p = parse_link(link)
    sys.stdout.write(summary(p) + "\n")


def cmd_make():
    link = os.environ.get("VLESS_LINK", "")
    p = parse_link(link)
    o = read_opts()
    core_version = os.environ.get("VLESS_CORE_VERSION", "")
    core_family = os.environ.get("VLESS_CORE_FAMILY", "modern")
    if p["flow"] == "xtls-rprx-vision" and effective_flow(p, o) != p["flow"]:
        sys.stderr.write("примечание: flow=xtls-rprx-vision заменён на xtls-rprx-vision-udp443,\n"
                         "иначе ядро отбрасывает UDP/443 и QUIC/HTTP-3 через туннель не работает\n"
                         "(отключить: --no-vision-udp443)\n")
    cfg = build_config(p, o)
    st = build_state(p, o, core_version, core_family)
    with open(os.environ["VLESS_OUT_CONFIG"], "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2, ensure_ascii=False)
        f.write("\n")
    with open(os.environ["VLESS_OUT_STATE"], "w", encoding="utf-8") as f:
        json.dump(st, f, indent=2, ensure_ascii=False)
        f.write("\n")
    sys.stdout.write(summary(p) + "\n")


def cmd_state_get():
    path, key = sys.argv[2], sys.argv[3]
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        sys.exit(0)
    cur = data
    for part in key.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            sys.exit(0)
    if isinstance(cur, list):
        print("\n".join(str(x) for x in cur))
    elif isinstance(cur, bool):
        print("true" if cur else "false")
    elif cur is None:
        sys.exit(0)
    else:
        print(cur)


def cmd_state_dump():
    path = sys.argv[2]
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        print("{}")
        return
    print(json.dumps(data, ensure_ascii=False))


def cmd_cert_pin():
    """Печатает SHA256-отпечатки (hex) сертификатов сервера для pinnedPeerCertSha256."""
    import hashlib, socket, ssl
    host, port, sni = sys.argv[2], int(sys.argv[3]), (sys.argv[4] if len(sys.argv) > 4 else "")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    pins = []
    try:
        with socket.create_connection((host, port), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni or host) as ss:
                der = ss.getpeercert(binary_form=True)
                if der:
                    pins.append(hashlib.sha256(der).hexdigest())
                try:
                    for cert in (ss.get_unverified_chain() or []):
                        try:
                            raw = cert.public_bytes()
                        except Exception:
                            continue
                        h = hashlib.sha256(raw).hexdigest()
                        if h not in pins:
                            pins.append(h)
                except Exception:
                    pass
    except Exception as exc:
        sys.stderr.write("не удалось получить сертификат %s:%s (%s)\n" % (host, port, exc))
        sys.exit(1)
    if not pins:
        sys.exit(1)
    sys.stdout.write(",".join(pins) + "\n")


def main():
    if len(sys.argv) < 2:
        die("не указана подкоманда")
    cmd = sys.argv[1]
    if cmd == "parse":
        cmd_parse()
    elif cmd == "make":
        cmd_make()
    elif cmd == "state-get":
        cmd_state_get()
    elif cmd == "state-dump":
        cmd_state_dump()
    elif cmd == "cert-pin":
        cmd_cert_pin()
    else:
        die("неизвестная подкоманда: %s" % cmd)


main()
PYEOF
}

state_get() { py_backend state-get "$STATE_FILE" "$1"; }

#-------------------------------------------------------------------------------
#  Определение архитектуры / зависимостей
#-------------------------------------------------------------------------------
core_asset_name() {
  case "$(uname -m)" in
    x86_64|amd64)   echo "Xray-linux-64.zip" ;;
    aarch64|arm64)  echo "Xray-linux-arm64-v8a.zip" ;;
    armv7l|armv7)   echo "Xray-linux-arm32-v7a.zip" ;;
    armv6l)         echo "Xray-linux-arm32-v6.zip" ;;
    i386|i686)      echo "Xray-linux-32.zip" ;;
    s390x)          echo "Xray-linux-s390x.zip" ;;
    *)              die "неподдерживаемая архитектура: $(uname -m)" ;;
  esac
}

ensure_deps() {
  local pkgs=() p rc=0
  for p in curl unzip python3; do have "$p" || pkgs+=("$p"); done
  have iptables || pkgs+=("iptables")
  have ip || pkgs+=("iproute2")
  if [ "${#pkgs[@]}" -gt 0 ]; then
    info "устанавливаю пакеты: ${pkgs[*]}"
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq || warn "apt-get update завершился с ошибкой"
    apt-get install -y -qq "${pkgs[@]}" || { err "не удалось установить пакеты: ${pkgs[*]}"; rc=1; }
  fi
  have visudo || warn "visudo не найден — проверка sudoers будет пропущена"
  # systemd проверяем последним: пакеты уже поставлены, и видно, что именно мешает
  if ! have systemctl; then
    err "systemd не найден — скрипт рассчитан на Ubuntu с systemd"
    rc=1
  fi
  return $rc
}

# Обязательные и необязательные зависимости: печатает таблицу.
# Возвращает 1, если чего-то обязательного не хватает.
deps_report() {
  local missing=0 c m
  log "${C_BLD}Обязательные:${C_RST}"
  for c in bash curl unzip python3 iptables ip6tables ip ss systemctl; do
    if have "$c"; then ok "  $c — есть"
    else err "  $c — ОТСУТСТВУЕТ"; missing=1; fi
  done
  log "${C_BLD}Необязательные (используются, если есть):${C_RST}"
  for c in modprobe sha256sum visudo zenity runuser nft systemd-analyze update-desktop-database; do
    if have "$c"; then log "  $c — есть"
    else warn "  $c — нет (не критично)"; fi
  done
  if have modinfo; then
    for m in xt_TPROXY nf_tproxy_ipv4; do
      if modinfo -F filename "$m" >/dev/null 2>&1; then log "  модуль $m — есть"
      else warn "  модуль $m — нет (прозрачный UDP/QUIC не заработает)"; missing=1; fi
    done
  fi
  return $missing
}

ensure_zenity() {
  have zenity && return 0
  info "устанавливаю zenity (для графической кнопки)"
  export DEBIAN_FRONTEND=noninteractive
  apt-get install -y -qq zenity >/dev/null 2>&1 || return 1
  have zenity
}

ensure_user() { # $1 = quiet (не печатать про уже существующего пользователя)
  if id -u "$SVC_USER" >/dev/null 2>&1; then
    USER_CREATED="no"
    if [ "${1:-}" != "quiet" ]; then
      info "системный пользователь $SVC_USER уже существует — использую его (удалять его скрипт не будет)"
    fi
    return 0
  fi
  useradd --system --no-create-home --home-dir "$PREFIX_DIR" \
          --shell /usr/sbin/nologin --comment "vless-tunnel service user" "$SVC_USER" \
    || die "не удалось создать системного пользователя $SVC_USER"
  USER_CREATED="yes"
  ok "создан системный пользователь $SVC_USER"
}

ensure_dirs() {
  install -d -m 0755 "$PREFIX_DIR" "$BIN_DIR"
  install -d -m 0750 -o root -g "$SVC_USER" "$ETC_DIR"
  install -d -m 0750 -o "$SVC_USER" -g "$SVC_USER" "$LOG_DIR"
}

install_self() {
  local src
  src=$(readlink -f "$0")
  if [ "$src" != "$SELF_PATH" ]; then
    install -m 0755 -o root -g root "$src" "$SELF_PATH" || die "не удалось установить $SELF_PATH"
    ok "скрипт установлен в $SELF_PATH"
  fi
}

#-------------------------------------------------------------------------------
#  Установка ядра Xray
#-------------------------------------------------------------------------------
resolve_latest_core_version() {
  local url="${OPT_GH_PROXY:+$OPT_GH_PROXY/}https://github.com/XTLS/Xray-core/releases/latest"
  local eff
  eff=$(curl -fsSLI -o /dev/null -w '%{url_effective}' --max-time 30 "$url" 2>/dev/null || true)
  case "$eff" in
    */tag/*) printf '%s\n' "${eff##*/tag/}" ;;
    *) printf '%s\n' "" ;;
  esac
}

download_url_for() { # $1 = версия, $2 = файл
  local base="https://github.com/XTLS/Xray-core/releases/download/$1/$2"
  if [ -n "$OPT_GH_PROXY" ]; then printf '%s/%s\n' "${OPT_GH_PROXY%/}" "$base"; else printf '%s\n' "$base"; fi
}

install_core_from_file() {
  local src="$1"
  require_root
  ensure_user quiet; ensure_dirs
  [ -f "$src" ] || die "файл не найден: $src"
  install -m 0755 -o root -g root "$src" "$BIN_DIR/xray-custom"
  ln -sf "xray-custom" "$BIN_DIR/xray"
  "$BIN_DIR/xray" version >/dev/null 2>&1 || die "файл $src не является рабочим бинарём Xray"
  ok "ядро установлено из файла: $src"
}

install_core() { # $1 = версия (vX.Y.Z) или "latest"
  local want="$1" ver="$1" asset url dgst_url tmpd hash want_hash
  require_root
  ensure_user quiet; ensure_dirs
  if [ "$want" = "latest" ] || [ -z "$want" ]; then
    ver=$(resolve_latest_core_version)
    if [ -z "$ver" ]; then
      # GitHub недоступен — если рабочее ядро уже стоит, НЕ ломаем установку
      if [ -x "$BIN_DIR/xray" ] && "$BIN_DIR/xray" version >/dev/null 2>&1; then
        warn "не удалось узнать последнюю версию Xray (GitHub недоступен) — оставляю установленное ядро $(core_version_string)"
        return 0
      fi
      die "не удалось определить последнюю версию Xray (GitHub недоступен?). Укажите --core-version, --from-file или --gh-proxy"
    fi
    info "последняя версия Xray: $ver"
  fi
  asset=$(core_asset_name)
  if [ -x "$BIN_DIR/xray-$ver" ] && "$BIN_DIR/xray-$ver" version >/dev/null 2>&1 \
     && [ "${FORCE_CORE:-no}" != "yes" ]; then
    ln -sf "xray-$ver" "$BIN_DIR/xray"
    ok "ядро $ver уже установлено"
    return 0
  fi
  url=$(download_url_for "$ver" "$asset")
  tmpd=$(mktemp -d)
  info "скачиваю $asset ($ver)"
  if ! curl -fL --retry 3 --connect-timeout 20 -o "$tmpd/$asset" "$url"; then
    rm -rf "$tmpd"
    die "не удалось скачать ядро: $url
Подсказка: используйте --gh-proxy https://ваш-прокси/ или --from-file /путь/к/xray"
  fi
  dgst_url="$url.dgst"
  if curl -fsL --max-time 30 -o "$tmpd/$asset.dgst" "$dgst_url" 2>/dev/null; then
    want_hash=$(awk -F'= ' '/^SHA2-256/{print $2; exit}' "$tmpd/$asset.dgst" | tr -d '[:space:]')
    if [ -n "$want_hash" ]; then
      hash=$(sha256sum "$tmpd/$asset" | awk '{print $1}')
      if [ "$hash" != "$want_hash" ]; then
        rm -rf "$tmpd"
        die "контрольная сумма не совпала! ожидалось $want_hash, получено $hash"
      fi
      ok "контрольная сумма SHA-256 проверена"
    fi
  else
    warn "файл .dgst недоступен — контрольная сумма не проверена"
  fi
  unzip -oq "$tmpd/$asset" -d "$tmpd/extract" || { rm -rf "$tmpd"; die "не удалось распаковать архив ядра"; }
  [ -f "$tmpd/extract/xray" ] || { rm -rf "$tmpd"; die "в архиве нет бинарника xray"; }
  install -m 0755 -o root -g root "$tmpd/extract/xray" "$BIN_DIR/xray-$ver"
  ln -sf "xray-$ver" "$BIN_DIR/xray"
  rm -rf "$tmpd"
  "$BIN_DIR/xray" version | head -1
  ok "ядро Xray $ver установлено в $BIN_DIR/xray"
}

core_version_string() { "$BIN_DIR/xray" version 2>/dev/null | head -1 | awk '{print $2}'; }

validate_config() {
  local out
  if ! out=$("$BIN_DIR/xray" run -test -c "$CONFIG_FILE" 2>&1); then
    printf '%s\n' "$out" >&2
    return 1
  fi
  return 0
}

#-------------------------------------------------------------------------------
#  Сборка config.json / state.json
#-------------------------------------------------------------------------------
# Заполняет глобальные переменные: SUM_NETWORK, SUM_SECURITY, SUM_SERVER,
# SUM_PORT, SUM_SNI, SUM_NAME, SUM_CORE_FAMILY, SUM_LEGACY_REASON
link_summary() {
  local link="$1" out
  if ! out=$(py_backend parse "$link"); then return 1; fi
  SUM_NETWORK=""; SUM_SECURITY=""; SUM_SERVER=""; SUM_PORT=""
  SUM_SNI=""; SUM_NAME=""; SUM_CORE_FAMILY="modern"; SUM_LEGACY_REASON=""
  SUM_ALLOW_INSECURE="false"
  while IFS='=' read -r k v; do
    case "$k" in
      NETWORK) SUM_NETWORK="$v" ;;
      SECURITY) SUM_SECURITY="$v" ;;
      SERVER) SUM_SERVER="$v" ;;
      SERVER_PORT) SUM_PORT="$v" ;;
      SNI) SUM_SNI="$v" ;;
      NAME) SUM_NAME="$v" ;;
      CORE_FAMILY) SUM_CORE_FAMILY="$v" ;;
      LEGACY_REASON) SUM_LEGACY_REASON="$v" ;;
      ALLOW_INSECURE) SUM_ALLOW_INSECURE="$v" ;;
    esac
  done <<< "$out"
  [ -n "$SUM_SERVER" ]
}

compute_cert_pin() { # $1=хост $2=порт $3=sni → отпечатки сертификатов (или пусто)
  py_backend cert-pin "$1" "$2" "$3" 2>/dev/null || true
}

prepare_cert_pin() { # $1 = семейство ядра; использует SUM_* из link_summary
  CALC_CERT_PIN=""
  [ "$SUM_ALLOW_INSECURE" = "true" ] || return 0
  [ "$1" = "legacy" ] && return 0
  CALC_CERT_PIN=$(compute_cert_pin "$SUM_SERVER" "$SUM_PORT" "${SUM_SNI:-$SUM_SERVER}")
  if [ -n "$CALC_CERT_PIN" ]; then
    ok "получен отпечаток TLS-сертификата сервера (allowInsecure → pinnedPeerCertSha256)"
  else
    warn "в ссылке allowInsecure=1, но отпечаток сертификата получить не удалось"
    warn "в новом Xray allowInsecure удалён: при самоподписанном сертификате соединение может не установиться"
  fi
  return 0
}

is_ip_addr() {
  python3 -c 'import ipaddress,sys
try:
    ipaddress.ip_address(sys.argv[1])
except Exception:
    sys.exit(1)' "$1" 2>/dev/null
}

resolve_server_ips() { # $1 = хост
  local host="$1"
  if [ -z "$host" ]; then return 0; fi
  if is_ip_addr "$host"; then printf '%s\n' "$host"; return 0; fi
  { getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}'
    getent ahostsv6 "$host" 2>/dev/null | awk '{print $1}'; } | sort -u | paste -sd, -
}

choose_core_version() { # $1 = core family (modern|legacy)
  if [ -n "$OPT_CORE_VERSION" ]; then printf '%s\n' "$OPT_CORE_VERSION"; return 0; fi
  if [ "$1" = "legacy" ]; then printf '%s\n' "$LEGACY_CORE_VERSION"; else printf '%s\n' "latest"; fi
}

build_config_files_to() { # $1=ссылка $2=версия ядра $3=семейство $4=out config $5=out state
  local link="$1" core_ver="$2" core_fam="$3" out_cfg="$4" out_state="$5"
  local tmpc tmps summary ips
  ips=$(resolve_server_ips "$SUM_SERVER" || true)
  tmpc=$(mktemp) || die "mktemp"
  tmps=$(mktemp) || die "mktemp"
  if ! summary=$(VLESS_LINK="$link" \
      VLESS_SOCKS_PORT="$OPT_SOCKS_PORT" \
      VLESS_HTTP_PORT="$OPT_HTTP_PORT" \
      VLESS_TPROXY_PORT="$OPT_TPROXY_PORT" \
      VLESS_EXCLUDE_LAN="$OPT_EXCLUDE_LAN" \
      VLESS_IPV6_MODE="$OPT_IPV6_MODE" \
      VLESS_DIRECT_DNS="$OPT_DIRECT_DNS" \
      VLESS_SERVER_IPS="$ips" \
      VLESS_EXCLUDE_USERS="$OPT_EXCLUDE_USERS" \
      VLESS_MUX="$OPT_MUX" \
      VLESS_LOG_LEVEL="$OPT_LOG_LEVEL" \
      VLESS_ACCESS_LOG="$OPT_ACCESS_LOG" \
      VLESS_WATCHDOG="$OPT_WATCHDOG" \
      VLESS_LOG_DIR="$LOG_DIR" \
      VLESS_SVC_USER="$SVC_USER" \
      VLESS_USER_CREATED="$USER_CREATED" \
      VLESS_FWMARK="${FWMARK:-0x1}" \
      VLESS_RT_TABLE="${RT_TABLE:-100}" \
      VLESS_CORE_VERSION="$core_ver" \
      VLESS_CORE_FAMILY="$core_fam" \
      VLESS_CERT_PIN="${CALC_CERT_PIN:-}" \
      VLESS_VISION_UDP443="$OPT_VISION_UDP443" \
      VLESS_OUT_CONFIG="$tmpc" \
      VLESS_OUT_STATE="$tmps" \
      py_backend make); then
    rm -f "$tmpc" "$tmps"
    return 1
  fi
  install -m 0640 -o root -g "$SVC_USER" "$tmpc" "$out_cfg"
  install -m 0600 -o root -g root "$tmps" "$out_state"
  rm -f "$tmpc" "$tmps"
  printf '%s\n' "$summary"
}

build_config_files() { # $1=ссылка $2=версия ядра $3=семейство → в ETC_DIR
  build_config_files_to "$1" "$2" "$3" "$CONFIG_FILE" "$STATE_FILE"
}

apply_link() { # $1 = ссылка; $2 = restart|start|none (по умолчанию restart)
  local link="$1" action="${2:-restart}" core_ver core_fam bak_cfg bak_state
  link_summary "$link" || die "не удалось разобрать ссылку vless://"
  core_fam="$SUM_CORE_FAMILY"
  if [ "$core_fam" = "legacy" ]; then
    warn "для этой ссылки нужны legacy-транспорты (${SUM_LEGACY_REASON})"
    warn "будет использовано ядро Xray $LEGACY_CORE_VERSION (в новых версиях эти транспорты удалены)"
  fi
  core_ver=$(choose_core_version "$core_fam")
  install_core "$core_ver"
  core_ver=$(core_version_string)
  prepare_cert_pin "$core_fam"
  read_net_params   # сохраняем прежние fwmark/таблицу (или подбираем свободные)
  bak_cfg=""; bak_state=""
  [ -f "$CONFIG_FILE" ] && { bak_cfg=$(mktemp); cp -a "$CONFIG_FILE" "$bak_cfg"; }
  [ -f "$STATE_FILE" ] && { bak_state=$(mktemp); cp -a "$STATE_FILE" "$bak_state"; }
  step "собираю конфигурацию Xray"
  build_config_files "$link" "$core_ver" "$core_fam" >/dev/null || {
    rm -f "$bak_cfg" "$bak_state"; die "не удалось собрать config.json (см. сообщение выше)"; }
  chmod 0640 "$CONFIG_FILE"; chown root:"$SVC_USER" "$CONFIG_FILE"
  if ! validate_config; then
    [ -n "$bak_cfg" ] && install -m 0640 -o root -g "$SVC_USER" "$bak_cfg" "$CONFIG_FILE"
    [ -n "$bak_state" ] && install -m 0600 -o root -g root "$bak_state" "$STATE_FILE"
    rm -f "$bak_cfg" "$bak_state"
    die "ядро Xray отвергло конфигурацию (см. вывод выше)"
  fi
  ok "конфигурация проверена ядром Xray"

  case "$action" in
    restart)
      if svc_active; then
        systemctl restart "$SVC_NAME.service" || die "не удалось перезапустить службу"
        sleep 1
        svc_active || { err "служба не поднялась, смотрите: journalctl -u $SVC_NAME -n 50"; return 1; }
        if ! tunnel_works; then
          warn "новый сервер не отвечает — возвращаю прежнюю конфигурацию"
          [ -n "$bak_cfg" ] && install -m 0640 -o root -g "$SVC_USER" "$bak_cfg" "$CONFIG_FILE"
          [ -n "$bak_state" ] && install -m 0600 -o root -g root "$bak_state" "$STATE_FILE"
          rm -f "$bak_cfg" "$bak_state"
          systemctl restart "$SVC_NAME.service" 2>/dev/null || true
          return 1
        fi
      fi ;;
    start)
      systemctl restart "$SVC_NAME.service" 2>/dev/null || systemctl start "$SVC_NAME.service" || true
      sleep 1 ;;
  esac
  rm -f "$bak_cfg" "$bak_state"
  return 0
}

#-------------------------------------------------------------------------------
#  Прозрачное проксирование: правила iptables + policy routing
#-------------------------------------------------------------------------------
CHAIN_MARK="VLESS_MARK"      # mangle: MARK UDP
CHAIN_TPROXY="VLESS_TPROXY"  # mangle: TPROXY UDP
CHAIN_V6BLOCK="VLESS_V6BLOCK"
FWMARK="0x1"
RT_TABLE="100"

ipt() { iptables "$@"; }
ipt6() { ip6tables "$@"; }

add_rule() { # add_rule <ipt|ipt6> <таблица> <цепочка> <правило...>
  local tool="$1" table="$2" chain="$3"; shift 3
  if ! "$tool" -t "$table" -C "$chain" "$@" 2>/dev/null; then
    "$tool" -t "$table" -A "$chain" "$@" || die "$tool -t $table -A $chain $* — не удалось"
  fi
}

new_chain() { # new_chain <ipt|ipt6> <таблица> <цепочка>
  local tool="$1" table="$2" chain="$3"
  "$tool" -t "$table" -N "$chain" 2>/dev/null || true
  "$tool" -t "$table" -F "$chain" 2>/dev/null || true
}

del_chain_everywhere() { # del_chain_everywhere <ipt|ipt6> <таблица> <цепочка>
  local tool="$1" table="$2" chain="$3" parent
  for parent in OUTPUT PREROUTING INPUT FORWARD; do
    while "$tool" -t "$table" -C "$parent" -j "$chain" 2>/dev/null; do
      "$tool" -t "$table" -D "$parent" -j "$chain" 2>/dev/null || break
    done
  done
  "$tool" -t "$table" -F "$chain" 2>/dev/null || true
  "$tool" -t "$table" -X "$chain" 2>/dev/null || true
}

tproxy_up() {
  local tproxy_port svc_uid exclude_lan ipv6_mode
  local -a server_ips=()
  if ! [ -f "$STATE_FILE" ]; then
    warn "нет $STATE_FILE — правила не применяю"
    return 0
  fi
  tproxy_port=$(state_get tproxy_port); tproxy_port="${tproxy_port:-$DEF_TPROXY_PORT}"
  exclude_lan=$(state_get exclude_lan); exclude_lan="${exclude_lan:-true}"
  ipv6_mode=$(state_get ipv6_mode); ipv6_mode="${ipv6_mode:-proxy}"
  svc_uid=$(uid_of_user "$SVC_USER")
  local -a skip_uids=("$svc_uid")
  local exu exuid
  while IFS= read -r exu; do
    [ -n "$exu" ] || continue
    exuid=$(id -u "$exu" 2>/dev/null || true)
    if [ -n "$exuid" ] && [ "$exuid" != "$svc_uid" ]; then skip_uids+=("$exuid"); fi
  done < <(state_get exclude_users || true)
  while IFS= read -r line; do [ -n "$line" ] && server_ips+=("$line"); done < <(state_get server_ips || true)
  # переразрешаем домен сервера, чтобы исключения были актуальны
  local srv; srv=$(state_get server || true)
  if [ -n "$srv" ]; then
    local fresh; fresh=$(resolve_server_ips "$srv" || true)
    if [ -n "$fresh" ]; then
      IFS=',' read -r -a server_ips <<< "$fresh"
    fi
  fi

  modprobe -q xt_TPROXY 2>/dev/null || true
  modprobe -q nf_tproxy_ipv4 2>/dev/null || true
  modprobe -q nf_tproxy_ipv6 2>/dev/null || true

  # --- policy routing для помеченных (UDP) пакетов -------------------------
  # fwmark/таблица берутся из state; если их там нет — подбираются свободные,
  # чтобы не сломать чужой policy routing (sing-box/xray/VPN и т.п.)
  read_net_params
  local added=""
  if ip rule show 2>/dev/null | grep -Eq "fwmark ${FWMARK}([^0-9a-f]|\$)"; then
    : # правило уже есть (возможно, наше с прошлого запуска) — не трогаем
  else
    if ip rule add fwmark "$FWMARK" table "$RT_TABLE" 2>/dev/null; then
      added="rule"
    else
      warn "не удалось добавить ip rule fwmark $FWMARK table $RT_TABLE"
    fi
  fi
  if ip route show table "$RT_TABLE" 2>/dev/null | grep -q '^local default dev lo'; then
    :
  else
    if ip route add local default dev lo table "$RT_TABLE" 2>/dev/null \
       || ip route add local 0.0.0.0/0 dev lo table "$RT_TABLE" 2>/dev/null; then
      added="${added:+$added,}route"
    else
      warn "не удалось добавить маршрут local default в таблицу $RT_TABLE"
    fi
  fi
  [ -n "$added" ] && write_rules_marker

  # --- IPv4: только mangle (MARK в OUTPUT + TPROXY в PREROUTING) ----------
  # TCP тоже через TPROXY (при sockopt.tproxy ядро берёт адрес из LocalAddr(),
  # поэтому nat/REDIRECT даёт петлю "loopback connection detected")

  new_chain ipt mangle "$CHAIN_MARK"
  for exuid in "${skip_uids[@]}"; do
    add_rule ipt mangle "$CHAIN_MARK" -m owner --uid-owner "$exuid" -j RETURN
  done
  add_rule ipt mangle "$CHAIN_MARK" -m mark --mark "$FWMARK" -j RETURN
  for ip in "${server_ips[@]}"; do
    [ -n "$ip" ] && add_rule ipt mangle "$CHAIN_MARK" -d "$ip" -j RETURN
  done
  add_rule ipt mangle "$CHAIN_MARK" -p tcp --dport 53 -j MARK --set-mark "$FWMARK"
  add_rule ipt mangle "$CHAIN_MARK" -p udp --dport 53 -j MARK --set-mark "$FWMARK"
  if [ "$exclude_lan" = "true" ]; then
    local cidr
    for cidr in $PRIVATE_CIDRS_V4; do
      add_rule ipt mangle "$CHAIN_MARK" -d "$cidr" -j RETURN
    done
  fi
  add_rule ipt mangle "$CHAIN_MARK" -p tcp -j MARK --set-mark "$FWMARK"
  add_rule ipt mangle "$CHAIN_MARK" -p udp -j MARK --set-mark "$FWMARK"
  add_rule ipt mangle OUTPUT -j "$CHAIN_MARK"

  new_chain ipt mangle "$CHAIN_TPROXY"
  add_rule ipt mangle "$CHAIN_TPROXY" -p tcp -m mark --mark "$FWMARK" \
    -j TPROXY --on-ip 127.0.0.1 --on-port "$tproxy_port" --tproxy-mark "$FWMARK"
  add_rule ipt mangle "$CHAIN_TPROXY" -p udp -m mark --mark "$FWMARK" \
    -j TPROXY --on-ip 127.0.0.1 --on-port "$tproxy_port" --tproxy-mark "$FWMARK"
  add_rule ipt mangle PREROUTING -j "$CHAIN_TPROXY"

  # --- IPv6 ---------------------------------------------------------------
  local v6_ok="yes"
  have ip6tables || v6_ok="no"
  [ -f /proc/net/if_inet6 ] || v6_ok="no"
  if [ "$ipv6_mode" = "block" ] && [ "$v6_ok" = "yes" ]; then
    new_chain ipt6 filter "$CHAIN_V6BLOCK"
    add_rule ipt6 filter "$CHAIN_V6BLOCK" -o lo -j RETURN
    add_rule ipt6 filter "$CHAIN_V6BLOCK" -d ::1/128 -j RETURN
    add_rule ipt6 filter "$CHAIN_V6BLOCK" -d fe80::/10 -j RETURN
    add_rule ipt6 filter "$CHAIN_V6BLOCK" -d fc00::/7 -j RETURN
    add_rule ipt6 filter "$CHAIN_V6BLOCK" -j REJECT --reject-with icmp6-adm-prohibited
    add_rule ipt6 filter OUTPUT -j "$CHAIN_V6BLOCK"
  elif [ "$v6_ok" != "yes" ]; then
    warn "IPv6 недоступен или ip6tables отсутствует — правила IPv6 пропущены"
  else
    local added6=""
    if ip -6 rule show 2>/dev/null | grep -Eq "fwmark ${FWMARK}([^0-9a-f]|\$)"; then
      :
    elif ip -6 rule add fwmark "$FWMARK" table "$RT_TABLE" 2>/dev/null; then
      added6="rule"
    fi
    if ip -6 route show table "$RT_TABLE" 2>/dev/null | grep -q '^local default dev lo'; then
      :
    elif ip -6 route add local default dev lo table "$RT_TABLE" 2>/dev/null \
      || ip -6 route add local ::/0 dev lo table "$RT_TABLE" 2>/dev/null; then
      added6="${added6:+$added6,}route"
    fi
    [ -n "$added6" ] && write_rules_marker

    # TCP через TPROXY (см. комментарий выше)

    new_chain ipt6 mangle "$CHAIN_MARK"
    for exuid in "${skip_uids[@]}"; do
      add_rule ipt6 mangle "$CHAIN_MARK" -m owner --uid-owner "$exuid" -j RETURN
    done
    add_rule ipt6 mangle "$CHAIN_MARK" -m mark --mark "$FWMARK" -j RETURN
    for ip in "${server_ips[@]}"; do
      case "$ip" in *:*) add_rule ipt6 mangle "$CHAIN_MARK" -d "$ip" -j RETURN ;; esac
    done
    add_rule ipt6 mangle "$CHAIN_MARK" -p tcp --dport 53 -j MARK --set-mark "$FWMARK"
    add_rule ipt6 mangle "$CHAIN_MARK" -p udp --dport 53 -j MARK --set-mark "$FWMARK"
    if [ "$exclude_lan" = "true" ]; then
      local cidr6
      for cidr6 in $PRIVATE_CIDRS_V6; do
        add_rule ipt6 mangle "$CHAIN_MARK" -d "$cidr6" -j RETURN
      done
    fi
    add_rule ipt6 mangle "$CHAIN_MARK" -p tcp -j MARK --set-mark "$FWMARK"
    add_rule ipt6 mangle "$CHAIN_MARK" -p udp -j MARK --set-mark "$FWMARK"
    add_rule ipt6 mangle OUTPUT -j "$CHAIN_MARK"

    new_chain ipt6 mangle "$CHAIN_TPROXY"
    add_rule ipt6 mangle "$CHAIN_TPROXY" -p tcp -m mark --mark "$FWMARK" \
      -j TPROXY --on-ip ::1 --on-port "$tproxy_port" --tproxy-mark "$FWMARK"
    add_rule ipt6 mangle "$CHAIN_TPROXY" -p udp -m mark --mark "$FWMARK" \
      -j TPROXY --on-ip ::1 --on-port "$tproxy_port" --tproxy-mark "$FWMARK"
    add_rule ipt6 mangle PREROUTING -j "$CHAIN_TPROXY"
  fi
  return 0
}

tproxy_down() {
  # Важно: iptables/IPv6-цепочки удаляем всегда (они наши по имени), а вот
  # policy routing (fwmark/таблица) — только если это действительно наши записи,
  # чтобы не сломать чужой sing-box/xray/VPN, использующий те же fwmark/таблицу.
  local own="no" mf="" rt=""
  if [ -f "$RULES_MARKER" ]; then
    own="yes"
    mf=$(marker_value FWMARK)
    rt=$(marker_value RT_TABLE)
  fi
  read_net_params
  [ -n "$mf" ] && FWMARK="$mf"
  [ -n "$rt" ] && RT_TABLE="$rt"

  del_chain_everywhere ipt mangle "$CHAIN_MARK"
  del_chain_everywhere ipt mangle "$CHAIN_TPROXY"
  del_chain_everywhere ipt6 mangle "$CHAIN_MARK"
  del_chain_everywhere ipt6 mangle "$CHAIN_TPROXY"
  del_chain_everywhere ipt6 filter "$CHAIN_V6BLOCK"

  if [ "$own" != "yes" ]; then
    warn "policy routing (fwmark/таблица) не тронут: записи созданы не этим скриптом"
    return 0
  fi
  while ip rule show 2>/dev/null | grep -Eq "fwmark ${FWMARK}([^0-9a-f]|\$)"; do
    ip rule del fwmark "$FWMARK" table "$RT_TABLE" 2>/dev/null || break
  done
  while ip route show table "$RT_TABLE" 2>/dev/null | grep -q '^local default dev lo'; do
    ip route del local default dev lo table "$RT_TABLE" 2>/dev/null || break
  done
  while ip -6 rule show 2>/dev/null | grep -Eq "fwmark ${FWMARK}([^0-9a-f]|\$)"; do
    ip -6 rule del fwmark "$FWMARK" table "$RT_TABLE" 2>/dev/null || break
  done
  while ip -6 route show table "$RT_TABLE" 2>/dev/null | grep -q '^local default dev lo'; do
    ip -6 route del local default dev lo table "$RT_TABLE" 2>/dev/null || break
  done
  clear_rules_marker
  return 0
}

#-------------------------------------------------------------------------------
#  systemd / sudoers / desktop
#-------------------------------------------------------------------------------
write_service_units() {
  cat > "$SVC_UNIT" <<EOF
[Unit]
Description=VLESS Tunnel — прозрачное проксирование всего трафика (Xray-core)
Documentation=file:$SELF_PATH
After=network-online.target nss-lookup.target
Wants=network-online.target
StartLimitIntervalSec=0

[Service]
Type=simple
User=$SVC_USER
Group=$SVC_USER
ExecStartPre=+$SELF_PATH _tproxy up
ExecStart=$BIN_DIR/xray run -c $CONFIG_FILE
ExecStopPost=+$SELF_PATH _tproxy down
Restart=on-failure
RestartSec=3
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
LimitNOFILE=1048576
LogsDirectory=$(basename "$LOG_DIR")
LogsDirectoryMode=0750
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
  cat > "$WD_UNIT" <<EOF
[Unit]
Description=Проверка и восстановление правил vless-tunnel
After=${SVC_NAME}.service

[Service]
Type=oneshot
ExecStart=$SELF_PATH ensure
EOF
  cat > "$WD_TIMER" <<EOF
[Unit]
Description=Периодическая проверка правил vless-tunnel

[Timer]
OnBootSec=2min
OnUnitActiveSec=1min
AccuracySec=10s
Unit=${SVC_NAME}-watchdog.service

[Install]
WantedBy=timers.target
EOF
  chmod 0644 "$SVC_UNIT" "$WD_UNIT" "$WD_TIMER"
  ok "systemd-юниты записаны"
}

write_sudoers() {
  local users="$1" u
  [ -n "$users" ] || { warn "не удалось определить пользователя для NOPASSWD (используйте --allow-user ИМЯ)"; return 0; }
  {
    echo "# Управление $APP без пароля sudo. Создано автоматически."
    echo "# Удалить: sudo rm $SUDOERS_FILE"
    for u in ${users//,/ }; do
      printf '%s ALL=(root) NOPASSWD: %s menu, %s on, %s off, %s toggle, %s restart, %s status, %s status --json, %s test, %s logs, %s logs --lines *, %s set-link, %s set-link --stdin, %s set-link --link-stdin, %s self-update, %s autostart, %s autostart on, %s autostart off, %s doctor, %s update-core, %s uninstall, %s uninstall --yes\n' \
        "$u" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH" "$SELF_PATH"
    done
  } > "$SUDOERS_FILE"
  chown root:root "$SUDOERS_FILE"
  chmod 0440 "$SUDOERS_FILE"
  if have visudo; then
    visudo -cf "$SUDOERS_FILE" >/dev/null 2>&1 || { rm -f "$SUDOERS_FILE"; die "ошибка в $SUDOERS_FILE — файл удалён"; }
  fi
  ok "правило sudo без пароля добавлено для: $users"
}

write_desktop_file() {
  cat > "$DESKTOP_FILE" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=VLESS Tunnel
Name[ru]=VLESS Tunnel (прокси всего трафика)
Comment=Включить/выключить прозрачный туннель VLESS
Comment[en]=Toggle transparent VLESS tunnel
Exec=$SELF_PATH gui
Icon=network-vpn
Terminal=false
Categories=Network;Security;
Keywords=vpn;proxy;vless;xray;quic;
StartupNotify=true
EOF
  chmod 0644 "$DESKTOP_FILE"
  have update-desktop-database && update-desktop-database >/dev/null 2>&1 || true
  ok "ярлык в меню приложений: $DESKTOP_FILE"
}

remove_sudoers() {
  rm -f "$SUDOERS_FILE"
  local f="/etc/sudoers.d/90-vless-test"
  if [ -f "$f" ] && grep -q "vless-tunnel" "$f" 2>/dev/null; then
    rm -f "$f"
    ok "временное правило /etc/sudoers.d/90-vless-test тоже удалено"
  fi
  ok "правило sudoers удалено"
}
remove_desktop_file() { rm -f "$DESKTOP_FILE"; ok "ярлык приложения удалён"; }

#-------------------------------------------------------------------------------
#  Команды
#-------------------------------------------------------------------------------
print_help() {
  cat <<EOF
${C_BLD}$APP $APP_VERSION${C_RST} — прозрачный туннель VLESS (Xray-core) для Ubuntu

${C_BLD}Использование:${C_RST}
  $APP                     установка (если не установлено) или меню управления
  sudo $APP install [опции]    установка с нуля
  $APP on | off | toggle   включить / выключить / переключить туннель
  $APP restart             перезапустить
  $APP status [--json]     состояние туннеля
  $APP test                проверка соединения (HTTP, SOCKS, прозрачный TCP и UDP/QUIC)
  $APP logs [--lines N]    последние строки журнала
  $APP set-link [--stdin]  сменить сервер (вставить новую ссылку vless://)
  $APP gui                 графическая кнопка (zenity)
  $APP update-core         переустановить/обновить ядро Xray
  $APP autostart on|off    включить/выключить автозапуск при загрузке
  $APP deps                проверить зависимости (--install — доустановить)
  $APP doctor              диагностика окружения
  sudo $APP sudoers        переустановить правило «без пароля sudo» для текущего пользователя
  sudo $APP uninstall      удалить туннель

${C_BLD}Опции установки:${C_RST}
  --link URL           ссылка vless:// (иначе будет запрошена)
  --link-stdin         прочитать ссылку из stdin
  -y, --yes            отвечать «да» на все вопросы (неинтерактивно)
  --socks-port N       локальный SOCKS5-порт        (по умолчанию $DEF_SOCKS_PORT)
  --http-port N        локальный HTTP-прокси порт   (по умолчанию $DEF_HTTP_PORT)
  --tproxy-port N      внутренний порт TPROXY       (по умолчанию $DEF_TPROXY_PORT)
  --proxy-lan          заворачивать в туннель и локальные сети (по умолчанию — нет)
  --block-ipv6         блокировать IPv6 вместо проксирования
  --direct-dns LIST    DNS для домена сервера (по умолчанию 1.1.1.1,8.8.8.8)
  --core-version V     версия ядра Xray (например v26.9.9 или v1.8.24)
  --from-file PATH     установить ядро из локального файла
  --gh-proxy URL       зеркало GitHub (напр. https://ghproxy.net/)
  --allow-user U[,U]   кому разрешить управление без пароля sudo
  --log-level LVL      warning|info|debug|error
  --access-log         включить access-лог
  --exclude-user U[,U] не перехватывать трафик этих пользователей (напр. свой старый
                       xray/sing-box клиент: --exclude-user xray)
  --no-vision-udp443   не добавлять -udp443 к flow=xtls-rprx-vision (по умолчанию
                       добавляется, иначе QUIC/HTTP-3 через туннель не пойдёт)
  --mux                включить Mux (несовместимо с flow=xtls-rprx-vision)
  --no-watchdog        не ставить таймер автовосстановления правил
  --autostart          включить автозапуск при загрузке (по умолчанию НЕ включается:
                       туннель поднимается только вручную или кнопкой)
  --no-autostart       то же самое (оставлено для совместимости)
  --keep-config        при удалении сохранить конфиг и ядро
  --keep-user          при удалении оставить системного пользователя $SVC_USER
  --force              переустановить принудительно
  --dry-run            только разобрать ссылку и собрать конфиг, ничего не менять
  --no-start           установить, но НЕ запускать службу (интернет точно не тронем;
                       запуск потом: vless-tunnel on)

${C_BLD}Примеры:${C_RST}
  sudo $APP install --link 'vless://uuid@example.com:443?type=xhttp&mode=stream-one&security=reality&pbk=...&sni=...&alpn=h3'
  $APP set-link          # вставить новую ссылку (пароль sudo не спросит)
  $APP toggle && $APP test
EOF
}

ask_link() {
  local link=""
  if [ "$OPT_LINK_STDIN" = "yes" ]; then
    # читаем весь поток: ссылка может быть в середине вставленного текста
    link=$(cat 2>/dev/null || true)
  elif [ -n "$OPT_LINK" ]; then
    link="$OPT_LINK"
  elif [ -t 0 ]; then
    {
      hr
      log "${C_BLD}Вставьте ссылку на сервер VLESS${C_RST} (из панели, бота или клиента)."
      log "Она начинается с ${C_BLD}vless://${C_RST} и содержит UUID, адрес и параметры."
      log "Например: vless://uuid@example.com:443?type=tcp&security=reality&pbk=...&sni=..."
      printf 'вставьте ссылку > '
    } >&2
    local buf="" line="" n=0 _drain
    while [ "$n" -lt 40 ]; do
      IFS= read -r -t 30 line || break
      buf+="$line "
      case "$line" in *vless://*) break ;; esac
      n=$((n + 1))
    done
    # подчищаем остатки вставленного текста, чтобы их не выполнил shell
    while IFS= read -r -t 0.2 _drain; do :; done
    link="$buf"
    hr >&2
  else
    die "ссылка не передана: используйте --link URL или --link-stdin"
  fi
  printf '%s\n' "$link"
}

show_link_summary() {
  local link="$1"
  link_summary "$link" || die "не удалось разобрать ссылку vless://"
  log "  Сервер:    ${C_BLD}${SUM_SERVER}:${SUM_PORT}${C_RST}"
  log "  Транспорт: ${SUM_NETWORK}   защита: ${SUM_SECURITY}${SUM_SNI:+ (sni=$SUM_SNI)}"
  [ -n "$SUM_NAME" ] && log "  Название:  $SUM_NAME"
  if [ "$SUM_CORE_FAMILY" = "legacy" ]; then
    log "  Ядро:      Xray $LEGACY_CORE_VERSION ${C_YEL}(legacy: ${SUM_LEGACY_REASON})${C_RST}"
  else
    log "  Ядро:      Xray ${OPT_CORE_VERSION:-latest}"
  fi
}

cmd_install() {
  require_root
  if installed && [ "$OPT_FORCE" != "yes" ] && [ "$OPT_DRY_RUN" != "yes" ]; then
    if [ -f "$SVC_UNIT" ]; then
      info "$APP уже установлен — показываю меню управления"
      cmd_menu
      return 0
    fi
    warn "найдена незавершённая установка (нет $SVC_UNIT) — довожу её до конца"
  fi
  step "1/8 проверка системы"
  [ -r /etc/os-release ] && . /etc/os-release
  case "${ID:-}${ID_LIKE:-}" in
    *ubuntu*|*debian*) ok "ОС: ${PRETTY_NAME:-неизвестно}" ;;
    *) warn "скрипт рассчитан на Ubuntu/Debian, обнаружено: ${PRETTY_NAME:-неизвестно}" ;;
  esac
  [ "$(ps -p 1 -o comm= 2>/dev/null)" = "systemd" ] || warn "PID 1 не systemd — автозапуск может не работать"
  ok "архитектура: $(uname -m) → $(core_asset_name)"
  if ! detect_conflicts; then
    warn "на машине уже есть другой туннель/прозрачный прокси (см. выше):"
    warn "  • файлы и службы Xray/sing-box этот скрипт НЕ трогает (свои пути и имена служб),"
    warn "  • но перехват трафика поделить нельзя: чужой клиент перестанет работать корректно."
    confirm "Продолжить установку поверх?" "n" || die "отменено: сначала отключите существующий туннель (например: sudo systemctl stop xray sing-box)"
  fi

  step "2/8 установка зависимостей"
  ensure_deps || die "не хватает зависимостей (см. выше) — проверьте: $APP deps"
  ok "зависимости на месте"

  step "3/8 сервисный пользователь, каталоги и порты"
  ensure_user
  ensure_dirs
  install_self
  ok "каталоги: $PREFIX_DIR, $ETC_DIR, $LOG_DIR"
  check_ports_free || die "освободите порты или укажите другие (--socks-port/--http-port/--tproxy-port)"

  step "4/8 ссылка на сервер VLESS"
  local link; link=$(ask_link)
  show_link_summary "$link"
  # fwmark и таблица policy routing: берём из state или подбираем свободные,
  # чтобы не задеть уже существующий прозрачный прокси
  read_net_params
  info "policy routing: fwmark $FWMARK, таблица $RT_TABLE"
  if [ "$OPT_DRY_RUN" = "yes" ]; then
    local dcfg dstate
    # обязательно с расширением .json: Xray определяет формат конфига по нему
    dcfg=$(mktemp --suffix=.json) || die "mktemp"
    dstate=$(mktemp --suffix=.json) || die "mktemp"
    build_config_files_to "$link" "${OPT_CORE_VERSION:-latest}" "$SUM_CORE_FAMILY" "$dcfg" "$dstate" >/dev/null \
      || die "не удалось собрать конфигурацию"
    log "--- config.json (dry-run) ---"
    cat "$dcfg"
    log "--- конец config.json ---"
    if [ -x "$BIN_DIR/xray" ]; then
      if "$BIN_DIR/xray" run -test -c "$dcfg" >/dev/null 2>&1; then
        ok "установленное ядро приняло конфигурацию"
      else
        warn "установленное ядро отвергло конфигурацию (возможно, нужен --core-version)"
      fi
    else
      warn "ядро Xray ещё не установлено — проверка конфига ядром пропущена"
    fi
    rm -f "$dcfg" "$dstate"
    return 0
  fi
  confirm "Продолжить установку?" || die "отменено пользователем"

  step "5/8 установка ядра Xray"
  # конфиг собирается до старта службы
  link_summary "$link" || die "не удалось разобрать ссылку"
  local core_fam="$SUM_CORE_FAMILY" core_ver
  core_ver=$(choose_core_version "$core_fam")
  if [ -n "$OPT_FROM_FILE" ]; then
    install_core_from_file "$OPT_FROM_FILE"
  elif [ -z "$OPT_CORE_VERSION" ] && [ "$core_fam" != "legacy" ] && [ -f "$VENDOR_CORE" ]; then
    info "использую ядро Xray, зашитое в пакет (без обращения к GitHub)"
    install_core_from_file "$VENDOR_CORE"
  else
    install_core "$core_ver"
  fi
  core_ver=$(core_version_string)

  step "6/8 конфигурация"
  prepare_cert_pin "$core_fam"
  build_config_files "$link" "$core_ver" "$core_fam" >/dev/null || die "не удалось собрать конфигурацию"
  validate_config || die "ядро Xray отвергло конфигурацию"
  ok "config.json собран и проверен"

  step "7/8 доступ без пароля sudo, ярлык и службы systemd"
  write_service_units
  local users="$OPT_ALLOW_USERS"
  if [ -z "$users" ]; then
    users="${SUDO_USER:-}"
    [ -z "$users" ] && users="$(logname 2>/dev/null || true)"
  fi
  write_sudoers "$users"
  if [ -f "$NATIVE_GUI_PY" ]; then
    # Installed via .deb: the package already ships a proper desktop file
    # (with our real icon, correctly matched to the GTK app's id). Writing
    # our own here as well would just create a duplicate menu entry with a
    # generic icon.
    info "ярлык уже предоставлен пакетом — пропускаю"
  else
    write_desktop_file
  fi
  systemd-analyze verify "$SVC_UNIT" >/dev/null 2>&1 || warn "systemd-analyze verify нашёл замечания к unit-файлу"
  if [ "$OPT_AUTOSTART" != "yes" ]; then
    info "автозапуск не включаю — туннель поднимается только вручную (по умолчанию)"
    info "включить автозапуск при желании: $APP autostart on"
  fi
  if [ "$OPT_NO_START" != "yes" ]; then
    if ! "$SELF_PATH" _tproxy up; then
      die "не удалось применить правила прозрачного прокси (см. сообщение выше) — установка остановлена"
    fi
  fi
  systemctl daemon-reload
  if [ "$OPT_AUTOSTART" = "yes" ]; then
    systemctl enable "$SVC_NAME.service" >/dev/null 2>&1 || warn "не удалось включить автозапуск"
    ok "автозапуск при загрузке включён (--autostart)"
  fi
  if [ "$OPT_WATCHDOG" = "yes" ]; then
    systemctl enable --now "${SVC_NAME}-watchdog.timer" >/dev/null 2>&1 || warn "watchdog не включён"
  fi
  # Резервная копия рабочего конфига: если служба не поднимется, вернём прежнее
  local bak_cfg="" bak_state=""
  [ -f "$CONFIG_FILE" ] && { bak_cfg=$(mktemp); cp -a "$CONFIG_FILE" "$bak_cfg"; }
  [ -f "$STATE_FILE" ] && { bak_state=$(mktemp); cp -a "$STATE_FILE" "$bak_state"; }
  if [ "$OPT_NO_START" = "yes" ]; then
    systemctl stop "$SVC_NAME.service" >/dev/null 2>&1 || true
    "$SELF_PATH" _tproxy down >/dev/null 2>&1 || true   # на случай остатков от прошлых запусков
    rm -f "$bak_cfg" "$bak_state"
    ok "служба установлена, но НЕ запущена (--no-start) — интернет не тронут"
    warn "запуск: $APP on  (он сам проверит туннель и выключит перехват, если тот не отвечает)"
    hr; print_status; hr
    return 0
  fi
  systemctl restart "$SVC_NAME.service" || true
  sleep 2
  if ! svc_active; then
    if [ -n "$bak_cfg" ] && [ -n "$bak_state" ]; then
      warn "новая конфигурация не поднялась — возвращаю предыдущую рабочую"
      install -m 0640 -o root -g "$SVC_USER" "$bak_cfg" "$CONFIG_FILE"
      install -m 0600 -o root -g root "$bak_state" "$STATE_FILE"
      systemctl restart "$SVC_NAME.service" 2>/dev/null || true
      sleep 2
      svc_active && ok "прежняя конфигурация восстановлена и работает"
    fi
    journalctl -u "$SVC_NAME" -n 30 --no-pager 2>/dev/null || true
    rm -f "$bak_cfg" "$bak_state"
    die "служба не поднялась (см. журнал выше)"
  fi
  rm -f "$bak_cfg" "$bak_state"
  if ! tunnel_works; then
    warn "туннель не отвечает — выключаю перехват (интернет остаётся прямым)"
    systemctl stop "$SVC_NAME.service" 2>/dev/null || true
    die "туннель не поднялся. Конфиг сохранён: $CONFIG_FILE — пришлите вывод: $APP logs"
  fi
  ok "служба запущена, туннель проверен (внешний IP: $TUNNEL_EXIT_IP)"

  step "8/8 проверка графической кнопки"
  if [ -d /usr/share/xsessions ] || [ -d /usr/share/wayland-sessions ]; then
    if ensure_zenity; then
      ok "графическая кнопка доступна: $APP gui (или ярлык «VLESS Tunnel» в меню)"
    else
      warn "zenity не установлен — графическая кнопка недоступна"
      warn "установите при необходимости: sudo apt install zenity"
    fi
  fi

  hr
  print_status
  hr
  ok "${C_BLD}Готово.${C_RST} Управление: $APP status|on|off|toggle|test|gui"
  log "Ссылку можно сменить в любой момент: ${C_BLD}$APP set-link${C_RST} (пароль sudo не потребуется)"
  return 0
}

cmd_set_link() {
  require_root
  installed || die "туннель не установлен — сначала выполните: sudo $APP install"
  local link; link=$(ask_link)
  show_link_summary "$link"
  confirm "Применить эту ссылку?" || die "отменено пользователем"
  hr
  apply_link "$link" restart || die "не удалось применить новую ссылку"
  ok "сервер изменён"
  hr
  print_status
  return 0
}

tunnel_works() { # 0 — туннель отвечает, 1 — нет; результат в TUNNEL_EXIT_IP
  local socks http ip
  socks=$(state_get socks_port 2>/dev/null); socks="${socks:-$DEF_SOCKS_PORT}"
  http=$(state_get http_port 2>/dev/null);  http="${http:-$DEF_HTTP_PORT}"
  ip=$(curl -s --max-time 15 --socks5-hostname "127.0.0.1:$socks" https://api.ipify.org 2>/dev/null || true)
  if [ -z "$ip" ]; then
    ip=$(curl -s --max-time 15 -x "http://127.0.0.1:$http" https://api.ipify.org 2>/dev/null || true)
  fi
  [ -n "$ip" ] || return 1
  TUNNEL_EXIT_IP="$ip"
  return 0
}

cmd_on() {
  require_root
  installed || die "туннель не установлен: sudo $APP install"
  svc_exists || die "служба не установлена (нет $SVC_UNIT) — доведите установку: sudo $APP install --force"
  systemctl start "$SVC_NAME.service"
  sleep 1
  svc_active || die "туннель не поднялся (journalctl -u $SVC_NAME -n 50)"
  if ! tunnel_works; then
    warn "служба запущена, но туннель не отвечает — выключаю перехват, чтобы не оставить без интернета"
    systemctl stop "$SVC_NAME.service" 2>/dev/null || true
    die "не удалось поднять туннель; интернет прямой. Диагностика: $APP logs"
  fi
  ok "туннель включён и проверен (внешний IP: $TUNNEL_EXIT_IP)"
}

cmd_off() {
  require_root
  installed || die "туннель не установлен"
  svc_exists || return 0
  systemctl stop "$SVC_NAME.service"
  ok "туннель выключен"
}

cmd_toggle() {
  require_root
  installed || die "туннель не установлен: sudo $APP install"
  svc_exists || die "служба не установлена (нет $SVC_UNIT) — доведите установку: sudo $APP install --force"
  if svc_active; then cmd_off; else cmd_on; fi
}

cmd_restart() {
  require_root
  installed || die "туннель не установлен"
  svc_exists || die "служба не установлена (нет $SVC_UNIT) — доведите установку: sudo $APP install --force"
  systemctl restart "$SVC_NAME.service"
  sleep 1
  svc_active && ok "туннель перезапущен" || die "не удалось перезапустить"
}

status_json() {
  local active="false" enabled="false"
  svc_active && active="true"
  svc_enabled && enabled="true"
  local is_inst="false"; installed && is_inst="true"
  if ! [ -f "$STATE_FILE" ]; then
    printf '{"installed":%s,"active":%s,"enabled":%s}\n' "$is_inst" "$active" "$enabled"
    return 0
  fi
  python3 - "$STATE_FILE" "$active" "$enabled" "$is_inst" "$BIN_DIR/xray" <<'PY'
import json, subprocess, sys
path, active, enabled, installed, xbin = sys.argv[1:6]
try:
    with open(path, encoding="utf-8") as f:
        st = json.load(f)
except Exception:
    st = {}
st = {k: v for k, v in st.items() if k != "link"}
st["active"] = active == "true"
st["enabled"] = enabled == "true"
st["installed"] = installed == "true"
try:
    out = subprocess.run([xbin, "version"], capture_output=True, text=True, timeout=5).stdout.splitlines()
    st["core_running_version"] = out[0].split()[1] if out else ""
except Exception:
    st["core_running_version"] = ""
print(json.dumps(st, ensure_ascii=False))
PY
}

print_status() {
  local active="выключен" enabled="нет"
  svc_active && active="${C_GRN}включён${C_RST}"
  svc_enabled && enabled="да"
  log "${C_BLD}VLESS Tunnel${C_RST} ($APP $APP_VERSION, сборка $APP_BUILD)"
  if ! [ -f "$STATE_FILE" ]; then
    log "  Состояние: ${C_YEL}не установлен${C_RST}"
    log "  Установка: sudo $APP install"
    return 0
  fi
  local net sec srv port name fam core exclude_lan ipv6 socks http tproxy
  net=$(state_get network); sec=$(state_get security); srv=$(state_get server)
  port=$(state_get server_port); name=$(state_get name); fam=$(state_get core_family)
  core=$(state_get core_version); exclude_lan=$(state_get exclude_lan)
  ipv6=$(state_get ipv6_mode); socks=$(state_get socks_port)
  http=$(state_get http_port); tproxy=$(state_get tproxy_port)
  log "  Туннель:   $active     автозапуск: $enabled"
  log "  Сервер:    ${C_BLD}${srv}:${port}${C_RST}  (vless/$net/$sec)${name:+  «$name»}"
  log "  Ядро:      Xray $core ${fam:+($fam)}"
  log "  Прокси:    socks5 127.0.0.1:$socks | http 127.0.0.1:$http"
  log "  Прозрачно: TCP: да | UDP/QUIC: да | IPv6: $([ "$ipv6" = block ] && echo 'блокируется' || echo 'через туннель')"
  log "  LAN:       $([ "$exclude_lan" = true ] && echo 'напрямую (не через туннель)' || echo 'через туннель') | TPROXY-порт: $tproxy"
}

cmd_status() {
  if [ "$OPT_JSON" = "yes" ]; then status_json; return 0; fi
  require_root
  print_status
}

cmd_logs() {
  require_root
  journalctl -u "$SVC_NAME.service" -n "${OPT_LINES:-40}" --no-pager 2>/dev/null || \
    die "не удалось прочитать журнал"
}

cmd_test() {
  require_root
  installed || die "туннель не установлен"
  local socks http rc=0
  socks=$(state_get socks_port); http=$(state_get http_port)
  log "${C_BLD}Проверка соединения${C_RST}"
  if svc_active; then ok "служба активна"; else err "служба не запущена"; rc=1; fi

  local ip_socks="" ip_http="" ip_trans="" ip_dns=""
  ip_socks=$(curl -s --max-time 20 --socks5-hostname "127.0.0.1:$socks" https://api.ipify.org 2>/dev/null || true)
  [ -n "$ip_socks" ] && ok "SOCKS5 127.0.0.1:$socks → $ip_socks" || { err "SOCKS5 не работает"; rc=1; }

  ip_http=$(curl -s --max-time 20 -x "http://127.0.0.1:$http" https://api.ipify.org 2>/dev/null || true)
  [ -n "$ip_http" ] && ok "HTTP   127.0.0.1:$http → $ip_http" || { err "HTTP-прокси не работает"; rc=1; }

  if svc_active; then
    ip_trans=$(curl -s --max-time 20 https://api.ipify.org 2>/dev/null || true)
    [ -n "$ip_trans" ] && ok "прозрачный TCP (без настроек прокси) → $ip_trans" || { err "прозрачный TCP не работает"; rc=1; }

    if python3 - <<'PY' 2>/dev/null
import socket, struct, random, sys
name = "example.com"
tid = random.randint(0, 65535)
header = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0)
qd = b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00" + struct.pack(">HH", 1, 1)
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(8)
try:
    s.sendto(header + qd, ("9.9.9.9", 53))
    data, _ = s.recvfrom(4096)
    sys.exit(0 if len(data) > 12 else 1)
except Exception:
    sys.exit(1)
PY
    then
      ok "прозрачный UDP (QUIC-путь, DNS через туннель): работает"
    else
      err "прозрачный UDP не работает (QUIC/HTTP-3 может не проходить)"
      rc=1
    fi
  fi

  if [ -n "$ip_socks" ] && [ -n "$ip_http" ] && [ "$ip_socks" != "$ip_http" ]; then
    warn "SOCKS и HTTP показывают разные внешние IP — возможен рассинхрон"
  fi
  if [ -n "$ip_socks" ]; then
    ip_dns=$(curl -s --max-time 15 --socks5-hostname "127.0.0.1:$socks" https://1.1.1.1/cdn-cgi/trace 2>/dev/null | awk -F= '$1=="ip"{print $2}' || true)
    [ -n "$ip_dns" ] && log "  (проверка Cloudflare через туннель: $ip_dns)"
  fi
  hr
  if [ "$rc" -eq 0 ]; then ok "${C_BLD}Туннель работает.${C_RST}"; else err "есть проблемы — смотрите $APP logs"; fi
  return "$rc"
}

cmd_sudoers() {
  require_root
  local users="$OPT_ALLOW_USERS"
  if [ -z "$users" ]; then
    users="${SUDO_USER:-}"
    [ -z "$users" ] && users="$(logname 2>/dev/null || true)"
  fi
  [ -n "$users" ] || die "не удалось определить пользователя — укажите: $APP sudoers --allow-user ИМЯ"
  write_sudoers "$users"
}

cmd_autostart() { # $1 = on|off|status
  require_root
  installed || die "туннель не установлен"
  local act="${1:-status}"
  case "$act" in
    on)
      systemctl enable "$SVC_NAME.service" >/dev/null 2>&1 || die "не удалось включить автозапуск"
      [ "$OPT_WATCHDOG" = "yes" ] && systemctl enable --now "${SVC_NAME}-watchdog.timer" >/dev/null 2>&1 || true
      ok "автозапуск включён: туннель будет подниматься сам при загрузке" ;;
    off)
      systemctl disable "$SVC_NAME.service" >/dev/null 2>&1 || true
      ok "автозапуск выключен: туннель поднимается только вручную ($APP on / кнопкой)"
      log "  сам туннель это не выключает — состояние: $(svc_active && echo 'включён' || echo 'выключен')" ;;
    status|*)
      local en; en=$(systemctl is-enabled "$SVC_NAME.service" 2>/dev/null || echo "disabled")
      log "автозапуск: $en   (watchdog-таймер: $(systemctl is-enabled "${SVC_NAME}-watchdog.timer" 2>/dev/null || echo disabled))"
      log "включается только вручную: $APP on | toggle | gui" ;;
  esac
}

cmd_deps() {
  local rc=0
  deps_report || rc=1
  if [ "$OPT_DEPS_INSTALL" = "yes" ]; then
    require_root
    info "устанавливаю недостающие пакеты"
    ensure_deps || rc=1
    hr
    info "повторная проверка:"
    deps_report || rc=1
  elif [ "$rc" -ne 0 ]; then
    log "  установить недостающее: sudo $APP deps --install  (или просто выполнить install)"
  fi
  return "$rc"
}

cmd_self_update() {
  require_root
  local src; src=$(readlink -f "$0")
  install_self
  ok "установленная копия обновлена: $SELF_PATH"
  if [ "$src" != "$SELF_PATH" ]; then
    log "  источник: $src  ($(sha256sum "$src" | cut -c1-16)…)"
  fi
}

cmd_ensure() {
  require_root
  installed || return 0
  svc_active || return 0
  tproxy_up
}

cmd_doctor() {
  require_root
  log "${C_BLD}Диагностика${C_RST}"
  log "-- ОС: $(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-?}") / $(uname -m)"
  log "-- systemd: $(systemctl --version | head -1)"
  log "-- iptables: $(iptables --version 2>/dev/null || echo нет) / nft: $(nft --version 2>/dev/null || echo нет)"
  log "-- iptables backend: $(iptables --version 2>/dev/null | grep -o 'nf_tables\|legacy' || echo '?')"
  if modinfo -F filename xt_TPROXY >/dev/null 2>&1; then
    log "-- TPROXY: ядро поддерживает (xt_TPROXY), загружено в lsmod: $(lsmod 2>/dev/null | grep -cE '^(xt_TPROXY|nf_tproxy)')"
  else
    warn "модуль xt_TPROXY не найден для ядра $(uname -r) — прозрачный UDP/QUIC работать не будет"
  fi
  log "-- Xray: $([ -x "$BIN_DIR/xray" ] && "$BIN_DIR/xray" version | head -1 || echo 'не установлен')"
  log "-- Служба: $(systemctl is-active "$SVC_NAME.service" 2>/dev/null) / автозапуск: $(systemctl is-enabled "$SVC_NAME.service" 2>/dev/null)"
  log "-- Правила mangle: $(iptables -t mangle -S OUTPUT 2>/dev/null | grep -c "$CHAIN_MARK")"
  read_net_params
  log "-- policy routing: fwmark $FWMARK, таблица $RT_TABLE (маркер: $([ -f "$RULES_MARKER" ] && echo есть || echo нет))"
  log "-- ip rule по нашему fwmark: $(ip rule show 2>/dev/null | grep -cE "fwmark ${FWMARK}([^0-9a-f]|\$)")"
  local dp dh dt dbusy="" dport
  dp=$(state_get socks_port);  dp="${dp:-$OPT_SOCKS_PORT}"
  dh=$(state_get http_port);   dh="${dh:-$OPT_HTTP_PORT}"
  dt=$(state_get tproxy_port); dt="${dt:-$OPT_TPROXY_PORT}"
  for dport in "$dp" "$dh" "$dt"; do
    port_in_use "$dport" && dbusy="$dbusy$dport "
  done
  log "-- Порты (socks/http/tproxy): $dp/$dh/$dt${dbusy:+  — УЖЕ ЗАНЯТЫ: $dbusy}"
  hr
  log "Проверка конфликтов с другими туннелями/прокси:"
  if detect_conflicts; then
    ok "конфликтов не обнаружено"
  else
    warn "найдены конфликты (см. выше) — сосуществовать с другим полным туннелем нельзя"
  fi
  hr
  if have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then
    warn "ufw активен: после 'ufw reload' правила могут слетать — watchdog восстановит (проверьте '$APP ensure')"
  fi
  if have docker && systemctl is-active --quiet docker 2>/dev/null; then
    warn "docker установлен: его трафик идёт через цепочки DOCKER-USER; при проблемах добавьте исключения"
  fi
  if [ -f /etc/resolv.conf ]; then
    log "-- /etc/resolv.conf: $(awk '/^nameserver/{printf "%s ", $2}' /etc/resolv.conf)"
  fi
  local def; def=$(ip route show default 2>/dev/null | head -1)
  log "-- Маршрут по умолчанию: ${def:-нет}"
  hr
  log "Зависимости:"
  deps_report || warn "не хватает обязательных зависимостей — установить: sudo $APP deps --install"
  hr
  # Итоговый вердикт: сверяем состояние службы, правил и конфига
  local svc_on="no" rules_on="no" cfg_ok="yes"
  svc_active && svc_on="yes"
  [ "$(iptables -t mangle -S OUTPUT 2>/dev/null | grep -c "$CHAIN_MARK")" != "0" ] && rules_on="yes"
  if [ -f "$CONFIG_FILE" ]; then
    "$BIN_DIR/xray" run -test -c "$CONFIG_FILE" >/dev/null 2>&1 || cfg_ok="no"
  else
    cfg_ok="нет конфига"
  fi
  if [ "$svc_on" = "yes" ] && [ "$rules_on" = "yes" ] && [ "$cfg_ok" = "yes" ]; then
    ok "ВЕРДИКТ: туннель включён, правила и конфиг согласованы"
    log "  хочешь убедиться, что трафик реально идёт — нажми «Проверить соединение»"
  elif [ "$svc_on" = "yes" ] && [ "$rules_on" = "no" ]; then
    warn "ВЕРДИКТ: служба работает, а правил перехвата НЕТ — трафик идёт напрямую"
    log "  исправить: $APP ensure   (watchdog делает это автоматически раз в минуту)"
  elif [ "$svc_on" = "no" ] && [ "$rules_on" = "yes" ]; then
    warn "ВЕРДИКТ: правила перехвата остались, а ядро не работает — интернета не будет"
    log "  исправить: $APP off   (снять правила) или $APP on (поднять туннель)"
  else
    ok "ВЕРДИКТ: туннель выключен, правил нет — интернет идёт напрямую"
  fi
  [ "$cfg_ok" = "yes" ] || warn "конфиг не прошёл проверку ядром ($cfg_ok) — $APP logs или заново вставить ссылку"
  return 0
}

cmd_update_core() {
  require_root
  installed || die "туннель не установлен"
  local fam ver link prev_core
  fam=$(state_get core_family); fam="${fam:-modern}"
  link=$(state_get link)
  ver=$(choose_core_version "$fam")
  prev_core=$(readlink -f "$BIN_DIR/xray" 2>/dev/null || true)
  FORCE_CORE="yes"
  OPT_FORCE="yes"
  install_core "$ver"
  if [ "$fam" != "legacy" ]; then
    link_summary "$link" || die "в state.json повреждена ссылка — примените её заново: $APP set-link"
    prepare_cert_pin "$fam"
    read_net_params
    ver=$(core_version_string)
    build_config_files "$link" "$ver" "$fam" >/dev/null || die "не удалось обновить конфиг"
  fi
  validate_config || die "новое ядро отвергло конфигурацию"
  systemctl restart "$SVC_NAME.service" || true
  sleep 2
  if ! svc_active; then
    _restore_prev_core "$prev_core" "$link" "$fam"
    journalctl -u "$SVC_NAME" -n 20 --no-pager 2>/dev/null || true
    die "новое ядро не запустилось (см. журнал выше)"
  fi
  if ! tunnel_works; then
    warn "новое ядро запустилось, но трафик через туннель не идёт"
    _restore_prev_core "$prev_core" "$link" "$fam"
    systemctl stop "$SVC_NAME.service" 2>/dev/null || true
    die "ядро не заработало; перехват выключен, интернет прямой. Диагностика: $APP logs"
  fi
  ok "ядро обновлено до $(core_version_string), туннель перепроверен (внешний IP: $TUNNEL_EXIT_IP)"
}

# возвращает предыдущее ядро, если новое не заработало
_restore_prev_core() { # $1 = прежний бинарь, $2 = ссылка, $3 = семейство
  local prev="$1" link="$2" fam="$3" pv
  [ -n "$prev" ] && [ -x "$prev" ] || return 0
  warn "возвращаю прежнее ядро: $(basename "$prev")"
  ln -sf "$(basename "$prev")" "$BIN_DIR/xray"
  pv=$(core_version_string)
  if [ -n "$link" ] && [ "$fam" != "legacy" ]; then
    build_config_files "$link" "$pv" "$fam" >/dev/null 2>&1 || true
  fi
  systemctl restart "$SVC_NAME.service" 2>/dev/null || true
  sleep 2
  if svc_active && tunnel_works; then
    ok "прежнее ядро $pv восстановлено и работает (внешний IP: $TUNNEL_EXIT_IP)"
  else
    warn "прежнее ядро тоже не поднялось — проверьте: $APP logs"
  fi
  return 0
}

cmd_uninstall() {
  require_root
  installed || [ -f "$SVC_UNIT" ] || die "нечего удалять: $APP не установлен"
  confirm "Полностью откатить всё, что сделал $APP?
  служба и таймеры, правила iptables/маршруты, конфиг и ядро,
  логи, правило sudo, ярлык, системный пользователь $SVC_USER" "n" || die "отменено"
  local user_created=""
  user_created=$(state_get svc_user_created 2>/dev/null || true)
  info "останавливаю службу"
  systemctl disable --now "${SVC_NAME}-watchdog.timer" >/dev/null 2>&1 || true
  systemctl disable --now "$SVC_NAME.service" >/dev/null 2>&1 || true
  sleep 1
  info "снимаю правила прозрачного прокси"
  tproxy_down
  info "удаляю файлы"
  rm -f "$SVC_UNIT" "$WD_UNIT" "$WD_TIMER"
  systemctl daemon-reload >/dev/null 2>&1 || true
  systemctl reset-failed "$SVC_NAME.service" >/dev/null 2>&1 || true
  remove_sudoers
  remove_desktop_file
  if [ "$OPT_KEEP_CONFIG" = "yes" ]; then
    warn "конфигурация сохранена: $ETC_DIR, $BIN_DIR"
  else
    rm -rf "$ETC_DIR" "$PREFIX_DIR" "$LOG_DIR"
  fi
  rm -f "$SELF_PATH"
  rmdir /run/vless-tunnel 2>/dev/null || true
  if id -u "$SVC_USER" >/dev/null 2>&1; then
    if [ "$OPT_PURGE_USER" != "yes" ] || [ "$OPT_KEEP_USER" = "yes" ]; then
      info "системный пользователь $SVC_USER оставлен (--keep-user)"
    elif [ "$user_created" = "true" ] || getent passwd "$SVC_USER" 2>/dev/null | grep -q "vless-tunnel service user"; then
      userdel "$SVC_USER" 2>/dev/null || true
      ok "пользователь $SVC_USER удалён"
    else
      warn "пользователь $SVC_USER существовал до установки — НЕ удаляю его"
    fi
  fi
  ok "$APP удалён полностью"
}

cmd_gui() {
  # GUI запускается от имени обычного пользователя, привилегии — через sudo -n
  if [ "$(id -u)" -eq 0 ]; then
    local u="${SUDO_USER:-}"
    [ -z "$u" ] && u="$(logname 2>/dev/null || true)"
    if [ -n "$u" ] && [ "$u" != "root" ]; then
      exec runuser -u "$u" -- "$SELF_PATH" gui
    fi
    warn "GUI от имени root запускать не рекомендуется — запустите: $APP gui"
  fi
  if [ -f "$NATIVE_GUI_PY" ] && have python3 \
     && python3 -c 'import gi; gi.require_version("Gtk","4.0"); gi.require_version("Adw","1")' >/dev/null 2>&1; then
    exec python3 "$NATIVE_GUI_PY"
  fi
  if ! have zenity; then
    err "zenity не установлен. Установите: sudo apt install zenity"
    err "или пользуйтесь меню в терминале: $APP"
    return 1
  fi
  have python3 || { err "для GUI нужен python3"; return 1; }
  local self="$SELF_PATH"
  local GUI_RESULT="" GUI_RC=1

  gui_info() { zenity --info  --title="VLESS Tunnel" --width=520 --text="$1" 2>/dev/null || true; }
  gui_err()  { zenity --error --title="VLESS Tunnel" --width=560 --text="$1" 2>/dev/null || true; }
  # ВАЖНО: zenity --text-info читает содержимое из stdin, а не из --text
  gui_show() {
    local title="$1" body="$2"
    [ -n "$body" ] || body="(пусто — команда ничего не вывела, смотрите журнал)"
    printf '%s\n' "$body" | zenity --text-info --title="$title" --width=760 --height=480 --ok-label="Понятно" --cancel-label="Назад" 2>/dev/null || true
  }

  # Выполняет команду, показывая индикатор прогресса (операции бывают до ~20 с)
  gui_run() { # $1 = текст, дальше — команда
    local msg="$1"; shift
    local outf rcf pid
    outf=$(mktemp); rcf=$(mktemp)
    ( "$@" >"$outf" 2>&1; echo $? >"$rcf" ) &
    pid=$!
    ( while kill -0 "$pid" 2>/dev/null; do echo "# $msg"; sleep 0.4; done ) \
      | zenity --progress --pulsate --no-cancel --auto-close --title="VLESS Tunnel" \
               --width=440 --text="$msg" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
    GUI_RC=$(cat "$rcf" 2>/dev/null || echo 1)
    GUI_RESULT=$(cat "$outf" 2>/dev/null || true)
    rm -f "$outf" "$rcf"
    return 0
  }

  local st active autostart text choice toggle_label
  local GUI_ACTIONS="Сменить сервер (вставить новую ссылку)|Проверить соединение|Показать журнал|Включить автозапуск при загрузке|Выключить автозапуск при загрузке|Обновить ядро Xray|Диагностика|Удалить vless-tunnel"
  local HAVE_EXTRA="no"
  zenity --help-general 2>/dev/null | grep -q -- '--extra-button' && HAVE_EXTRA="yes"
  while :; do
    st=$(sudo -n "$self" status --json 2>/dev/null || true)
    if [ -z "$st" ]; then
      gui_err "Не удалось получить статус (нужно правило sudo без пароля).\n\nЗапустите в терминале:\n  sudo $self install"
      return 1
    fi
    active=$(printf '%s' "$st" | python3 -c 'import json,sys;print("true" if json.load(sys.stdin).get("active") else "false")' 2>/dev/null || echo false)
    autostart=$(systemctl is-enabled "$SVC_NAME.service" 2>/dev/null || echo disabled)
    text=$(printf '%s' "$st" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("<b>Туннель %s</b>" % ("ВКЛЮЧЁН" if d.get("active") else "ВЫКЛЮЧЕН"))
if d.get("installed"):
    print("Сервер:  %s:%s  (%s / %s)" % (d.get("server"), d.get("server_port"), d.get("network"), d.get("security")))
    print("Ядро:    Xray %s" % d.get("core_version", "?"))
    print("Прокси:  socks5 127.0.0.1:%s   http 127.0.0.1:%s" % (d.get("socks_port", ""), d.get("http_port", "")))
else:
    print("Туннель не установлен — выполните: sudo %s install" % "'"$APP"'")
' 2>/dev/null || echo "")
    case "$autostart" in enabled) text="$text"$'\n'"Автозапуск: включён";; *) text="$text"$'\n'"Автозапуск: выключен (только вручную)";; esac

    # Главное окно — только кнопки (без списка, а значит без сортировки:
    # в zenity 4 списку всегда приделывается GtkStringSorter, --hide-header
    # убирает лишь текст заголовка, оставляя кликабельную сортировку).
    if [ "$active" = "true" ]; then toggle_label="Выключить туннель"; else toggle_label="Включить туннель"; fi
    if [ "$HAVE_EXTRA" = "yes" ]; then
      local rc=0
      ZENITY_EXTRA=2 zenity --question --title="VLESS Tunnel" --width=560 \
        --text="$text" --ok-label="$toggle_label" \
        --extra-button="Действия…" --cancel-label="Закрыть" 2>/dev/null || rc=$?
      case "$rc" in
        0)  choice="$toggle_label" ;;
        2)  choice=$(zenity --forms --title="VLESS Tunnel: действия" --width=560 --text="$text" \
              --ok-label="Выполнить" --cancel-label="Назад" --add-combo="Действие" --combo-values="$GUI_ACTIONS" 2>/dev/null) || continue
            [ -n "$choice" ] || continue ;;
        *)  break ;;
      esac
    else
      # zenity без доп. кнопки: всё одним выпадающим списком, окно не закрывается
      choice=$(zenity --forms --title="VLESS Tunnel" --width=560 --text="$text" \
        --ok-label="Выполнить" --cancel-label="Назад" --add-combo="Действие" --combo-values="$toggle_label|$GUI_ACTIONS" 2>/dev/null) || break
      [ -n "$choice" ] || break
    fi

    case "$choice" in
      "Включить туннель")
        gui_run "Включаю туннель и проверяю связь…" sudo -n "$self" on
        if [ "$GUI_RC" = "0" ]; then gui_info "Готово.\n\n$(printf '%s' "$GUI_RESULT" | grep -E 'туннель включён' || printf '%s' "$GUI_RESULT" | tail -2)"
        else gui_err "Туннель не поднялся (перехват выключен, интернет прямой).\n\n$(printf '%s' "$GUI_RESULT" | tail -5)"; fi ;;
      "Выключить туннель")
        gui_run "Выключаю туннель…" sudo -n "$self" off
        [ "$GUI_RC" = "0" ] && gui_info "Туннель выключен." || gui_err "Не получилось выключить.\n\n$(printf '%s' "$GUI_RESULT" | tail -4)" ;;
      "Сменить сервер"*)
        local link tmpf
        link=$(zenity --text-info --editable --width=700 --height=330 </dev/null 2>/dev/null \
          --ok-label="Применить" --cancel-label="Назад" --title="Новый сервер: вставьте ссылку vless:// (можно вместе с текстом)") || continue
        [ -n "$link" ] || continue
        case "$link" in *vless://*) ;; *) gui_err "В ссылке нет vless:// — проверьте и попробуйте снова"; continue ;; esac
        tmpf=$(mktemp); printf '%s' "$link" > "$tmpf"
        gui_run "Меняю сервер и проверяю связь…" bash -c "sudo -n '$self' set-link --link-stdin < '$tmpf'"
        rm -f "$tmpf"
        if [ "$GUI_RC" = "0" ]; then gui_info "Сервер изменён.\n\n$(printf '%s' "$GUI_RESULT" | grep -E 'туннель включён|Сервер:' | head -2)"
        else gui_err "Не удалось применить ссылку (вернул прежний рабочий сервер).\n\n$(printf '%s' "$GUI_RESULT" | tail -5)"; fi ;;
      "Проверить соединение")
        gui_run "Проверяю SOCKS5, HTTP, прозрачный TCP и UDP…" sudo -n "$self" test
        gui_show "Проверка соединения" "$GUI_RESULT" ;;
      "Показать журнал")
        gui_run "Читаю журнал…" sudo -n "$self" logs --lines 80
        gui_show "Журнал vless-tunnel" "$GUI_RESULT" ;;
      "Включить автозапуск при загрузке")
        gui_run "Включаю автозапуск…" sudo -n "$self" autostart on
        [ "$GUI_RC" = "0" ] && gui_info "Автозапуск включён: туннель будет подниматься сам при загрузке." || gui_err "Не удалось (нужно правило sudo)." ;;
      "Выключить автозапуск при загрузке")
        gui_run "Выключаю автозапуск…" sudo -n "$self" autostart off
        [ "$GUI_RC" = "0" ] && gui_info "Автозапуск выключен: туннель поднимается только вручную." || gui_err "Не удалось (нужно правило sudo)." ;;
      "Обновить ядро Xray")
        if zenity --question --title="VLESS Tunnel" --width=460 \
             --text="Обновить ядро Xray и перезапустить туннель?" --ok-label="Обновить" --cancel-label="Отмена" 2>/dev/null; then
          gui_run "Обновляю ядро…" sudo -n "$self" update-core
          gui_show "Обновление ядра" "$GUI_RESULT"
        fi ;;
      "Диагностика")
        gui_run "Собираю диагностику…" sudo -n "$self" doctor
        gui_show "Диагностика" "$GUI_RESULT" ;;
      "Удалить vless-tunnel")
        if zenity --question --title="VLESS Tunnel" --width=480 \
             --text="Полностью откатить всё, что сделал vless-tunnel?\n\nслужба и таймеры, правила iptables и маршруты,\nконфиг и ядро, логи, правило sudo, ярлык,\nсистемный пользователь vless" \
             --ok-label="Удалить" --cancel-label="Отмена" 2>/dev/null; then
          gui_run "Откатываю изменения…" sudo -n "$self" uninstall --yes
          if [ "$GUI_RC" = "0" ]; then gui_info "Готово: всё, что ставил скрипт, удалено."; break
          else gui_err "Не удалось удалить.\n\n$(printf '%s' "$GUI_RESULT" | tail -5)"; fi
        fi ;;
      "") break ;;   # закрытие окна или «Выход»
      *) : ;;
    esac
  done
  return 0
}


cmd_menu() {
  require_root
  if ! installed; then
    cmd_install
    return 0
  fi
  # установлено — предлагаем управление и смену сервера
  local choice
  while :; do
    hr
    print_status
    hr
    log "  1) Включить / выключить туннель"
    log "  2) ${C_BLD}Сменить сервер (вставить другую ссылку vless://)${C_RST}"
    log "  3) Проверить соединение"
    log "  4) Последние строки журнала"
    log "  5) Обновить ядро Xray"
    log "  6) Переустановить службу и правила (с текущей ссылкой)"
    log "  7) Диагностика"
    log "  8) Графическая кнопка (GUI)"
    log "  9) ${C_BLD}Удалить $APP (полный откат: служба, правила, конфиг, пользователь)${C_RST}"
    log "  0) Выход"
    printf 'Выбор [0-9]: '
    read -r choice || choice=0
    case "$choice" in
      1) cmd_toggle ;;
      2)
        local link; link=$(ask_link)
        show_link_summary "$link"
        if confirm "Применить эту ссылку?"; then
          if apply_link "$link" restart; then ok "сервер изменён"; else err "не удалось применить ссылку"; fi
        else
          info "отменено"
        fi ;;
      3) cmd_test || true ;;
      4) cmd_logs ;;
      5) cmd_update_core ;;
      6) OPT_FORCE="yes"; cmd_install ;;
      7) cmd_doctor ;;
      8) cmd_gui ;;
      9) cmd_uninstall; return 0 ;;
      0|"") return 0 ;;
      *) warn "нет такого пункта" ;;
    esac
  done
}

#-------------------------------------------------------------------------------
#  Разбор аргументов и запуск
#-------------------------------------------------------------------------------
parse_args() {
  local first="${1:-}"
  case "$first" in
    ""|-h|--help|help) ;;
    -V|--version|version) printf '%s %s (сборка %s)\n' "$APP" "$APP_VERSION" "$APP_BUILD"; exit 0 ;;
    _tproxy)   # внутренняя команда: systemd вызывает "<script> _tproxy up|down"
      OPT_CMD="_tproxy"; TPROXY_ACTION="${2:-up}"
      shift; if [ $# -gt 0 ]; then shift; fi ;;
    autostart)   # подкоманда: "<script> autostart on|off|status"
      OPT_CMD="autostart"; AUTOSTART_ACTION="${2:-status}"
      shift; if [ $# -gt 0 ]; then shift; fi ;;
    install|reinstall|menu|on|off|toggle|restart|status|test|logs|set-link|gui|update-core|doctor|uninstall|ensure|self-update|sudoers|deps|link-check)
      OPT_CMD="$first"; shift ;;
    --*) ;;
    -*) ;;
    *) die "неизвестная команда: $first (см. $APP --help)" ;;
  esac
  [ -n "$OPT_CMD" ] || OPT_CMD="menu"

  while [ $# -gt 0 ]; do
    case "$1" in
      --link) OPT_LINK="${2:-}"; shift 2 ;;
      --link=*) OPT_LINK="${1#*=}"; shift ;;
      --link-stdin|--stdin) OPT_LINK_STDIN="yes"; shift ;;   # --stdin оставлен для GUI
      -y|--yes) OPT_YES="yes"; shift ;;
      --force) OPT_FORCE="yes"; shift ;;
      --no-autostart) OPT_AUTOSTART="no"; shift ;;
      --autostart) OPT_AUTOSTART="yes"; shift ;;
      --keep-config) OPT_KEEP_CONFIG="yes"; shift ;;
      --purge-user) OPT_PURGE_USER="yes"; shift ;;
      --keep-user) OPT_PURGE_USER="no"; OPT_KEEP_USER="yes"; shift ;;
      --socks-port) OPT_SOCKS_PORT="${2:-}"; shift 2 ;;
      --http-port) OPT_HTTP_PORT="${2:-}"; shift 2 ;;
      --tproxy-port) OPT_TPROXY_PORT="${2:-}"; shift 2 ;;
      --proxy-lan) OPT_EXCLUDE_LAN="no"; shift ;;
      --block-ipv6) OPT_IPV6_MODE="block"; shift ;;
      --direct-dns) OPT_DIRECT_DNS="${2:-}"; shift 2 ;;
      --core-version) OPT_CORE_VERSION="${2:-}"; shift 2 ;;
      --from-file) OPT_FROM_FILE="${2:-}"; shift 2 ;;
      --gh-proxy) OPT_GH_PROXY="${2:-}"; shift 2 ;;
      --allow-user) OPT_ALLOW_USERS="${2:-}"; shift 2 ;;
      --log-level) OPT_LOG_LEVEL="${2:-}"; shift 2 ;;
      --access-log) OPT_ACCESS_LOG="yes"; shift ;;
      --exclude-user) OPT_EXCLUDE_USERS="${2:-}"; shift 2 ;;
      --no-vision-udp443) OPT_VISION_UDP443="no"; shift ;;
      --mux) OPT_MUX="yes"; shift ;;
      --no-watchdog) OPT_WATCHDOG="no"; shift ;;
      --no-gui) shift ;;
      --json) OPT_JSON="yes"; shift ;;
      --lines) OPT_LINES="${2:-40}"; shift 2 ;;
      --dry-run) OPT_DRY_RUN="yes"; shift ;;
      --install) OPT_DEPS_INSTALL="yes"; shift ;;
      --no-start) OPT_NO_START="yes"; shift ;;
      -q|--quiet) OPT_VERBOSE="no"; shift ;;
      -h|--help) print_help; exit 0 ;;
      -V|--version) printf '%s %s (сборка %s)\n' "$APP" "$APP_VERSION" "$APP_BUILD"; exit 0 ;;
      *) die "неизвестная опция: $1 (см. $APP --help)" ;;
    esac
  done
  case "$OPT_SOCKS_PORT$OPT_HTTP_PORT$OPT_TPROXY_PORT$OPT_LINES" in
    *[!0-9]*) die "порты и --lines должны быть числами" ;;
  esac
  [ "$OPT_SOCKS_PORT" -ge 1024 ] && [ "$OPT_SOCKS_PORT" -le 65535 ] || die "--socks-port: 1024..65535"
  [ "$OPT_HTTP_PORT" -ge 1024 ] && [ "$OPT_HTTP_PORT" -le 65535 ] || die "--http-port: 1024..65535"
  [ "$OPT_TPROXY_PORT" -ge 1024 ] && [ "$OPT_TPROXY_PORT" -le 65535 ] || die "--tproxy-port: 1024..65535"
  if [ "$OPT_SOCKS_PORT" = "$OPT_HTTP_PORT" ] || [ "$OPT_SOCKS_PORT" = "$OPT_TPROXY_PORT" ] || [ "$OPT_HTTP_PORT" = "$OPT_TPROXY_PORT" ]; then
    die "порты SOCKS/HTTP/TPROXY не должны совпадать"
  fi
}

reexec_as_root_if_needed() {
  [ "$(id -u)" -eq 0 ] && return 0
  local self="$SELF_PATH"
  [ -x "$self" ] || self=$(readlink -f "$0")
  case "$OPT_CMD" in
    menu|on|off|toggle|restart|status|test|logs|set-link|update-core|doctor|ensure|_tproxy|self-update|autostart)
      # после установки эти команды разрешены без пароля sudo
      if sudo -n -l "$self" "$OPT_CMD" >/dev/null 2>&1; then
        exec sudo -n "$self" "$@"
      fi
      if [ -t 0 ] && [ -t 2 ]; then exec sudo "$self" "$@"; fi
      die "нужны права root без пароля. Выполните один раз: sudo $self install"
      ;;
    install|reinstall|uninstall)
      if [ -t 0 ] && [ -t 2 ]; then exec sudo "$self" "$@"; fi
      die "нужны права root: запустите через sudo (например: sudo $self install)"
      ;;
    gui)
      return 0 ;;   # GUI работает от обычного пользователя
    deps)
      # отчёт можно смотреть без root; доустановка пакетов — только от root
      if [ "$OPT_DEPS_INSTALL" = "yes" ]; then
        if [ -t 0 ] && [ -t 2 ]; then exec sudo "$self" "$@"; fi
        die "нужны права root: sudo $self deps --install"
      fi
      return 0 ;;
    link-check)
      return 0 ;;
    *)
      die "нужны права root"
      ;;
  esac
}

main() {
  parse_args "$@"
  reexec_as_root_if_needed "$@"
  case "$OPT_CMD" in
    menu) cmd_menu ;;
    install|reinstall) cmd_install ;;
    on) cmd_on ;;
    off) cmd_off ;;
    toggle) cmd_toggle ;;
    restart) cmd_restart ;;
    status) cmd_status ;;
    test) cmd_test ;;
    logs) cmd_logs ;;
    set-link) cmd_set_link ;;
    gui) cmd_gui ;;
    update-core) cmd_update_core ;;
    doctor) cmd_doctor ;;
    uninstall) cmd_uninstall ;;
    ensure) cmd_ensure ;;
    self-update) cmd_self_update ;;
    sudoers) cmd_sudoers ;;
    deps) cmd_deps ;;
    autostart) cmd_autostart "$AUTOSTART_ACTION" ;;
    _tproxy)
      require_root
      case "$TPROXY_ACTION" in
        up) tproxy_up ;;
        down) tproxy_down ;;
        *) die "_tproxy up|down" ;;
      esac ;;
    link-check)   # служебное: разобрать ссылку и показать сводку
      local _l; _l=$(ask_link)
      link_summary "$_l" && show_link_summary "$_l" ;;
    *) die "неизвестная команда" ;;
  esac
}

main "$@"
