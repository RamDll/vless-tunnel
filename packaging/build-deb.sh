#!/usr/bin/env bash
#===============================================================================
#  Собирает vless-tunnel_<version>_amd64.deb из vless-tunnel.sh + GUI + иконок.
#
#  Ядро Xray зашивается в пакет (офлайн-установка): по умолчанию берётся
#  .work/core/xray (кеш, оставшийся после tests/container-test.sh), либо путь
#  из переменной XRAY_BIN.
#
#  Запуск:
#    bash packaging/build-deb.sh
#    XRAY_BIN=/путь/к/xray bash packaging/build-deb.sh
#===============================================================================
set -Eeuo pipefail

ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
PKG_DIR="$ROOT/packaging"
OUT_DIR="$ROOT/dist"
XRAY_BIN="${XRAY_BIN:-$ROOT/.work/core/xray}"

VERSION=$(grep -oP 'readonly APP_VERSION="\K[^"]+' "$ROOT/vless-tunnel.sh")
[ -n "$VERSION" ] || { echo "не удалось определить APP_VERSION из vless-tunnel.sh" >&2; exit 1; }

[ -x "$XRAY_BIN" ] || { echo "не найден бинарник ядра Xray: $XRAY_BIN (сначала прогоните tests/container-test.sh или задайте XRAY_BIN=)" >&2; exit 1; }
"$XRAY_BIN" version >/dev/null 2>&1 || { echo "$XRAY_BIN не является рабочим бинарём Xray" >&2; exit 1; }

STAGE=$(mktemp -d)
trap 'rm -rf "$STAGE"' EXIT

echo "==> версия: $VERSION"
echo "==> ядро: $XRAY_BIN ($("$XRAY_BIN" version | head -1))"

mkdir -p "$STAGE/DEBIAN"
sed "s/VERSION_PLACEHOLDER/$VERSION/" "$PKG_DIR/debian/control" > "$STAGE/DEBIAN/control"
install -m 0755 "$PKG_DIR/debian/postinst" "$STAGE/DEBIAN/postinst"
install -m 0755 "$PKG_DIR/debian/prerm"    "$STAGE/DEBIAN/prerm"
install -m 0755 "$PKG_DIR/debian/postrm"   "$STAGE/DEBIAN/postrm"

install -d -m 0755 "$STAGE/usr/bin"
install -m 0755 "$ROOT/vless-tunnel.sh" "$STAGE/usr/bin/vless-tunnel"

install -d -m 0755 "$STAGE/usr/lib/vless-tunnel"
install -m 0755 "$ROOT/gui/vless-tunnel-gui.py" "$STAGE/usr/lib/vless-tunnel/vless-tunnel-gui.py"
install -m 0755 "$ROOT/gui/vless-tunnel-tray.py" "$STAGE/usr/lib/vless-tunnel/vless-tunnel-tray.py"
install -m 0755 "$XRAY_BIN" "$STAGE/usr/lib/vless-tunnel/xray"

install -d -m 0755 "$STAGE/usr/share/applications"
install -m 0644 "$PKG_DIR/desktop/vless-tunnel.desktop" "$STAGE/usr/share/applications/vless-tunnel.desktop"

install -d -m 0755 "$STAGE/usr/lib/systemd/user"
install -m 0644 "$PKG_DIR/systemd-user/vless-tunnel-tray.service" \
  "$STAGE/usr/lib/systemd/user/vless-tunnel-tray.service"

while IFS= read -r -d '' png; do
  rel="${png#"$PKG_DIR"/icons/}"
  install -D -m 0644 "$png" "$STAGE/usr/share/icons/$rel"
done < <(find "$PKG_DIR/icons/hicolor" -name '*.png' -print0)
install -D -m 0644 "$PKG_DIR/icons/hicolor/scalable/apps/vless-tunnel.svg" \
  "$STAGE/usr/share/icons/hicolor/scalable/apps/vless-tunnel.svg"

mkdir -p "$OUT_DIR"
DEB_FILE="$OUT_DIR/vless-tunnel_${VERSION}_amd64.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$DEB_FILE" >/dev/null
echo "==> собрано: $DEB_FILE"
dpkg-deb --info "$DEB_FILE" | sed 's/^/    /'
echo "==> файлы:"
dpkg-deb --contents "$DEB_FILE" | sed 's/^/    /'
