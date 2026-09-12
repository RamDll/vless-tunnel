#!/usr/bin/env python3
"""System tray indicator for vless-tunnel.

Deliberately a separate GTK3 process: libayatana-appindicator's menu is a
GTK3 widget, and GTK3/GTK4 cannot be loaded in the same process as the main
vless-tunnel-gui.py (which is GTK4/libadwaita). This process only shows
status and does a quick on/off toggle + opens the main window for everything
else — no logic is duplicated beyond a minimal status/on/off call.
"""
import json
import os
import subprocess

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import AyatanaAppIndicator3 as AppIndicator, GLib, Gtk  # noqa: E402

APP_BIN = os.environ.get("VLESS_APP_BIN", "vless-tunnel")
APP_ID = "vless-tunnel-tray"
POLL_SECONDS = 5


def run(args, timeout=15, escalate=False):
    """Same sudo-then-pkexec pattern as the main GUI, kept minimal here."""
    cmd = ["sudo", "-n", APP_BIN, *args]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)
    if escalate and p.returncode != 0 and (p.stderr or "").strip().startswith("sudo:"):
        try:
            p = subprocess.run(["pkexec", APP_BIN, *args],
                                capture_output=True, text=True, timeout=max(timeout, 180))
        except Exception as exc:  # noqa: BLE001
            return 1, "", str(exc)
    return p.returncode, p.stdout, p.stderr


def get_status():
    rc, out, _err = run(["status", "--json"], escalate=False)
    if rc != 0:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


class Tray:
    def __init__(self):
        self.indicator = AppIndicator.Indicator.new(
            APP_ID, "vless-tunnel-unknown",
            AppIndicator.IndicatorCategory.APPLICATION_STATUS,
        )
        self.indicator.set_status(AppIndicator.IndicatorStatus.ACTIVE)
        self.indicator.set_title("VLESS Tunnel")

        self.menu = Gtk.Menu()

        self.status_item = Gtk.MenuItem(label="Проверяю…")
        self.status_item.set_sensitive(False)
        self.menu.append(self.status_item)

        self.menu.append(Gtk.SeparatorMenuItem())

        self.toggle_item = Gtk.MenuItem(label="Включить/выключить")
        self.toggle_item.connect("activate", self.on_toggle)
        self.menu.append(self.toggle_item)

        open_item = Gtk.MenuItem(label="Открыть окно")
        open_item.connect("activate", self.on_open_window)
        self.menu.append(open_item)

        self.menu.append(Gtk.SeparatorMenuItem())

        quit_item = Gtk.MenuItem(label="Выход из трея")
        quit_item.connect("activate", lambda *_: Gtk.main_quit())
        self.menu.append(quit_item)

        self.menu.show_all()
        self.indicator.set_menu(self.menu)

        self._busy = False
        self.refresh()
        GLib.timeout_add_seconds(POLL_SECONDS, self._poll)

    def _poll(self):
        if not self._busy:
            self.refresh()
        return True  # keep the timeout running

    def refresh(self):
        status = get_status()
        if status is None or status.get("installed") is False:
            self.indicator.set_icon_full("vless-tunnel-unknown", "не настроено")
            self.status_item.set_label("Туннель не настроен")
            self.toggle_item.set_sensitive(False)
            return
        self.toggle_item.set_sensitive(True)
        active = bool(status.get("active"))
        server = status.get("server", "")
        if active:
            self.indicator.set_icon_full("vless-tunnel-on", "включён")
            self.status_item.set_label(f"Туннель включён — {server}" if server else "Туннель включён")
            self.toggle_item.set_label("Выключить")
        else:
            self.indicator.set_icon_full("vless-tunnel-off", "выключен")
            self.status_item.set_label("Туннель выключен")
            self.toggle_item.set_label("Включить")

    def on_toggle(self, _item):
        status = get_status()
        if status is None:
            return
        cmd = "off" if status.get("active") else "on"
        self._busy = True
        self.toggle_item.set_sensitive(False)

        def worker():
            run([cmd], escalate=True)
            GLib.idle_add(self._after_toggle)

        import threading
        threading.Thread(target=worker, daemon=True).start()

    def _after_toggle(self):
        self._busy = False
        self.toggle_item.set_sensitive(True)
        self.refresh()

    def on_open_window(self, _item):
        # The main GUI is a single-instance Adw.Application: if it's already
        # running this just re-presents its existing window instead of
        # starting a second copy.
        subprocess.Popen([APP_BIN, "gui"], start_new_session=True)


def main():
    Tray()
    Gtk.main()


if __name__ == "__main__":
    main()
