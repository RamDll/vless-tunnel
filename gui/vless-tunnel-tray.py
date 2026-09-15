#!/usr/bin/env python3
"""System tray indicator for vless-tunnel.

Deliberately a separate GTK3 process: libayatana-appindicator's menu is a
GTK3 widget, and GTK3/GTK4 cannot be loaded in the same process as the main
vless-tunnel-gui.py (which is GTK4/libadwaita). This process only shows
status and does a quick on/off toggle + opens the main window for everything
else — no logic is duplicated beyond a minimal status/on/off call.
"""
import json
import subprocess
import threading

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("AyatanaAppIndicator3", "0.1")
from gi.repository import AyatanaAppIndicator3 as AppIndicator, GLib, Gtk  # noqa: E402

from vless_tunnel_common import APP_BIN, run  # noqa: E402

APP_ID = "vless-tunnel-tray"
POLL_SECONDS = 30


def get_status():
    rc, out, _err = run(["status", "--json"], escalate=False)
    if rc != 0:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def run_async(args, on_done, timeout=15, escalate=False):
    def worker():
        rc, out, err = run(args, timeout=timeout, escalate=escalate)
        GLib.idle_add(on_done, rc, out, err)

    threading.Thread(target=worker, daemon=True).start()


def show_text_dialog(title, body):
    dlg = Gtk.Dialog(title=title)
    dlg.set_default_size(560, 420)
    dlg.add_button("Закрыть", Gtk.ResponseType.CLOSE)
    scroller = Gtk.ScrolledWindow()
    scroller.set_hexpand(True)
    scroller.set_vexpand(True)
    view = Gtk.TextView(editable=False, cursor_visible=False, monospace=True,
                         left_margin=8, right_margin=8, top_margin=8, bottom_margin=8)
    view.get_buffer().set_text(body or "(пусто)")
    scroller.add(view)
    box = dlg.get_content_area()
    box.pack_start(scroller, True, True, 0)
    dlg.show_all()
    dlg.connect("response", lambda d, _r: d.destroy())


class Tray:
    def __init__(self):
        self.indicator = AppIndicator.Indicator.new(
            APP_ID, "vless-tunnel-unknown",
            AppIndicator.IndicatorCategory.APPLICATION_STATUS,
        )
        self.indicator.set_status(AppIndicator.IndicatorStatus.ACTIVE)
        self.indicator.set_title("VLESS Tunnel")
        self.indicator.set_label("VLESS", "VLESS")  # text next to the icon in the panel

        self.menu = Gtk.Menu()

        self.status_item = Gtk.MenuItem()
        self.status_item.set_sensitive(False)
        self.status_label = Gtk.Label(label="Проверяю…", xalign=0, use_markup=True)
        self.status_item.add(self.status_label)
        self.menu.append(self.status_item)

        self.menu.append(Gtk.SeparatorMenuItem())

        self.toggle_item = Gtk.MenuItem(label="Включить/выключить")
        self.toggle_item.connect("activate", self.on_toggle)
        self.menu.append(self.toggle_item)

        open_item = Gtk.MenuItem(label="Открыть окно")
        open_item.connect("activate", self.on_open_window)
        self.menu.append(open_item)

        self._autostart_guard = True
        self.autostart_item = Gtk.CheckMenuItem(label="Автозапуск при загрузке")
        self.autostart_item.connect("toggled", self.on_autostart_toggled)
        self.menu.append(self.autostart_item)

        more_item = Gtk.MenuItem(label="Ещё")
        more_menu = Gtk.Menu()
        for label, args, title in (
            ("Проверить туннель", ["test"], "Проверка туннеля"),
            ("Показать журнал", ["logs", "--lines", "200"], "Журнал"),
            ("Диагностика", ["doctor"], "Диагностика"),
        ):
            sub = Gtk.MenuItem(label=label)
            sub.connect("activate", self._make_report_handler(args, title))
            more_menu.append(sub)
        more_item.set_submenu(more_menu)
        self.menu.append(more_item)

        self.menu.append(Gtk.SeparatorMenuItem())

        quit_item = Gtk.MenuItem(label="Выход")
        quit_item.connect("activate", self.on_quit)
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
        # get_status() shells out (sudo -n ...); never call it directly on
        # the GTK main loop or a slow/contended call freezes the whole
        # panel icon and menu until it returns.
        def worker():
            status = get_status()
            GLib.idle_add(self._apply_status, status)

        threading.Thread(target=worker, daemon=True).start()

    def _apply_status(self, status):
        if status is None or status.get("installed") is False:
            self.indicator.set_icon_full("vless-tunnel-unknown", "не настроено")
            self.status_label.set_markup("Туннель не настроен")
            self.toggle_item.set_sensitive(False)
            self.autostart_item.set_sensitive(False)
            return
        self.toggle_item.set_sensitive(True)
        self.autostart_item.set_sensitive(True)
        self._autostart_guard = True
        self.autostart_item.set_active(bool(status.get("enabled")))
        self._autostart_guard = False
        active = bool(status.get("active"))
        server = status.get("server", "")
        if active:
            self.indicator.set_icon_full("vless-tunnel-on", "включён")
            markup = '<span color="#2e7d4f"><b>Туннель ON</b></span>'
            if server:
                markup += f"\n{GLib.markup_escape_text(server)}"
            self.status_label.set_markup(markup)
            self.toggle_item.set_label("Выключить")
        else:
            self.indicator.set_icon_full("vless-tunnel-off", "выключен")
            self.status_label.set_markup('<span color="#b23a2e"><b>Туннель OFF</b></span>')
            self.toggle_item.set_label("Включить")

    def on_toggle(self, _item):
        self._busy = True
        self.toggle_item.set_sensitive(False)

        def worker():
            run(["toggle"], escalate=True)
            GLib.idle_add(self._after_toggle)

        threading.Thread(target=worker, daemon=True).start()

    def _after_toggle(self):
        self._busy = False
        self.toggle_item.set_sensitive(True)
        self.refresh()

    def _make_report_handler(self, args, title):
        def handler(_item):
            def done(rc, out, err):
                show_text_dialog(title, out or err)

            run_async(args, done)

        return handler

    def on_autostart_toggled(self, item):
        if self._autostart_guard:
            return
        run_async(["autostart", "on" if item.get_active() else "off"], lambda *_a: None, escalate=True)

    def on_open_window(self, _item):
        # The main GUI is a single-instance Adw.Application: if it's already
        # running this just re-presents its existing window instead of
        # starting a second copy.
        subprocess.Popen([APP_BIN, "gui"], start_new_session=True)

    def on_quit(self, _item):
        status = get_status()
        if status and status.get("active"):
            run(["off"], escalate=True)
        Gtk.main_quit()


def main():
    Tray()
    Gtk.main()


if __name__ == "__main__":
    main()
