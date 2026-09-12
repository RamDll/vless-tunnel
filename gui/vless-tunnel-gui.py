#!/usr/bin/env python3
"""GTK4/libadwaita GUI for vless-tunnel. Talks to the installed CLI only —
all tunnel logic stays in vless-tunnel.sh; this file just shells out to it."""
import json
import os
import subprocess
import threading

import gi

gi.require_version("Gtk", "4.0")
gi.require_version("Adw", "1")
from gi.repository import Adw, GLib, Gtk  # noqa: E402

# Must exactly match the installed .desktop file's basename (see
# packaging/desktop/) — otherwise GNOME can't find its Icon= entry for the
# taskbar/alt-tab and falls back to a generated initials icon.
APP_ID = "io.github.ramdll.VlessTunnel"
APP_BIN = os.environ.get("VLESS_APP_BIN", "vless-tunnel")
_DEMO_MODE = os.environ.get("VLESS_GUI_DEMO", "")
DEMO = _DEMO_MODE in ("1", "onboarding")

DEMO_STATUS = {
    "server": "203.0.113.45",
    "server_port": 443,
    "network": "xhttp",
    "security": "reality",
    "sni": "cdn.jsdelivr.net",
    "core_running_version": "26.3.27",
    "socks_port": 10808,
    "http_port": 10809,
    "active": True,
    "enabled": False,
    "installed": True,
}
DEMO_IP = {"live": "203.0.113.45", "direct": "185.71.9.201"}


# ------------------------------------------------------------------ backend
def run(args, input_text=None, timeout=30, escalate=True):
    """Run `sudo -n vless-tunnel <args>`, return (rc, stdout, stderr).

    Everyday commands work silently once `install` has written the NOPASSWD
    sudoers rule. Before that (first run, or if the rule is missing for any
    reason), `sudo -n` refuses to even start the command — the exact wording
    varies ("a password is required", "interactive authentication is
    required", ...), but sudo's own refusals are always prefixed "sudo:",
    unlike output from vless-tunnel itself. When `escalate` is true we treat
    any such refusal as "needs a graphical prompt" and retry once through
    `pkexec`.
    """
    if DEMO:
        return _demo_run(args, input_text)
    cmd = ["sudo", "-n", APP_BIN, *args]
    try:
        p = subprocess.run(
            cmd, input=input_text, capture_output=True, text=True, timeout=timeout
        )
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)
    if escalate and p.returncode != 0 and (p.stderr or "").strip().startswith("sudo:"):
        try:
            p = subprocess.run(
                ["pkexec", APP_BIN, *args],
                input=input_text, capture_output=True, text=True, timeout=max(timeout, 180),
            )
        except Exception as exc:  # noqa: BLE001
            return 1, "", str(exc)
    return p.returncode, p.stdout, p.stderr


def _demo_run(args, input_text):
    global _demo_active, _demo_installed
    if args[:1] == ["status"]:
        st = dict(DEMO_STATUS)
        st["active"] = _demo_active
        st["installed"] = _demo_installed
        return 0, json.dumps(st), ""
    if args[:1] == ["install"]:
        _demo_installed = True
        _demo_active = True
        return 0, "[ok] служба запущена, туннель проверен (внешний IP: 203.0.113.45) (демо-режим)", ""
    if args[:1] == ["on"]:
        _demo_active = True
        return 0, "[ok] туннель включён и проверен (внешний IP: 203.0.113.45)", ""
    if args[:1] == ["off"]:
        _demo_active = False
        return 0, "[ok] туннель выключен", ""
    if args[:1] == ["test"]:
        return 0, "[ok] Туннель работает.\n(демо-режим, реальная проверка не выполнялась)", ""
    if args[:1] == ["logs"]:
        return 0, "Sep 12 10:06:25 xray[1166]: Xray 26.3.27 started\n(демо-режим)", ""
    if args[:1] == ["doctor"]:
        return 0, "[ok] ВЕРДИКТ: туннель включён, правила и конфиг согласованы\n(демо-режим)", ""
    if args[:1] == ["set-link"]:
        return 0, "[ok] сервер изменён (демо-режим)", ""
    if args[:1] == ["uninstall"]:
        return 0, "[ok] vless-tunnel удалён (демо-режим)", ""
    if args[:1] == ["autostart"]:
        return 0, "[ok] автозапуск обновлён (демо-режим)", ""
    return 0, "", ""


_demo_active = True
_demo_installed = _DEMO_MODE != "onboarding"


def run_async(args, on_done, input_text=None, timeout=30, escalate=True):
    """Run a backend command off the UI thread, deliver result via GLib.idle_add."""

    def worker():
        rc, out, err = run(args, input_text=input_text, timeout=timeout, escalate=escalate)
        GLib.idle_add(on_done, rc, out, err)

    threading.Thread(target=worker, daemon=True).start()


def run_raw_privileged(cmd, timeout=180):
    """Run an arbitrary root command straight through `pkexec`.

    Used only for the one action that is deliberately NOT in the fixed
    NOPASSWD sudoers list (removing the .deb package itself) — such a
    destructive, rare action should always ask for a password, even once
    the tunnel is otherwise configured.
    """
    if DEMO:
        return 0, "(демо-режим, команда не выполнялась)", ""
    try:
        p = subprocess.run(["pkexec", *cmd], capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as exc:  # noqa: BLE001
        return 1, "", str(exc)


def run_async_raw(cmd, on_done, timeout=180):
    def worker():
        rc, out, err = run_raw_privileged(cmd, timeout=timeout)
        GLib.idle_add(on_done, rc, out, err)

    threading.Thread(target=worker, daemon=True).start()


# --------------------------------------------------------------------- text
def transport_label(status):
    net = (status.get("network") or "").upper()
    sec = (status.get("security") or "").capitalize()
    return " · ".join(p for p in (net, sec) if p)


def make_info_row(title, value_widget, dot=None):
    """One row of the boxed info list: title on the left, value on the right —
    the same label/value layout as the approved HTML mockup's `.toprow`.
    `dot` is an optional status-dot widget shown right before the title."""
    row = Gtk.ListBoxRow(activatable=False, selectable=False)
    box = Gtk.Box(spacing=12, margin_top=10, margin_bottom=10, margin_start=14, margin_end=14)
    title_box = Gtk.Box(spacing=8)
    if dot is not None:
        title_box.append(dot)
    title_box.append(Gtk.Label(label=title, xalign=0, css_classes=["dim-label"]))
    box.append(title_box)
    value_widget.set_hexpand(True)
    value_widget.set_halign(Gtk.Align.END)
    box.append(value_widget)
    row.set_child(box)
    return row


def mono_label(text="—"):
    return Gtk.Label(label=text, xalign=1, css_classes=["mono-value"])


# ---------------------------------------------------------------- text view
class TextViewer(Adw.Window):
    def __init__(self, parent, title, body):
        super().__init__(transient_for=parent, modal=True, default_width=620, default_height=460)
        toolbar = Adw.ToolbarView()
        toolbar.add_top_bar(Adw.HeaderBar())
        scroller = Gtk.ScrolledWindow(vexpand=True, hexpand=True)
        view = Gtk.TextView(
            editable=False,
            cursor_visible=False,
            monospace=True,
            top_margin=10,
            bottom_margin=10,
            left_margin=12,
            right_margin=12,
        )
        view.get_buffer().set_text(body or "(пусто)")
        scroller.set_child(view)
        toolbar.set_content(scroller)
        self.set_content(toolbar)
        self.set_title(title)


# ---------------------------------------------------------------- set-link
class SetLinkDialog(Adw.Window):
    """Used both for the first-time setup (`install`) and for later
    `set-link` calls — same paste-a-link UI, different backend command."""

    def __init__(self, parent, on_applied, mode="set-link"):
        self.mode = mode
        title = "Настроить туннель" if mode == "install" else "Сменить сервер"
        apply_label = "Установить" if mode == "install" else "Применить"
        super().__init__(
            transient_for=parent, modal=True, default_width=520, default_height=340,
            title=title,
        )
        self.on_applied = on_applied
        toolbar = Adw.ToolbarView()
        header = Adw.HeaderBar(show_end_title_buttons=False)
        cancel = Gtk.Button(label="Назад")
        cancel.connect("clicked", lambda *_: self.close())
        header.pack_start(cancel)
        self.apply_btn = Gtk.Button(label=apply_label, css_classes=["suggested-action"])
        self.apply_btn.connect("clicked", self._apply)
        header.pack_end(self.apply_btn)
        toolbar.add_top_bar(header)

        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10,
                       margin_top=14, margin_bottom=14, margin_start=14, margin_end=14)
        hint_text = (
            "Вставьте vless://-ссылку — можно вместе с текстом (например, "
            "целым сообщением от панели), ссылка будет найдена сама."
        )
        if mode == "install":
            hint_text += " Потребуется один раз подтвердить пароль администратора."
        hint = Gtk.Label(label=hint_text, wrap=True, xalign=0, css_classes=["dim-label"])
        box.append(hint)
        scroller = Gtk.ScrolledWindow(vexpand=True, css_classes=["card"])
        self.entry = Gtk.TextView(monospace=True, top_margin=8, bottom_margin=8,
                                   left_margin=8, right_margin=8)
        scroller.set_child(self.entry)
        box.append(scroller)
        toolbar.set_content(box)
        self.set_content(toolbar)

    def _apply(self, _btn):
        buf = self.entry.get_buffer()
        text = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True).strip()
        if not text:
            return
        self.apply_btn.set_sensitive(False)
        self.apply_btn.set_label("Устанавливаю…" if self.mode == "install" else "Применяю…")

        def done(rc, out, err):
            self.close()
            self.on_applied(rc, out or err)

        cmd = ["install", "--yes", "--link-stdin"] if self.mode == "install" else ["set-link", "--link-stdin"]
        run_async(cmd, done, input_text=text + "\n", timeout=120)


# -------------------------------------------------------------------- main
class VlessTunnelWindow(Adw.ApplicationWindow):
    def __init__(self, app):
        super().__init__(application=app, title="VLESS Tunnel",
                          default_width=340, resizable=False)

        toolbar = Adw.ToolbarView()

        header = Adw.HeaderBar()
        # Left-aligned title (icon + name) instead of the default centered
        # one — pack_start widgets sit at the edge, unlike the title-widget
        # slot, which libadwaita always centers regardless of its content.
        title_box = Gtk.Box(spacing=6)
        title_box.append(Gtk.Image.new_from_icon_name("vless-tunnel"))
        title_box.append(Gtk.Label(label="VLESS Tunnel", css_classes=["title"]))
        header.pack_start(title_box)
        header.set_title_widget(Gtk.Label())  # suppress the default centered title

        menu_btn = Gtk.MenuButton(icon_name="open-menu-symbolic")
        menu_btn.set_popover(self._build_actions_popover())
        header.pack_end(menu_btn)

        toolbar.add_top_bar(header)

        self.view_stack = Gtk.Stack(transition_type=Gtk.StackTransitionType.CROSSFADE)

        # --- onboarding view (shown until a link has been configured) ------
        onboarding = Gtk.Box(
            orientation=Gtk.Orientation.VERTICAL, spacing=12,
            valign=Gtk.Align.CENTER, halign=Gtk.Align.CENTER,
            margin_top=40, margin_bottom=40, margin_start=24, margin_end=24,
        )
        onb_icon = Gtk.Image.new_from_icon_name("network-vpn-symbolic")
        onb_icon.set_pixel_size(48)
        onboarding.append(onb_icon)
        onboarding.append(Gtk.Label(label="Туннель ещё не настроен", css_classes=["title-2"]))
        onboarding.append(Gtk.Label(
            label="Вставьте вашу ссылку vless://, чтобы поднять туннель. "
                  "Потребуется один раз подтвердить пароль администратора.",
            wrap=True, justify=Gtk.Justification.CENTER, css_classes=["dim-label"],
            max_width_chars=34,
        ))
        onb_btn = Gtk.Button(label="Настроить", css_classes=["suggested-action", "pill"])
        onb_btn.set_margin_top(6)
        onb_btn.connect("clicked", lambda *_: self.action_install())
        onboarding.append(onb_btn)
        self.view_stack.add_named(onboarding, "onboarding")

        root = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=14,
                        margin_top=0, margin_bottom=14, margin_start=14, margin_end=14)

        # --- hero card -------------------------------------------------
        # (margins go on the inner content, not on `hero` itself, so the
        # card's own background spans the full width — same as the list below)
        hero = Gtk.Box(css_classes=["card"], spacing=12)

        text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4, hexpand=True,
                            margin_top=14, margin_bottom=14, margin_start=14)
        self.status_label = Gtk.Label(label="Проверяю…", css_classes=["title-3"], xalign=0)
        text_box.append(self.status_label)
        self.ip_label = Gtk.Label(label="", css_classes=["dim-label", "mono-value"], xalign=0, wrap=True)
        text_box.append(self.ip_label)

        self.power_switch = Gtk.Switch(valign=Gtk.Align.CENTER, css_classes=["power-switch"],
                                        margin_top=14, margin_bottom=14, margin_end=14)
        self.power_switch.connect("state-set", self._on_power_switch)

        hero.append(text_box)
        hero.append(self.power_switch)
        root.append(hero)

        # --- info list: outline only (no fill), label left / value right
        listbox = Gtk.ListBox(css_classes=["boxed-list", "outline-list"], selection_mode=Gtk.SelectionMode.NONE)

        self.val_server = mono_label()
        listbox.append(make_info_row("Сервер", self.val_server))

        self.transport_badge = Gtk.Label(label="—")
        listbox.append(make_info_row("Транспорт", self.transport_badge))

        self.val_core = mono_label()
        listbox.append(make_info_row("Ядро", self.val_core))

        proxy_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2, halign=Gtk.Align.END)
        self.val_socks = mono_label()
        self.val_http = mono_label()
        proxy_box.append(self.val_socks)
        proxy_box.append(self.val_http)
        self.proxy_dot = Gtk.Box(width_request=10, height_request=10, css_classes=["status-dot"], valign=Gtk.Align.CENTER)
        listbox.append(make_info_row("Прокси", proxy_box, dot=self.proxy_dot))

        self.autostart_switch = Gtk.Switch(valign=Gtk.Align.CENTER, css_classes=["power-switch"])
        self.autostart_switch.connect("state-set", self._on_autostart_toggled)
        self._autostart_guard = True
        listbox.append(make_info_row("Автозапуск при загрузке", self.autostart_switch))

        root.append(listbox)

        self.view_stack.add_named(root, "configured")

        toolbar.set_content(self.view_stack)
        self._toast_overlay = Adw.ToastOverlay()
        self._toast_overlay.set_child(toolbar)
        self.set_content(self._toast_overlay)

        css = Gtk.CssProvider()
        css.load_from_data(b"""
            /* teal accent, matching the approved mockup, instead of stock Adwaita blue */
            @define-color accent_color #0f7a68;
            @define-color accent_bg_color #0f7a68;
            @define-color accent_fg_color #fbfffd;

            /* both switches (power + autostart) render at the same fixed size,
               regardless of which container they sit in */
            switch.power-switch { min-width: 38px; min-height: 20px; }
            switch.power-switch slider {
                min-width: 16px;
                min-height: 16px;
                border-radius: 9999px;
                margin: 2px;
            }

            .status-dot {
                border-radius: 999px;
                background-color: @borders;
            }
            .status-dot.on {
                background-color: #2e7d4f;
                box-shadow: 0 0 0 3px alpha(#2e7d4f, 0.22);
            }
            .status-dot.off {
                background-color: #b23a2e;
                box-shadow: 0 0 0 3px alpha(#b23a2e, 0.22);
            }
            .danger-row, .danger-row image, .danger-row label { color: #b23a2e; }
            .mono-value { font-family: monospace; font-size: 0.95em; }
            /* outline only, no fill - as opposed to the solid hero card above */
            list.outline-list {
                background: none;
                border: 1px solid @borders;
                border-radius: 12px;
            }
            list.outline-list row { background: none; }
            /* row separators should match the box's own outer border, not the
               theme's default (slightly different) separator color */
            list.outline-list row:not(:last-child) {
                border-bottom: 1px solid @borders;
            }
            list.outline-list separator {
                background: none;
                min-height: 1px;
                background-color: @borders;
            }
        """)
        Gtk.StyleContext.add_provider_for_display(
            self.get_display(), css, Gtk.STYLE_PROVIDER_PRIORITY_APPLICATION
        )

        self.refresh()

    # ------------------------------------------------------------ actions
    def _build_actions_popover(self):
        popover = Gtk.Popover()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2,
                       margin_top=6, margin_bottom=6, margin_start=6, margin_end=6)

        def add_row(icon, label, handler, destructive=False):
            btn = Gtk.Button(css_classes=["flat"])
            row = Gtk.Box(spacing=10)
            row.append(Gtk.Image.new_from_icon_name(icon))
            row.append(Gtk.Label(label=label, xalign=0, hexpand=True))
            btn.set_child(row)
            if destructive:
                btn.add_css_class("danger-row")
            btn.connect("clicked", lambda *_: (popover.popdown(), handler()))
            box.append(btn)

        add_row("network-server-symbolic", "Сменить сервер", self.action_set_link)
        add_row("network-transmit-receive-symbolic", "Проверить туннель", self.action_test)
        add_row("text-x-generic-symbolic", "Показать журнал", self.action_logs)
        add_row("utilities-system-monitor-symbolic", "Диагностика", self.action_doctor)
        box.append(Gtk.Separator(margin_top=4, margin_bottom=4))
        add_row("user-trash-symbolic", "Удалить", self.action_uninstall, destructive=True)

        popover.set_child(box)
        return popover

    def action_set_link(self):
        SetLinkDialog(self, self._after_set_link).present()

    def _after_set_link(self, rc, output):
        self.refresh()
        self._toast("Сервер изменён" if rc == 0 else "Не удалось применить ссылку")

    def action_install(self):
        SetLinkDialog(self, self._after_install, mode="install").present()

    def _after_install(self, rc, output):
        self.refresh()
        if rc == 0:
            self._toast("Туннель настроен")
        else:
            TextViewer(self, "Не удалось установить", output).present()

    def action_test(self):
        self._toast("Проверяю туннель…")
        run_async(["test"], lambda rc, out, err: TextViewer(self, "Проверка туннеля", out or err).present())

    def action_logs(self):
        run_async(["logs", "--lines", "200"],
                   lambda rc, out, err: TextViewer(self, "Журнал", out or err).present())

    def action_doctor(self):
        run_async(["doctor"], lambda rc, out, err: TextViewer(self, "Диагностика", out or err).present())

    def action_uninstall(self):
        dlg = Adw.MessageDialog(
            transient_for=self, heading="Удалить vless-tunnel полностью?",
            body="Будут остановлены и удалены служба, конфиг, ядро Xray, sudoers-правило, "
                 "системный пользователь — и сам пакет vless-tunnel целиком (программа, "
                 "это окно, ярлык в меню). Действие необратимо. Потребуется подтвердить "
                 "пароль администратора. Поставить снова можно будет из .deb-файла.",
        )
        dlg.add_response("cancel", "Отмена")
        dlg.add_response("delete", "Удалить полностью")
        dlg.set_response_appearance("delete", Adw.ResponseAppearance.DESTRUCTIVE)

        def on_response(_d, response):
            if response != "delete":
                return

            def done(rc, out, err):
                if rc == 0:
                    self.get_application().quit()
                else:
                    TextViewer(self, "Не удалось удалить пакет", out or err).present()

            run_async_raw(["apt-get", "purge", "-y", "vless-tunnel"], done)

        dlg.connect("response", on_response)
        dlg.present()

    # -------------------------------------------------------------- power
    def _on_power_switch(self, switch, requested_state):
        cmd = "on" if requested_state else "off"

        def done(rc, out, err):
            if rc != 0:
                self._toast(f"Не удалось {'включить' if cmd == 'on' else 'выключить'} туннель")
            self.refresh()

        switch.set_sensitive(False)
        run_async([cmd], lambda rc, out, err: (switch.set_sensitive(True), done(rc, out, err)))
        return True  # we drive the actual state via refresh(), not the default handler

    def _on_autostart_toggled(self, switch, requested_state):
        if self._autostart_guard:
            return False
        run_async(["autostart", "on" if requested_state else "off"], lambda *_: None)
        return False  # let the switch move normally; this one isn't confirmed async

    # ------------------------------------------------------------ refresh
    def refresh(self):
        def done(rc, out, err):
            status = None
            if rc == 0:
                try:
                    status = json.loads(out)
                except json.JSONDecodeError:
                    status = None
            self._apply_status(status)

        # escalate=False: a passive status check on window open must never
        # pop up a graphical password prompt by itself.
        run_async(["status", "--json"], done, escalate=False)

    def _apply_status(self, status):
        if status is None or status.get("installed") is False:
            self.view_stack.set_visible_child_name("onboarding")
            return
        self.view_stack.set_visible_child_name("configured")

        active = bool(status.get("active"))
        self.status_label.set_label("Туннель включён" if active else "Туннель выключен")

        self.power_switch.handler_block_by_func(self._on_power_switch)
        self.power_switch.set_active(active)
        self.power_switch.set_state(active)  # Switch intercepts state-set, so the visual
        self.power_switch.handler_unblock_by_func(self._on_power_switch)  # thumb needs this too.

        server = status.get("server", "—")
        port = status.get("server_port", "")
        self.val_server.set_label(f"{server}:{port}" if port else server)
        self.transport_badge.set_label(transport_label(status) or "—")
        core = status.get("core_running_version") or status.get("core_version") or "—"
        self.val_core.set_label(f"Xray {core}")
        socks = status.get("socks_port", 10808)
        http = status.get("http_port", 10809)
        self.val_socks.set_label(f"socks5 127.0.0.1:{socks}")
        self.val_http.set_label(f"http 127.0.0.1:{http}")
        # the proxy ports only actually listen while the tunnel is running -
        # dim them the rest of the time so the row doesn't look connectable
        for lbl in (self.val_socks, self.val_http):
            if active:
                lbl.remove_css_class("dim-label")
            else:
                lbl.add_css_class("dim-label")
        self.proxy_dot.remove_css_class("on")
        self.proxy_dot.remove_css_class("off")
        self.proxy_dot.add_css_class("on" if active else "off")

        self._autostart_guard = True
        enabled = bool(status.get("enabled"))
        self.autostart_switch.set_active(enabled)
        self.autostart_switch.set_state(enabled)
        self._autostart_guard = False

        if DEMO:
            self.ip_label.set_label(f"Внешний IP: {DEMO_IP['live' if active else 'direct']}")
        else:
            self.ip_label.set_label("Внешний IP: проверяю…")
            self._refresh_ip(socks, active)

    def _refresh_ip(self, socks_port, active):
        def worker():
            try:
                if active:
                    cmd = ["curl", "-s", "--max-time", "5",
                           "--socks5-hostname", f"127.0.0.1:{socks_port}", "https://api.ipify.org"]
                else:
                    cmd = ["curl", "-s", "--max-time", "5", "https://api.ipify.org"]
                ip = subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout.strip()
            except Exception:  # noqa: BLE001
                ip = ""
            GLib.idle_add(self._set_ip_label, ip, active)

        threading.Thread(target=worker, daemon=True).start()

    def _set_ip_label(self, ip, active):
        if ip:
            self.ip_label.set_label(f"Внешний IP: {ip}")
        else:
            self.ip_label.set_label("Внешний IP: не удалось проверить")

    def _toast(self, text):
        overlay = getattr(self, "_toast_overlay", None)
        if overlay is None:
            return
        overlay.add_toast(Adw.Toast(title=text, timeout=3))


class VlessTunnelApp(Adw.Application):
    def __init__(self):
        super().__init__(application_id=APP_ID)

    def do_activate(self):
        win = self.props.active_window or VlessTunnelWindow(self)
        win.present()


if __name__ == "__main__":
    VlessTunnelApp().run()
