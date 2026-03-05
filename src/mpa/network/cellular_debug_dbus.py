from __future__ import annotations
from gi.repository import Gio, GLib
from mpa.common.logger import Logger
import sys

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

_MM_BUS = "org.freedesktop.ModemManager1"
_MM_IFACE = "org.freedesktop.ModemManager1.Modem"
_MM_SIM_IFACE = "org.freedesktop.ModemManager1.Sim"


def _unwrap(v):
    return None if v is None else v.unpack()


def find_objects_by_interface(
    connection: Gio.DBusConnection,
    interface: str,
) -> str | None:
    result = connection.call_sync(
        _MM_BUS,
        "/org/freedesktop/ModemManager1",
        "org.freedesktop.DBus.ObjectManager",
        "GetManagedObjects",
        None,
        GLib.VariantType("(a{oa{sa{sv}}})"),
        Gio.DBusCallFlags.NONE,
        -1,
        None,
    )
    objects: dict = _unwrap(result.get_child_value(0))
    iface = "org.freedesktop.ModemManager1.Modem"
    for path, ifaces in objects.items():
        if iface not in ifaces:
            continue
        ports = ifaces[iface].get("Ports", [])
        if any(entry[0] == interface for entry in ports if len(entry) >= 2):
            return path
    return None


def get_all(connection: Gio.DBusConnection, object_path: str,
            interface: str) -> dict:
    result = connection.call_sync(
        _MM_BUS,
        object_path,
        "org.freedesktop.DBus.Properties",
        "GetAll",
        GLib.Variant("(s)", (interface,)),
        GLib.VariantType("(a{sv})"),
        Gio.DBusCallFlags.NONE,
        -1,
        None,
    )
    return _unwrap(result.get_child_value(0))


def send_at(connection: Gio.DBusConnection, object_path: str, command: str):
    result = connection.call_sync(
            _MM_BUS,
            object_path,
            _MM_IFACE,
            "Command",
            GLib.Variant("(su)", (command, 5)),
            GLib.VariantType("(s)"),
            Gio.DBusCallFlags.NONE,
            (10) * 1000,
            None,
        )
    response = result.get_child_value(0).get_string()
    return response.strip()
