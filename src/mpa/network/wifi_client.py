#
# Copyright (c) 2025 Contributors to the Eclipse Foundation.
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License, Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
#
"""
Helpers for wifi client basic network connections configuration.
"""

# Standard imports
from collections import defaultdict
import sys
from threading import Event
from typing import Any, Dict, List, Optional, Union

# Local imports
from mpa.common.common import RESPONSE_OK
from mpa.common.logger import Logger
from mpa.communication.common import (
    InvalidParameterError,
    InvalidPreconditionError,
    NetworkManagerError,
    NMDeviceActivationError
)
from mpa.communication.message_parser import get_str, get_enum_str, get_enum_str_list
from mpa.network.wifi_common import (
    ConnectionCbInfo,
    create_wifi_connection,
    device_reason_to_string,
    error_is_cancelled,
    get_access_point_dbus_path,
    get_devices,
    get_ssid_as_utf8,
    NM_AP_FLAGS,
    NM_AP_FLAGS_SEC,
    NM_AP_MODE,
    ScanInfo,
    WifiListData
)

# This ugly non-pep8 compliant importing sequence is required by gi module
import gi  # type: ignore
gi.require_version("NM", "1.0")  # Use before import to ensure that the right version gets loaded
# all PyGObject API Reference can be read in below link
# https://lazka.github.io/pgi-docs/
from gi.repository import NM, GLib, Gio, GObject  # type: ignore # noqa: E402

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


def wifi_client_scan(nmc: NM.Client, rescan: str) -> Dict[Any, defaultdict[str, List[Dict[str, Any]]]]:
    match rescan:
        case "auto":
            rescan_cutoff_msec = NM.utils_get_timestamp_msec() - 30000
        case "no":
            rescan_cutoff_msec = GLib.MININT64
        case "yes":
            rescan_cutoff_msec = NM.utils_get_timestamp_msec()
        case _:
            raise InvalidParameterError(
                    f"Parameter rescan invalid choice: f{rescan} (choose from 'auto', 'yes', 'no')"
            )

    networks = {}
    event = Event()
    loop = GLib.MainLoop()

    def device_wifi_get_last_scan(wifi: NM.DeviceWifi) -> int:
        timestamp = wifi.get_last_scan()
        if (timestamp == -1):
            return GLib.MININT64  # type: ignore  # mypy does not recognize types
        return timestamp  # type: ignore  # mypy does not recognize types

    def wifi_list_finish(wifi_list_data: WifiListData, *, force_finished: bool) -> None:
        scan_info = wifi_list_data.scan_info

        if (not force_finished and
                # scan_info.rescan_cutoff_msec > device_wifi_get_last_scan(wifi_list_data.wifi_device)):
                rescan_cutoff_msec > device_wifi_get_last_scan(wifi_list_data.wifi_device)):
            # wait longer...
            return

        if (wifi_list_data.timeout_id):
            GObject.signal_handler_disconnect(wifi_list_data.wifi_device, wifi_list_data.last_scan_id)
            wifi_list_data.last_scan_id = 0
        if (wifi_list_data.timeout_id):
            GLib.source_remove(wifi_list_data.timeout_id)
            wifi_list_data.timeout_id = 0
        if (wifi_list_data.scan_cancellable):
            wifi_list_data.scan_cancellable.cancel()
            wifi_list_data.scan_cancellable = None

        scan_info.pending -= 1
        if (scan_info.pending > 0):
            return

        def frequency_to_band(frequency: int) -> str:
            match frequency:
                case freq if 5955 <= freq <= 7115:
                    return "6 GHz"
                case freq if 4915 <= freq <= 5825:
                    return "5 GHz"
                case freq if 2412 <= freq <= 2484:
                    return "2.4 Ghz"
                case _:
                    return "Unknown"

        def mode_to_string(mode: int) -> str:
            match mode:
                case NM_AP_MODE.ADHOC:
                    return "adhoc"
                case NM_AP_MODE.INFRA:
                    return "infra"
                case NM_AP_MODE.AP:
                    return "ap"
                case NM_AP_MODE.MESH:
                    return "mesh"
                case _:
                    return "unknown"

        def flags_to_security(flags: int, wpa_flags: int, rsn_flags: int) -> str:
            def any_flag_matches(flags: int, check: int) -> bool:
                return (((flags) & (check)) != 0)

            security = ""
            if (
                flags & NM_AP_FLAGS.PRIVACY and
                wpa_flags == NM_AP_FLAGS_SEC.NONE and
                rsn_flags == NM_AP_FLAGS_SEC.NONE
            ):
                security = security + " WEP"
            if wpa_flags != NM_AP_FLAGS_SEC.NONE:
                security = security + " WPA1"
            if (rsn_flags & NM_AP_FLAGS_SEC.KEY_MGMT_PSK) or (rsn_flags & NM_AP_FLAGS_SEC.KEY_MGMT_802_1X):
                security = security + " WPA2"
            if (rsn_flags & NM_AP_FLAGS_SEC.KEY_MGMT_SAE):
                security = security + " WPA3"
            if (any_flag_matches(rsn_flags, NM_AP_FLAGS_SEC.KEY_MGMT_OWE | NM_AP_FLAGS_SEC.KEY_MGMT_OWE_TM)):
                security = security + " OWE"
            if (wpa_flags & NM_AP_FLAGS_SEC.KEY_MGMT_802_1X) or (rsn_flags & NM_AP_FLAGS_SEC.KEY_MGMT_802_1X):
                security = security + " 802.1X"
            return security.lstrip()

        for device in scan_info.wifi_devices:
            access_points_info = defaultdict(list)
            active_access_point = device.get_active_access_point()
            active_access_point_ssid = get_ssid_as_utf8(active_access_point)
            active_access_point_bssid = active_access_point.get_bssid() if active_access_point else ""
            for access_point in device.get_access_points():
                ssid = get_ssid_as_utf8(access_point)
                bssid = access_point.get_bssid()
                access_points_info[ssid].append({
                    'in_use': active_access_point_ssid == ssid and bssid == active_access_point_bssid,
                    'bssid': bssid,
                    'band': frequency_to_band(access_point.get_frequency()),
                    'channel': NM.utils_wifi_freq_to_channel(access_point.get_frequency()),
                    'mode': mode_to_string(access_point.get_mode()),
                    'strength': access_point.get_strength(),
                    'security': flags_to_security(access_point.get_flags(),
                                                  access_point.get_wpa_flags(),
                                                  access_point.get_rsn_flags())
                })
            networks.update({device.get_iface(): access_points_info})

        # UNDER ANY CIRCUMSTANCES DO NOT TOUCH THIS, AS IT IS INTENTIONALLY PUTTED IN HERE
        loop.quit()
        event.set()

    def wifi_list_scan_timeout(data: WifiListData) -> bool:
        data.timeout_id = 0
        wifi_list_finish(data, force_finished=True)
        return GLib.SOURCE_REMOVE  # type: ignore  # mypy does not recognize types

    def wifi_last_scan_updated(dev: NM.DeviceWifi, result: Gio.AsyncResult, data: WifiListData) -> None:
        wifi_list_finish(data, force_finished=False)

    def wifi_list_rescan_cb(device: NM.DeviceWifi, result: Gio.AsyncResult, data: WifiListData) -> None:
        try:
            device.request_scan_finish(result)
        except GLib.Error as error:
            if (error_is_cancelled(error)):
                return

            if error.matches(NM.DeviceError, NM.DeviceError.NOTALLOWED) is True:
                if (device.get_state() < NM.DeviceState.DISCONNECTED):
                    # the device is either unmanaged or unavailable.

                    # If it's unmanaged, we don't expect any scan result and are done.
                    # If it's unavailable, that usually means that we wait for wpa_supplicant
                    # to start. In that case, also quit (without scan results).
                    force_finished = True
                    done = True
                else:
                    # This likely means that scanning is already in progress. There's
                    # good chance we'll get updated results soon; wait for them.

                    # But also, NetworkManager ratelimits (and rejects requests). That
                    # means, possibly we were just ratelimited, so waiting will not lead
                    # to a new scan result. Instead, repeatedly ask new scans...
                    # TODO: this part of C code has to be written
                    # nm_utils_invoke_on_timeout(1000,
                    #                            wifi_list_data->scan_cancellable,
                    #                            wifi_list_rescan_retry_cb,
                    #                            wifi_list_data)
                    force_finished = False
                    done = False
            else:
                force_finished = True
                done = True
        else:
            force_finished = False
            done = True

        if done is True:
            data.scan_cancellable = None
        wifi_list_finish(data, force_finished=force_finished)

    try:
        wifi_devices = get_devices(nmc, NM.DeviceType.WIFI)
        scan_info = ScanInfo(wifi_devices=wifi_devices)
        for wifi_device in wifi_devices:
            if (rescan_cutoff_msec <= device_wifi_get_last_scan(wifi_device)):
                timeout_msec = 0
            else:
                timeout_msec = 15000

            wifi_list_data = WifiListData(wifi_device=wifi_device, scan_info=scan_info)
            wifi_list_data.timeout_id = GLib.timeout_add(timeout_msec, wifi_list_scan_timeout, wifi_list_data)

            scan_info.pending += 1

            if (timeout_msec > 0):
                wifi_list_data.last_scan_id = wifi_device.connect("notify::last-scan",
                                                                  wifi_last_scan_updated,
                                                                  wifi_list_data)
                wifi_list_data.scan_cancellable = Gio.Cancellable().new()
                wifi_device.request_scan_async(wifi_list_data.scan_cancellable, wifi_list_rescan_cb, wifi_list_data)
    except GLib.Error as error:
        raise NetworkManagerError(error.message)

    # UNDER ANY CIRCUMSTANCES DO NOT TOUCH THIS AS IT IS INTENTIONALLY PUTTED IN HERE
    # AS IT MANAGES ALL THE AVAILABLE SOURCES OF EVENTS FOR GLIB AND GTK+ APPLICATIONS
    #
    # https://www.gnu.org/software/guile-gnome/docs/glib/html/The-Main-Event-Loop.html
    loop.run()
    event.wait()  # waiting for event to be set

    return networks


# TODO: dict[str, Any] should be replaced into always predictable dict
# meaning that Any is a dict with `str` key and values are 3 'str' and 4th
# is a list[str]
def wifi_client_set_config(nmc: NM.Client, network_config: Dict[str, Any]) -> str:
    response: Union[str, Exception] = ""
    ifname = next(iter(network_config.keys()))
    config = network_config[ifname]
    ssid = get_str(config, 'ssid')
    key = get_str(config, 'key')
    authentication = get_enum_str(config, 'authentication', ['auto', 'wpa-psk', 'wpa2-psk', 'wpa3-sae'])
    if authentication == 'wpa-psk' or authentication == 'wpa2-psk':
        allowed_ciphers = [['auto'], ['ccmp'], ['tkip'], ['ccmp', 'tkip']]
    else:
        allowed_ciphers = [['auto'], ['ccmp']]
    encryption = get_enum_str_list(config, 'encryption', allowed_ciphers)
    logger.info(f"config: set 'ssid' value '{ssid}'")
    logger.info("config: set 'key' value '<hidden>'")
    logger.info(f"config: set 'authentication' value '{authentication}'")
    logger.info(f"config: set 'encryption' value '{' '.join(encryption)}'")
    wifi = nmc.get_device_by_iface(ifname)
    if wifi is None:
        raise InvalidPreconditionError(f"Device {ifname} is not available")

    available_connections = wifi.get_available_connections()
    connection = None
    if available_connections:
        required_connections = [c for c in available_connections if c.get_id() == ifname]
        if len(required_connections) == 1:
            connection = required_connections[0]
        elif len(required_connections) != 0:
            raise RuntimeError(f"More than one connection set for {ifname}")
    event = Event()
    loop = GLib.MainLoop()

    def connected_state_cb(target: Optional[Union[NM.DeviceWifi, NM.ActiveConnection]] = None,
                           param_spec: Optional[GObject.GEnum] = None,
                           active_connection: NM.ActiveConnection = None) -> None:
        state = wifi.get_state()
        active_connection_state = active_connection.get_state()

        if active_connection_state == NM.ActiveConnectionState.ACTIVATING:
            return

        nonlocal response
        if state == NM.DeviceState.ACTIVATED:
            response = f"{RESPONSE_OK} Device {wifi.get_iface()} successfully activated"
        elif state <= NM.DeviceState.DISCONNECTED or state >= NM.DeviceState.DEACTIVATING:
            response = NMDeviceActivationError(device_reason_to_string(wifi.get_state_reason()))
        else:
            logger.info(f"Ingored state change to: {state}")
            return

        active_connection.disconnect_by_func(connected_state_cb)
        wifi.disconnect_by_func(connected_state_cb)
        loop.quit()
        event.set()

    # callback function
    def add_and_activate_cb(client: NM.Client, result: Gio.AsyncResult,
                            active_connection: Optional[NM.ActiveConnection]) -> None:
        try:
            active_connection = client.add_and_activate_connection_finish(result)
            wifi.connect("notify::state", connected_state_cb, active_connection)
            active_connection.connect("notify::state", connected_state_cb, active_connection)
            connected_state_cb(active_connection=active_connection)
        except GLib.Error as error:
            loop.quit()
            nonlocal response
            response = NetworkManagerError(error.message)
            event.set()

    def add_and_activate_connection() -> None:
        connection = create_wifi_connection(ifname, ssid, key, authentication, encryption)
        dbus_path = None
        if authentication == 'auto':
            # this is for determining access point's parameters to fill up missing connection settings
            dbus_path = get_access_point_dbus_path(wifi, ssid)
        nmc.add_and_activate_connection_async(connection,
                                              wifi,
                                              dbus_path,
                                              None,
                                              add_and_activate_cb,
                                              None)

    def delete_cb(connection: NM.RemoteConnection, result: Gio.AsyncResult,
                  connection_cb_info: ConnectionCbInfo) -> None:
        try:
            connection.delete_finish(result)
            add_and_activate_connection()
        except (GLib.Error, InvalidParameterError) as error:
            loop.quit()
            nonlocal response
            if isinstance(error, GLib.Error):
                response = NetworkManagerError(error.message)
            else:
                response = error
            event.set()

    if connection is None:
        add_and_activate_connection()
    else:
        connection.delete_async(None, delete_cb, None)

    # UNDER ANY CIRCUMSTANCES DO NOT TOUCH THIS AS IT IS INTENTIONALLY PUTTED IN HERE
    # AS IT MANAGES ALL THE AVAILABLE SOURCES OF EVENTS FOR GLIB AND GTK+ APPLICATIONS
    #
    # https://www.gnu.org/software/guile-gnome/docs/glib/html/The-Main-Event-Loop.html
    loop.run()
    event.wait()  # waiting for event to be set

    if isinstance(response, Exception):
        raise response

    return response
