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
Helpers for wifi network connections configuration.
"""
from __future__ import annotations

# Standard imports
from dataclasses import dataclass, field
from functools import singledispatchmethod
from ipaddress import IPv4Network
import sys
from typing import Any, MutableMapping, Optional, Union, List, Callable, Set
import uuid

# Local imports
from mpa.common.common import RESPONSE_OK
from mpa.common.logger import Logger
from mpa.communication.common import (
    get_system_network_interfaces,
    InvalidParameterError,
    InvalidPreconditionError,
    NetworkManagerError
)

# This ugly non-pep8 compliant importing sequence is required by gi module
import gi  # type: ignore
gi.require_version("NM", "1.0")  # Use before import to ensure that the right version gets loaded
# all PyGObject API Reference can be read in below link
# https://lazka.github.io/pgi-docs/
from gi.repository import NM, GLib, Gio, GObject  # type: ignore # noqa: E402

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

# Common strings
NM_AP_MODE = getattr(NM, "80211Mode")
NM_AP_FLAGS = getattr(NM, "80211ApFlags")
NM_AP_FLAGS_SEC = getattr(NM, "80211ApSecurityFlags")


@dataclass
class ConnectionCbInfo:
    loop: GLib.MainLoop = None
    nmc: NM.Client = None
    nowait_flag: bool = False
    objects: list[NM.Object] = field(default_factory=list)
    timeout_id: int = 0
    cancellable: Gio.Cancellable = None


@dataclass
class ScanInfo:
    wifi_devices: list[NM.DeviceWifi] = field(default_factory=list)
    pending: int = 0


@dataclass
class WifiListData:
    scan_info: ScanInfo = None  # type: ignore  # TODO looks like bug in mypy?
    wifi_device: NM.DeviceWifi = None
    last_scan_id: int = 0
    timeout_id: int = 0
    scan_cancellable: Gio.Cancellable = None


def is_wifi_interface(inet: str) -> bool:
    return True if inet.startswith("wifi") else False


def get_wifi_interfaces() -> Set[str]:
    return set(filter(is_wifi_interface, get_system_network_interfaces()))


def find_connections(nmc: NM.Client, argv: list[str], connection_type: str,
                     active: bool = False) -> list[Union[NM.RemoteConnection, NM.ActiveConnection]]:
    # parse the inpurt argv and select the connection profiles to activate.
    # The arguments are either "connection.id", "connection.uuid" or "connection.ifname",
    # possibly qualified by "id", "uuid" or "ifname".

    result = []

    while True:
        if not argv:
            break
        arg_type = argv.pop(0)
        if arg_type in ["id", "uuid", "ifname"]:
            if not argv:
                raise InvalidParameterError(f"Missing specifier after {arg_type}")
            arg_param = argv.pop(0)
        else:
            arg_param = arg_type
            arg_type = "*"

        connections_list = []

        match active:
            case False:
                for connection in nmc.get_connections():
                    if connection_type is None or connection.get_connection_type() == connection_type:
                        if arg_type in ["id", "*"] and connection.get_id() == arg_param:
                            connections_list.append(connection)
                        if arg_type in ["uuid", "*"] and connection.get_uuid() == arg_param:
                            connections_list.append(connection)
                        if arg_type in ["ifname", "*"] and connection.get_interface_name() == arg_param:
                            connections_list.append(connection)

                if not connections_list:
                    raise InvalidPreconditionError(f"Could not find a matching connection for {arg_type} {arg_param}")
                else:
                    for x in connections_list:
                        logger.info(x.get_interface_name())
            case True:
                for active_connection in nmc.get_active_connections():
                    if connection_type is None or active_connection.get_connection_type() == connection_type:
                        if arg_type in ["id", "*"] and active_connection.get_id() == arg_param:
                            connections_list.append(active_connection)
                        if arg_type in ["uuid", "*"] and active_connection.get_uuid() == arg_param:
                            connections_list.append(active_connection)
                        # XXX: Currently this will be always just one device
                        # https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/issues/1108
                        wifi = active_connection.get_devices()[0]
                        if arg_type in ["ifname", "*"] and wifi.get_ip_iface() == arg_param:
                            connections_list.append(active_connection)

                if not connections_list:
                    raise InvalidPreconditionError(f"Could not find an active connection for {arg_type} {arg_param}")
            case _:
                pass

        if len(connections_list) > 1:
            raise InvalidPreconditionError(
                f"Could not find a unique matching connection for {arg_type} {arg_param}, "
                f"instead {len(connections_list)} profiles found"
            )

        if connections_list[0] not in result:
            # we allow duplicates, but combine them.
            result.extend(connections_list)

    for connection in result:
        logger.info(f"requested connection: {connection.get_id()} ({connection.get_uuid()}) ({connection.get_path()})")

    return result


class Activation(object):
    ACTIVATION_STATE_START = "start"
    ACTIVATION_STATE_STARTING = "starting"
    ACTIVATION_STATE_STOPPING = "stopping"
    ACTIVATION_STATE_WAITING = "waiting"
    ACTIVATION_STATE_DONE = "done"

    @singledispatchmethod  # type: ignore  # TODO looks like bug in mypy?
    def __init__(self, connection: Any) -> None:
        raise InvalidParameterError(f"unsupported connection object: {connection}")

    @__init__.register
    def _from_remote_connection(self, connection: NM.RemoteConnection) -> None:
        self.connection = connection
        self.state = Activation.ACTIVATION_STATE_START
        self.message = ""
        self.active_connection = None
        self.wait_id = 0

    @__init__.register
    def _from_active_connection(self, active_connection: NM.ActiveConnection) -> None:
        self.connection = active_connection.get_connection()
        self.state = Activation.ACTIVATION_STATE_START
        self.message = ""
        self.active_connection = active_connection
        self.wait_id = 0

    def __str__(self) -> str:
        return f"{self.connection.get_id()} ({self.connection.get_uuid()})"

    def _log_result(self, message: str, done_with_success: bool = False) -> bool:
        if done_with_success:
            logger.info(f"connection {self} done: {message}")
        else:
            logger.error(f"connection {self} done: {message}")
        self.state = Activation.ACTIVATION_STATE_DONE
        self.done_with_success = done_with_success
        return True

    def set_autoconnect(self, state: str) -> bool:
        setting_connection = self.connection.get_setting_connection()
        match state:
            case 'enable':
                setting_connection.props.autoconnect = True
            case 'disable':
                setting_connection.props.autoconnect = False
            case _:
                raise InvalidPreconditionError(f"Invalid state value {state}, should be one of (enable or disable)")
        try:
            self.connection.commit_changes(True, None)
            logger.info(
                f"updated connection {self.connection.get_id()} ({self.connection.get_uuid()}) successfully saved to disk"
            )
        except GLib.Error as error:
            self.message = str(error)
            return self._log_result(f"failed updating ({state}) state with changes call ({self.message})")
        return self._log_result(f"connection successfully updated to ({state}) state", done_with_success=True)

    def is_done(self) -> bool:
        if self.state == Activation.ACTIVATION_STATE_DONE:
            return True
        if self.state != Activation.ACTIVATION_STATE_WAITING:
            return False

        active_connection = self.active_connection
        if not active_connection:
            return self._log_result(f"failed activation call ({self.message})")
        if active_connection.get_client() is None:
            return self._log_result("active connection disappeared")
        if active_connection.get_state() > NM.ActiveConnectionState.ACTIVATED:
            return self._log_result(f"connection failed to activate (state {active_connection.get_state()})")
        if active_connection.get_state() == NM.ActiveConnectionState.ACTIVATED:
            return self._log_result("connection successfully activated", done_with_success=True)

        return False

    def start(self, nmc: NM.Client, cancellable: Gio.Cancellable = None,
              activated_callback: Optional[Callable[[Activation], None]] = None) -> None:
        # Call nmc.activate_connection_async() and return a user data
        # with the information about the pending operation.

        assert self.state == Activation.ACTIVATION_STATE_START
        self.state = Activation.ACTIVATION_STATE_STARTING
        logger.info(f"activation {self} start asynchronously")

        def cb_activate_connection(source_object: GObject.Object, res: Gio.AsyncResult) -> None:
            assert self.state == Activation.ACTIVATION_STATE_STARTING
            try:
                active_connection = nmc.activate_connection_finish(res)
            except Exception as error:
                self.message = str(error)
                logger.error(f"activation {self} started asynchronously failed: {self.message}")
            else:
                self.message = "success"
                self.active_connection = active_connection
                logger.info(f"activation {self} started asynchronously success: {active_connection.get_path()}")
            self.state = Activation.ACTIVATION_STATE_WAITING
            if activated_callback is not None:
                activated_callback(self)

        nmc.activate_connection_async(self.connection, None, None, cancellable, cb_activate_connection)

    def stop(self, nmc: NM.Client) -> None:
        assert self.state == Activation.ACTIVATION_STATE_START

        self.state = Activation.ACTIVATION_STATE_STOPPING

        logger.info(f"deactivation {self} start synchronously")

        # TODO: currently disable state uses deprecated deactivate_connection()
        # but according to the nmcli source code, it uses it as well, so for now
        # we are using it as well
        nmc.deactivate_connection(self.active_connection, None)

    def wait(self, done_callback: Optional[Callable[[Activation], None]] = None) -> None:
        assert self.state == Activation.ACTIVATION_STATE_WAITING
        assert self.active_connection
        assert self.wait_id == 0

        def wait_cb(active_connection: NM.ActiveConnection, result: Gio.AsyncResult) -> None:
            if self.is_done():
                self.active_connection.disconnect(self.wait_id)
                self.wait_id = 0
                done_callback(self)

        logger.info(f"waiting for {self} to fully activate")
        self.wait_id = self.active_connection.connect("notify", wait_cb)


class ConnectionsManager(object):
    _num_parallel_in_progress = 50
    _num_parallel_starting = 10

    def __init__(self, nmc: NM.Client, connections: Union[NM.RemoteConnection, NM.ActiveConnection], state: str) -> None:
        self.nmc = nmc
        self.state = state
        self.start_state_activations = [Activation(connection) for connection in connections]
        self.starting_state_activations: list[Activation] = []
        self.waiting_state_activations: list[Activation] = []
        self.done_state_activations: list[Activation] = []

    def activate_connections(self) -> str:
        if self.state == 'disable':
            raise InvalidPreconditionError(f"Invalid state value {self.state}, Manager object should be set in enable state")

        # XXX: Currently only one connection profile may be configured
        # on an interface and what if there will be more than one? Only
        # one can be activated, but  others should have autoconnect
        # property set to `True` value.

        loop = GLib.MainLoop(self.nmc.get_main_context())

        while self.start_state_activations or self.starting_state_activations or self.waiting_state_activations:

            rate_limit_parallel_in_progress = (
                len(self.starting_state_activations) + len(self.waiting_state_activations) >=
                ConnectionsManager._num_parallel_in_progress
            )

            if (
                not rate_limit_parallel_in_progress
                and self.start_state_activations
                and len(self.starting_state_activations) < ConnectionsManager._num_parallel_starting
            ):
                activation = self.start_state_activations.pop(0)
                self.starting_state_activations.append(activation)

                def activated_cb(activation2: Activation) -> None:
                    self.starting_state_activations.remove(activation2)
                    if activation2.is_done():
                        if activation2.done_with_success:
                            activation2.set_autoconnect(self.state)
                        self.done_state_activations.append(activation2)
                    else:
                        self.waiting_state_activations.append(activation2)

                        def done_cb(activation3: Activation) -> None:
                            if activation3.done_with_success:
                                activation3.set_autoconnect(self.state)
                            self.waiting_state_activations.remove(activation3)
                            self.done_state_activations.append(activation3)
                            loop.quit()

                        activation2.wait(done_callback=done_cb)

                    loop.quit()

                activation.start(self.nmc, activated_callback=activated_cb)
                continue

            loop.run()

        results = [activation.done_with_success for activation in self.done_state_activations]

        logger.info(f"{sum(results)} out of {len(self.done_state_activations)} activations are now successfully activated")

        if all(results):
            retval = f"{RESPONSE_OK} Connection(s) activated"
        elif any(results):
            raise InvalidPreconditionError("Not all connections have been activated")
        else:
            raise InvalidPreconditionError("None of the connections have been activated")

        return retval

    def deactivate_connections(self) -> str:
        if self.state == 'enable':
            raise InvalidPreconditionError(
                f"Invalid state value {self.state}, Manager object should be set in disable state"
            )

        while self.start_state_activations:
            activation = self.start_state_activations.pop(0)
            try:
                # deactivate connection...
                activation.stop(self.nmc)
                # ...and make it persistent in the connection profile
                if activation.set_autoconnect(self.state):
                    self.done_state_activations.append(activation)
            except GLib.Error as error:
                raise NetworkManagerError(error.message)

        results = [activation.done_with_success for activation in self.done_state_activations]

        logger.info(f"{sum(results)} out of {len(self.done_state_activations)} activations are now successfully deactivated")

        if all(results):
            retval = f"{RESPONSE_OK} Connection(s) deactivated"
        elif any(results):
            raise InvalidPreconditionError("Not all connections have been deactivated")
        else:
            raise InvalidPreconditionError("None of the connections have been deactivated")

        return retval


# create a Wifi connection and return it
def create_wifi_connection(name: str, ssid: str, key: str, authentication: str, encryption: List[str]) -> NM.SimpleConnection:
    connection = NM.SimpleConnection.new()
    setting_connection = NM.SettingConnection.new()
    setting_connection.props.id = name
    setting_connection.props.uuid = str(uuid.uuid4())
    setting_connection.props.type = "802-11-wireless"
    setting_connection.props.interface_name = name

    setting_wireless = NM.SettingWireless.new()
    setting_wireless.props.mode = "infrastructure"
    setting_wireless.props.ssid = GLib.Bytes.new(ssid.encode("utf-8"))

    setting_wireless_security = NM.SettingWirelessSecurity.new()
    setting_wireless_security.props.psk = key
    if authentication != "auto":
        protocol_properties = authentication.split("-")
        protocol_version = protocol_properties[0]
        protocol_key_mgmt = protocol_properties[1]
        match protocol_version:
            case "wpa":
                protocol_key_mgmt = authentication
                setting_wireless_security.add_proto("wpa")
            case "wpa2":
                protocol_key_mgmt = authentication.replace("2", "")
                setting_wireless_security.add_proto("rsn")
            case _:
                pass
        setting_wireless_security.props.key_mgmt = protocol_key_mgmt
    if encryption != ['auto']:
        for cipher in encryption:
            setting_wireless_security.add_group(cipher)
            setting_wireless_security.add_pairwise(cipher)

    setting_ip4 = NM.SettingIP4Config.new()
    setting_ip4.props.method = "auto"

    setting_ip6 = NM.SettingIP6Config.new()
    setting_ip6.props.method = "auto"

    connection.add_setting(setting_connection)
    connection.add_setting(setting_ip4)
    connection.add_setting(setting_ip6)
    connection.add_setting(setting_wireless)
    connection.add_setting(setting_wireless_security)

    return connection


def get_ssid_as_utf8(access_point: Optional[NM.AccessPoint]) -> str:
    if access_point is None:
        return ""
    assert isinstance(access_point, NM.AccessPoint)
    ssid = access_point.get_ssid()
    if not ssid:
        return ""
    retval = NM.utils_ssid_to_utf8(access_point.get_ssid().get_data())
    assert isinstance(retval, str)  # TODO: remove when NM get typing hint
    return retval


def get_devices(nmc: NM.Client, dev_type: NM.DeviceType) -> list[NM.Device]:
    if nmc is not None:
        devs = nmc.get_devices()

        filtered_devs = [d for d in devs if d.get_device_type() == dev_type]

        if not filtered_devs:
            raise InvalidPreconditionError(f"No {GObject.enum_to_string(NM.DeviceType, dev_type)} available")

        return filtered_devs
    else:
        raise InvalidPreconditionError("NMClient cache not initialized")


def get_access_point_dbus_path(wifi: NM.DeviceWifi, ssid: str, bssid: str = "") -> str:
    dbus_path = ""
    if bssid:
        for access_point in wifi.get_access_points():
            if ssid == get_ssid_as_utf8(access_point) and bssid == access_point.get_bssid():
                dbus_path = access_point.get_path()
                break
    else:
        dbus_paths: dict[str, int] = {}
        for access_point in wifi.get_access_points():
            if ssid == get_ssid_as_utf8(access_point):
                dbus_paths.update({access_point.get_path(): access_point.get_strength()})
        if dbus_paths is None:
            raise InvalidParameterError(
                f"Access point with given ssid: {ssid} does not exist. Run scan command in order to verify."
            )
        dbus_path = sorted(dbus_paths.items(), key=lambda item: item[1], reverse=True)[0][0]

    if not dbus_path and bssid:
        raise InvalidParameterError(
            f"Access point with given ssid: {ssid} and bssid: {bssid} does not exist. Run scan command in order to verify."
        )

    return dbus_path


def device_reason_to_string(state_reason: NM.DeviceStateReason) -> str:
    reason_strings = {
        NM.DeviceStateReason.NONE: "No reason given",
        NM.DeviceStateReason.UNKNOWN: "Unknown error",
        NM.DeviceStateReason.NOW_MANAGED: "Device is now managed",
        NM.DeviceStateReason.NOW_UNMANAGED: "Device is now unmanaged",
        NM.DeviceStateReason.CONFIG_FAILED: "The device could not be readied for configuration",
        NM.DeviceStateReason.IP_CONFIG_UNAVAILABLE: "IP configuration could not be reserved "
        "(no available address, timeout, etc.)",
        NM.DeviceStateReason.IP_CONFIG_EXPIRED: "The IP configuration is no longer valid",
        NM.DeviceStateReason.NO_SECRETS: "Secrets were required, but not provided",
        NM.DeviceStateReason.SUPPLICANT_DISCONNECT: "802.1X supplicant disconnected",
        NM.DeviceStateReason.SUPPLICANT_CONFIG_FAILED: "802.1X supplicant configuration failed",
        NM.DeviceStateReason.SUPPLICANT_FAILED: "802.1X supplicant failed",
        NM.DeviceStateReason.SUPPLICANT_TIMEOUT: "802.1X supplicant took too long to authenticate",
        NM.DeviceStateReason.PPP_START_FAILED: "PPP service failed to start",
        NM.DeviceStateReason.PPP_DISCONNECT: "PPP service disconnected",
        NM.DeviceStateReason.PPP_FAILED: "PPP failed",
        NM.DeviceStateReason.DHCP_START_FAILED: "DHCP client failed to start",
        NM.DeviceStateReason.DHCP_ERROR: "DHCP client error",
        NM.DeviceStateReason.DHCP_FAILED: "DHCP client failed",
        NM.DeviceStateReason.SHARED_START_FAILED: "Shared connection service failed to start",
        NM.DeviceStateReason.SHARED_FAILED: "Shared connection service failed",
        NM.DeviceStateReason.AUTOIP_START_FAILED: "AutoIP service failed to start",
        NM.DeviceStateReason.AUTOIP_ERROR: "AutoIP service error",
        NM.DeviceStateReason.AUTOIP_FAILED: "AutoIP service failed",
        NM.DeviceStateReason.MODEM_BUSY: "The line is busy",
        NM.DeviceStateReason.MODEM_NO_DIAL_TONE: "No dial tone",
        NM.DeviceStateReason.MODEM_NO_CARRIER: "No carrier could be established",
        NM.DeviceStateReason.MODEM_DIAL_TIMEOUT: "The dialing request timed out",
        NM.DeviceStateReason.MODEM_DIAL_FAILED: "The dialing attempt failed",
        NM.DeviceStateReason.MODEM_INIT_FAILED: "Modem initialization failed",
        NM.DeviceStateReason.GSM_APN_FAILED: "Failed to select the specified APN",
        NM.DeviceStateReason.GSM_REGISTRATION_NOT_SEARCHING: "Not searching for networks",
        NM.DeviceStateReason.GSM_REGISTRATION_DENIED: "Network registration denied",
        NM.DeviceStateReason.GSM_REGISTRATION_TIMEOUT: "Network registration timed out",
        NM.DeviceStateReason.GSM_REGISTRATION_FAILED: "Failed to register with the requested network",
        NM.DeviceStateReason.GSM_PIN_CHECK_FAILED: "PIN check failed",
        NM.DeviceStateReason.FIRMWARE_MISSING: "Necessary firmware for the device may be missing",
        NM.DeviceStateReason.REMOVED: "The device was removed",
        NM.DeviceStateReason.SLEEPING: "NetworkManager went to sleep",
        NM.DeviceStateReason.CONNECTION_REMOVED: "The device's active connection disappeared",
        NM.DeviceStateReason.USER_REQUESTED: "Device disconnected by user or client",
        NM.DeviceStateReason.CARRIER: "Carrier/link changed",
        NM.DeviceStateReason.CONNECTION_ASSUMED: "The device's existing connection was assumed",
        NM.DeviceStateReason.SUPPLICANT_AVAILABLE: "The supplicant is now available",
        NM.DeviceStateReason.MODEM_NOT_FOUND: "The modem could not be found",
        NM.DeviceStateReason.BT_FAILED: "The Bluetooth connection failed or timed out",
        NM.DeviceStateReason.GSM_SIM_NOT_INSERTED: "GSM Modem's SIM card not inserted",
        NM.DeviceStateReason.GSM_SIM_PIN_REQUIRED: "GSM Modem's SIM PIN required",
        NM.DeviceStateReason.GSM_SIM_PUK_REQUIRED: "GSM Modem's SIM PUK required",
        NM.DeviceStateReason.GSM_SIM_WRONG: "GSM Modem's SIM wrong",
        NM.DeviceStateReason.INFINIBAND_MODE: "InfiniBand device does not support connected mode",
        NM.DeviceStateReason.DEPENDENCY_FAILED: "A dependency of the connection failed",
        NM.DeviceStateReason.BR2684_FAILED: "A problem with the RFC 2684 Ethernet over ADSL bridge",
        NM.DeviceStateReason.MODEM_MANAGER_UNAVAILABLE: "ModemManager is unavailable",
        NM.DeviceStateReason.SSID_NOT_FOUND: "The Wi-Fi network could not be found",
        NM.DeviceStateReason.SECONDARY_CONNECTION_FAILED: "A secondary connection of the base connection failed",
        NM.DeviceStateReason.DCB_FCOE_FAILED: "DCB or FCoE setup failed",
        NM.DeviceStateReason.TEAMD_CONTROL_FAILED: "teamd control failed",
        NM.DeviceStateReason.MODEM_FAILED: "Modem failed or no longer available",
        NM.DeviceStateReason.MODEM_AVAILABLE: "Modem now ready and available",
        NM.DeviceStateReason.SIM_PIN_INCORRECT: "SIM PIN was incorrect",
        NM.DeviceStateReason.NEW_ACTIVATION: "New connection activation was enqueued",
        NM.DeviceStateReason.PARENT_CHANGED: "The device's parent changed",
        NM.DeviceStateReason.PARENT_MANAGED_CHANGED: "The device parent's management changed",
        NM.DeviceStateReason.OVSDB_FAILED: "Open vSwitch database connection failed",
        NM.DeviceStateReason.IP_ADDRESS_DUPLICATE: "A duplicate IP address was detected",
        NM.DeviceStateReason.IP_METHOD_UNSUPPORTED: "The selected IP method is not supported",
        NM.DeviceStateReason.SRIOV_CONFIGURATION_FAILED: "Failed to configure SR-IOV parameters",
        NM.DeviceStateReason.PEER_NOT_FOUND: "The Wi-Fi P2P peer could not be found",
    }

    return reason_strings.get(state_reason, "Unknown")
#
#
# TODO: for now it is commented
# def connection_cb_info_obj_list_destroy(info: ConnectionCbInfo, obj: NM.Object) -> None:
#     obj.disconnect_by_func(down_active_connection_state_cb)


def connection_cb_info_obj_list_idx(info: ConnectionCbInfo, obj: NM.Object) -> int:
    try:
        index = info.objects.index(obj)
    except ValueError:
        index = -1
    finally:
        return index


def connection_cb_info_obj_list_has(info: ConnectionCbInfo, obj: NM.Object) -> Optional[NM.Object]:
    index = connection_cb_info_obj_list_idx(info, obj)
    if index >= 0:
        return info.objects[index]
    return None


def connection_cb_info_obj_list_steal(info: ConnectionCbInfo, obj: NM.Object) -> Optional[NM.Object]:
    index = connection_cb_info_obj_list_idx(info, obj)
    if index >= 0:
        # XXX: using here `del object[index]` as it is much faster than `pop` according to link below
        # https://stackoverflow.com/questions/627435/how-to-remove-an-element-from-a-list-by-index
        del info.objects[index]
        return obj
    return None


def connection_removed_cb(client: NM.Client, connection: NM.Connection, info: ConnectionCbInfo) -> None:
    if not connection_cb_info_obj_list_has(info, connection):
        return
    logger.info(f"Connection {connection.get_id()} ({connection.get_uuid()}) successfully deleted.")
    connection_cb_info_finish(info, connection)


def connection_cb_info_finish(connection_cb_info: ConnectionCbInfo, obj: NM.Object = GObject.GPointer) -> None:
    if obj is not None:
        obj = connection_cb_info_obj_list_steal(connection_cb_info, obj)
        # TODO: for now it is commented
        # if (obj)
        #     connection_cb_info_obj_list_destroy(info, obj);
    else:
        while len(connection_cb_info.objects) > 0:
            obj = connection_cb_info.objects.pop()
            # connection_cb_info_obj_list_destroy(connection_cb_info, obj)  # TODO: for now it is commented

    if len(connection_cb_info.objects) > 0:
        return

    if (connection_cb_info.timeout_id):
        GLib.source_remove(connection_cb_info.timeout_id)
        connection_cb_info.timeout_id = 0
    if (connection_cb_info.cancellable):
        connection_cb_info.cancellable.cancel()
        connection_cb_info.cancellable = None

    connection_cb_info.nmc.disconnect_by_func(connection_removed_cb)

    connection_cb_info.loop.quit()
    # TODO: this has to be somehow fixed
    # _client.respond("net.wifi.client.set_config.resp", RESPONSE_OK, connection_cb_info.from_part, connection_cb_info.message_id)


def connection_op_timeout_cb(info: ConnectionCbInfo) -> bool:
    connection_cb_info_finish(info)
    return GLib.SOURCE_REMOVE  # type: ignore  # mypy does not recognize types


def error_is_cancelled(error: GLib.GError) -> bool:
    # Whether error is due to cancellation.
    if isinstance(error, GLib.GError):
        if error.domain == "g-io-error-quark" and error.code == Gio.IOErrorEnum.CANCELLED:
            return True
    return False


def delete_connection(connection: NM. RemoteConnection, connection_cb_info: ConnectionCbInfo) -> None:
    def delete_cb(connection: NM.RemoteConnection, result: Gio.AsyncResult, connection_cb_info: ConnectionCbInfo) -> None:
        try:
            connection.delete_finish(result)
            if connection_cb_info.nowait_flag:
                connection_cb_info_finish(connection_cb_info, connection)
        except GLib.Error as error:
            if (error_is_cancelled(error)):
                return
            logger.info(f"Error: Connection deletion failed: {str(error)}")
            connection_cb_info_finish(connection_cb_info, connection)

    timeout = 10
    connection_cb_info.timeout_id = GLib.timeout_add(timeout, connection_op_timeout_cb, connection_cb_info)
    connection_cb_info.nowait_flag = (timeout == 0)
    connection_cb_info.nmc.connect(NM.CLIENT_CONNECTION_REMOVED, connection_removed_cb, connection_cb_info)
    connection.delete_async(connection_cb_info.cancellable, delete_cb, connection_cb_info)


def get_wifi_config(nmc: NM.Client, ifname: str, config: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    logger.info('get_wifi_config')

    wifi = nmc.get_device_by_iface(ifname)
    if wifi is None:
        return config

    active_connection = wifi.get_active_connection()
    available_connections = wifi.get_available_connections()
    # XXX: currently there is only one connection profile for wifi1 interface
    for connection in available_connections:
        connection_settings = {}
        setting_wireless = connection.get_setting_wireless()
        connection_settings['ssid'] = NM.utils_ssid_to_utf8(setting_wireless.get_ssid().get_data())
        connection_settings['bssid'] = setting_wireless.get_bssid()
        setting_wireless_security = connection.get_setting_wireless_security()
        # TODO: get_secrets() is deprecated but i don't have for now
        # an idea on how to do this with async call
        connection.update_secrets(NM.SETTING_WIRELESS_SECURITY_SETTING_NAME,
                                  connection.get_secrets(NM.SETTING_WIRELESS_SECURITY_SETTING_NAME, None))
        connection_settings['key'] = setting_wireless_security.get_psk()
        match setting_wireless_security.get_key_mgmt():
            case "wpa-psk":
                match setting_wireless_security.get_proto(0):
                    case "wpa":
                        connection_settings['authentication'] = 'wpa-psk'
                    case "rsn":
                        connection_settings['authentication'] = 'wpa2-psk'
                    case _:
                        pass
            case "sae":
                connection_settings['authentication'] = 'wpa3-sae'
            case _:
                pass

        group_encryption = sorted(setting_wireless_security.props.group)
        pairwise_encryption = sorted(setting_wireless_security.props.pairwise)
        if group_encryption == pairwise_encryption:
            if group_encryption:
                # XXX: the usage of 'setting_wireless_security.props.group' is here on purpouse
                # so that the list is not sorted
                connection_settings['encryption'] = setting_wireless_security.props.group
            else:
                connection_settings['encryption'] = ['auto']
        else:
            # FIXME: I do not know what should we do if somebody
            # will tamper configuration file ane group values
            # will be different than pairwise
            connection_settings['encryption'] = 'N/A'  # something is wrong with configuration
        # XXX: this is a workaround to keep order of settings in dict
        connection_settings['dhcp'] = False
        connection_settings['current_bssid'] = None
        connection_settings['current_ip'] = None
        connection_settings['current_subnet'] = None
        connection_settings['current_gateway'] = None
        connection_settings['current_dns'] = None
        connection_settings['state'] = "enabled" if connection.get_setting_connection().get_autoconnect() else "disabled"
        setting_ip4_config = connection.get_setting_ip4_config()
        if setting_ip4_config.get_method() == 'auto':
            connection_settings['dhcp'] = True
            if (active_connection and (connection.get_id() == active_connection.get_id()) and
                    (ip4_config := active_connection.get_ip4_config())):
                # Since connection is established, profile id is exactly the same as for
                # the active connection and ip4 configuration is set for interface, we can
                # retrive all the values.
                # connection_settings['current_bssid'] = active_connection.get_connection().get_setting_wireless().get_bssid()
                connection_settings['current_bssid'] = wifi.get_active_access_point().get_bssid()
                dhcp4_config = active_connection.get_dhcp4_config()
                ip_address = dhcp4_config.get_one_option('ip_address')
                ip_network = IPv4Network(ip_address + '/' + dhcp4_config.get_one_option('subnet_mask'), False)
                connection_settings['current_ip'] = ip_address
                connection_settings['current_subnet'] = str(ip_network.prefixlen)
                connection_settings['current_gateway'] = ip4_config.get_gateway()
                connection_settings['current_dns'] = ip4_config.get_nameservers()
        else:
            connection_settings['dhcp'] = False

        config['network'][ifname] = connection_settings

    return config


def wifi_change_state(nmc: NM.Client, state: str, ifname: str) -> str:
    wifi = nmc.get_device_by_iface(ifname)
    if wifi is None:
        raise InvalidParameterError(f"Device {ifname} is not available")

    match state:
        case "enable":
            logger.info('net_wifi_client_enable')
            available_connections = wifi.get_available_connections()
            # XXX: Currently only one connection will be available on the returned list
            # so we do not care about proper verification
            if not available_connections:
                raise InvalidPreconditionError(f"No matching connection for {ifname} interface name")
            retval = ConnectionsManager(nmc, available_connections, state).activate_connections()
        case "disable":
            logger.info('net_wifi_client_disable')
            # get_active_connection returns active_connection or None
            active_connections = [wifi.get_active_connection()]
            # XXX: Currently only one connection will be available on the created list
            # so we do not care about proper verification
            if None in active_connections:
                raise InvalidPreconditionError(f"No active connection on {ifname} interface name")
            retval = ConnectionsManager(nmc, active_connections, state).deactivate_connections()
        case _:
            raise InvalidParameterError(f"Invalid state {state} parameter provided")

    return retval
