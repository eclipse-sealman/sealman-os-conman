#!/usr/bin/env python3
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
Daemon responsible for basic network connections configuration.
"""

# Standard imports
import argparse
import collections.abc as abc
import ipaddress
import json
import re
import sys
from collections import defaultdict
from typing import Any, Callable, Dict, List, Mapping, MutableMapping, Optional, Set, Tuple, Union

# Third party imports
# This ugly non-pep8 compliant importing sequence is required by gi module
import gi  # type: ignore
from pyroute2.ethtool import Ethtool  # type: ignore

# Local imports
import mpa.communication.topics as topics
import mpa.network.management
from mpa.common.common import RESPONSE_OK, empty_message_wrapper
from mpa.common.logger import Logger
from mpa.communication import client as com_client
from mpa.communication.client import background, guarded, sync
from mpa.communication.common import (
    InvalidPayloadError,
    InvalidParameterError,
    InvalidPreconditionError,
    expect_empty_message,
    get_lan_interfaces,
    get_system_network_interfaces,
)
from mpa.communication.inter_process_lock import InterProcessLock
from mpa.communication.message_parser import (
    get_bool,
    get_dict,
    get_enum_str,
    get_int,
    get_ip4,
    get_ip46_list,
    get_list,
    get_optional_bool,
    get_optional_dict,
    get_str,
)
from mpa.communication.process import run_command, run_command_unchecked
from mpa.communication.status_codes import SUCCESS
from mpa.config.common import CONFIG_DIR_ROOT
from mpa.device.common import RESOLVED_CONF, LINK_TO_RESOLVED_CONF, CaseSensitiveConfigParser
from mpa.network.cellular_check import CellularCheck
from mpa.network.dhcp_server import Dhcp4Server
from mpa.network.management import (
    get_configured_addresses_and_masks,
    get_configured_dns,
    is_dhcp,
)
from mpa.network.wifi_client import wifi_client_scan, wifi_client_set_config
from mpa.network.wifi_common import get_wifi_config, get_wifi_interfaces, wifi_change_state

gi.require_version(
    "NM", "1.0"
)  # Use before import to ensure that the right version gets loaded
# all PyGObject API Reference can be read in below link
# https://lazka.github.io/pgi-docs/
from gi.repository import NM  # type: ignore # noqa: E402

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


class GetConfigData:
    def __init__(self) -> None:
        self.config: MutableMapping[str, Any] = dict()
        self.active_requests: List[Tuple[bytes, bytes]] = list()

    def respond(self, response: Any = None) -> None:
        if response is None:
            response = self.config
        for request in self.active_requests:
            _client.respond("net.get_config.resp", response, request[0], request[1])
        self.active_requests = list()


get_config_data = GetConfigData()


CELLULAR_CONFIG_FILE_PATTERN = str(CONFIG_DIR_ROOT / "cellular{interface}.conf")
ALLOWED_INTERFACES = get_lan_interfaces() | get_wifi_interfaces() | {"cellular1", "cellular2"}
LAN_INTERFACES = get_lan_interfaces()
NET_WIFI_CLIENT_SCAN_LOCK = InterProcessLock(CONFIG_DIR_ROOT / "mgmtd/net.wifi.client.scan.lock", stale_lock_seconds=600)
NET_WIFI_CLIENT_STATE_LOCK = InterProcessLock(CONFIG_DIR_ROOT / "mgmtd/net.wifi.client.state.lock", stale_lock_seconds=600)
NET_WIFI_CLIENT_SET_CONFIG = "net_wifi_client_set_config"

_parser = argparse.ArgumentParser(prog='Network config daemon')
com_client.add_command_line_params(_parser)
_args = _parser.parse_args()
_client = com_client.Client(args=_args)
# We do not care that this call is blocking D-Bus calls as we are using lock transactions
# https://lazka.github.io/pgi-docs/NM-1.0/classes/Client.html#NM.Client.new
# WARNING: this variable must be just one shared between all network submodules
# https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/issues/692#note_984378
_nmc = NM.Client.new(None)


def write_json(filename: str, payload: Mapping[str, Any]) -> None:
    with open(filename, "w") as file:
        json.dump(payload, file, sort_keys=False, indent=4)


def net_cellular_set_config(message: Optional[bytes] = None,
                            *,
                            config: Optional[Mapping[str, Any]] = None) -> Optional[str]:
    # Programming errors shall not happen, so raised as RuntimeError:
    if message is None and config is None:
        raise RuntimeError("Either message or config needs to be provided to net_cellular_set_config, but none were given")
    if message is not None and config is not None:
        raise RuntimeError("Either message or config needs to be provided to net_cellular_set_config, but both were given")
    if config is None:
        assert message is not None
        config = json.loads(message)
    if 'access_number' not in config:
        raise InvalidPayloadError("Cannot store CELLULAR config without 'access_number'")
    if 'apn' not in config:
        raise InvalidPayloadError("Cannot store CELLULAR config without 'apn'")

    interface_number = get_int(config, "interface")

    old_config = get_cellular_config(interface_number)
    logger.debug(f"Old config: {old_config}")
    if config == old_config:
        return f"{RESPONSE_OK} No change in config, nothing done"
    write_json(CELLULAR_CONFIG_FILE_PATTERN.format(interface=interface_number), config)
    state_str = ""
    if isinstance(old_config, abc.Mapping) and old_config['state'] == "on":
        mpa.network.management.turn_off_cellular(interface_number)
        state_str = "and cellular connection was turned off"
        if 'state' not in config or config['state'] == "on":
            mpa.network.management.turn_on_cellular(config, interface_number)
            state_str = "and cellular connection was restarted"
    elif 'state' in config and config['state'] == "on":
        mpa.network.management.turn_on_cellular(config, interface_number)
        state_str = "and cellular connection was started"
    return f"{RESPONSE_OK} New config applied {state_str}"


def get_cellular_config(interface: int) -> Union[None, str, Mapping[str, Any]]:
    def read_json(filename: str) -> Optional[MutableMapping[str, Any]]:
        try:
            with open(filename, "r") as file:
                config = file.read()
                retval = json.loads(config)
                if isinstance(retval, abc.MutableMapping):
                    return retval
                logger.error(f"File '{filename}' not parsed to mapping - invalid modem config.")
                return None
        except IOError:
            logger.warning("File not accessible - modem was not configured.")
            return None

    primart_port = mpa.network.management.get_cellular_primary_port(interface)

    if not mpa.network.management.device_exists(primart_port):
        return "Missing device --- probale misconfiguration or hardware failure"
    config = read_json(CELLULAR_CONFIG_FILE_PATTERN.format(interface=interface))
    if not config:
        return None
    if mpa.network.management.is_device_connected(primart_port):
        config['state'] = 'on'
    else:
        config['state'] = 'off'
    return config


def get_eth_config(config: MutableMapping[str, Any]) -> MutableMapping[str, Any]:
    for eth in get_lan_interfaces():
        if not mpa.network.management.device_exists(eth):
            config['network'][eth] = "Missing device --- probale misconfiguration or hardware failure"
        else:
            if mpa.network.management.is_dhcp(eth):
                config['network'][eth] = {"dhcp": True,
                                          "ignore_default_route":
                                          mpa.network.management.get_ignore_default_route(eth)}
            else:
                config['network'][eth] = {"dhcp": False,
                                          "ip": mpa.network.management.get_configured_address(eth),
                                          "subnet": mpa.network.management.get_configured_subnetmask(eth),
                                          "gateway": mpa.network.management.get_configured_gateway(eth),
                                          "mtu": mpa.network.management.get_configured_mtu(eth),
                                          "dns": mpa.network.management.get_configured_dns(eth)}
            config['network'][eth]["current_ip"] = mpa.network.management.get_actual_address(eth)
            config['network'][eth]["current_subnet"] = mpa.network.management.get_actual_subnetmask(eth)
            config['network'][eth]["current_gateway"] = mpa.network.management.get_actual_gateway(eth)
            config['network'][eth]["current_mtu"] = mpa.network.management.get_actual_mtu(eth)
            config['network'][eth]["current_dns"] = mpa.network.management.get_actual_dns(eth)
            config['network'][eth]["promiscous_mode"] = mpa.network.management.get_promiscous_mode(eth)
    return config


def net_set_config(message: bytes) -> None:
    """
    Handles "net.set_config.req" and sets network config.

    Example message looks like:
    {
        ...,
        "network": {
            "interface1": {
                interface config
            },
            "interface2": {
                interface_config
            },
            ...
        },
        ...
    }

    Subobjects other than "network" are ignored --- this allows sending same
    payload in messages for different subsystems.

    Allowed names of interfaces ("interface1" and "interface2" in example above)
    depend on the hardware configuration, currently they are "CELLULAR" for CELLULAR modem
    connection {ETHs} for ethernet connections and {WIFIs} for wifi connections. Invalid
    interface names lead to errors.

    Example interface_config for ethernet connections:
    {
        "dhcp": false,
        "ip": [ "192.168.0.1", "1.2.3.4", ... ],
        "subnet": [ "16", "8" ],
        "gateway": null,
        "dns": null,
        "mtu": null,
        "current_...": ignored,
        "promiscous_mode": false
    }
    Note that currently for set_config lists of IPs and subnets can have only one entry.
    "current_..." entries are ignored but three dots part after "current_" must
    match one of above non-current entries. Invalid entries lead to errors.

    For interface_config of "CELLULAR" look into net.cellular.set_config
    (net_cellular_set_config) documentation.
    For interface_config of "WIFI" look into net.wifi.client.set_config
    (net_wifi_client_set_config) documentation.
    """
    # TODO this shall be probably transaction with ability to roll back partiall
    payload = json.loads(message)
    network_config = get_dict(payload, "network")
    if "dhcp_server" in payload:
        dhcp_server_config = payload["dhcp_server"]
        shall_update_dhcp_config = True
    else:
        shall_update_dhcp_config = False
        dhcp_server_config = _dhcp_server_get_config()

    dns_config = get_optional_dict(payload, "dns")
    if dns_config is not None:
        set_dns_config(message)

    interface: str
    config: MutableMapping[str, Any]
    for interface in network_config:
        if interface not in ALLOWED_INTERFACES and network_config[interface] is not None:
            raise InvalidPayloadError(f"Unknown interface {interface}, allowed values are {ALLOWED_INTERFACES}")

    for interface, config in network_config.items():
        try:
            if interface.startswith("cellular"):
                if "interface" not in config:
                    interface_number = int(re.findall(r'\d+', interface)[0])
                    config["interface"] = interface_number  # add "interface" to config if not present
                net_cellular_set_config(config=config)
            elif interface.startswith("wifi"):
                net_wifi_client_set_config(config={interface: config})
            else:
                if config is None:
                    continue
                for key in config:
                    if key.startswith("current_"):
                        normalized_key = key[len("current_"):]
                    else:
                        normalized_key = key
                    if normalized_key not in ["ip", "subnet", "gateway", "dns", "dhcp", "mtu",
                                              "ignore_default_route", "promiscous_mode"]:
                        raise InvalidPayloadError(f"Invalid key {key} in {interface} config.")
                if (mode := get_optional_bool(config, "promiscous_mode")) is not None:
                    mpa.network.management.set_promiscous_mode(interface, mode)
                if config['dhcp']:
                    if interface in dhcp_server_config and dhcp_server_config[interface]["enabled"]:
                        raise InvalidPayloadError("DHCP Server can only be bound to interfaces with static IP.")

                    mpa.network.management.set_dhcp(interface)
                    if 'ignore_default_route' in config:
                        mpa.network.management.set_ignore_default_route(interface, config['ignore_default_route'])
                else:
                    mpa.network.management.assign_ip_configuration(interface, config)
        except RuntimeError as runerr:
            runerr.args = (f"For interface {interface}: {runerr.args[0]}",) + runerr.args[1:]
            raise

    if shall_update_dhcp_config:
        _dhcp_server_set_config(dhcp_server_config)


def net_set_ignore_default_route(message: bytes) -> None:
    json_settings: Mapping[str, Any] = json.loads(message)
    for key, value in json_settings['network'].items():
        mpa.network.management.set_ignore_default_route(key, value['ignore_default_route'])


def net_cellular_change_state(message: bytes) -> str:
    """
    Handles "net.cellular.change_state.req" which allows to turn CELLULAR connection on
    and off without changing its configuration.

    Example payload:
    {
        ...,
        "state": requested_state,
        ...
    }
    where requested state shall be "on" or "off".
    Subobjects other than "state" are ignored.
    """
    json_settings: Mapping[str, Any] = json.loads(message)
    if not isinstance(json_settings, abc.Mapping):
        raise InvalidPayloadError("Invalid message format (not a json object)")
    if "state" not in json_settings:
        raise InvalidPayloadError("Missing new state entry")
    value = get_str(json_settings, "state")
    interface = get_int(json_settings, "interface")
    if value == 'off':
        mpa.network.management.turn_off_cellular(interface)
        return f"{RESPONSE_OK} Turned cellular{interface} off"
    if value == 'on':
        config = get_cellular_config(interface)
        if not config:
            raise InvalidPreconditionError("cellular{interface} modem is not configured")
        if isinstance(config, str):
            # get_cellular_config failed in strange way (currently only missing modem can lead to it)
            raise RuntimeError(f"Unexpected error while checking cellular{interface} config: {config}")
        mpa.network.management.turn_on_cellular(config, interface)
        return f"{RESPONSE_OK} Turned cellular{interface} on"
    # value shall be prepared by UI, so this shall not happen, hence RuntimeError
    raise RuntimeError("Unrecognized state: {value}")


def net_get_config() -> MutableMapping[str, Any]:
    """
    Handles "net.get_config.req" and returns network config.

    Request payload shall be empty.

    Response format is identical as one described for net.set_config.req.
    The elements starting with "current_" provide values in use at the moment,
    which may differ from values configured (for example if device is configured
    for "dhcp" and is up it has concrete ip address currently, but has no
    concrete ip address configured in general).
    """
    logger.info('net_get_config')
    config: MutableMapping[str, Any] = {
        "network": {},
        }

    networks = get_system_network_interfaces()
    for network in networks:
        if network.startswith("cellular"):
            interface_number = re.findall(r'\d+', network)[0]
            primary_port = mpa.network.management.get_cellular_primary_port(interface_number)
            if mpa.network.management.device_exists(primary_port):
                config['network'][f'cellular{interface_number}'] = get_cellular_config(interface_number)
        if network.startswith("wifi"):
            config = get_wifi_config(_nmc, network, config)

    config = get_eth_config(config)
    config["dns"] = get_current_dns()
    return config


def get_config_step_store(config_part: str, message: Union[str, bytes]) -> Optional[bool]:
    if isinstance(message, str):
        get_config_data.config[config_part] = message
        return False
    get_config_data.config.update(json.loads(message))
    return None


def get_config_step_trivial(config_part: str,
                            next_message_topic: str,
                            query: Dict[str, Any],
                            next_handler: com_client.QueryHandlerCallable) -> com_client.QueryHandlerCallable:
    def trivial_step_handler(message: Union[str, bytes]) -> Optional[bool]:
        _client.query(next_message_topic, query, next_handler)
        return get_config_step_store(config_part, message)
    return trivial_step_handler


def get_config_step_final(config_part: str) -> com_client.QueryHandlerCallable:
    def final_handler(message: Union[str, bytes]) -> Optional[bool]:
        try:
            return get_config_step_store(config_part, message)
        finally:
            get_config_data.respond()
    return final_handler


def get_config_step_init(message: bytes, from_part: bytes, message_id: bytes) -> com_client.Async:
    if message:
        logger.warning(f"Non empty message received by get_config_step_init(): {message!r}")
    get_config_data.active_requests.append((from_part, message_id))
    if len(get_config_data.active_requests) == 1:
        try:
            get_config_data.config = {**net_get_config(), **dhcp_server_get_config(b"")}
            _client.query(topics.net.routing.get_config, "", get_config_step_trivial("routes",
                                                                                     topics.net.vlan.get_config,
                                                                                     {"interface": "all"},
                                                                                     get_config_step_final("vlans")))
        except Exception:
            get_config_data.active_requests.pop()
            raise
    return com_client.Async()


def net_status(message: bytes) -> MutableMapping[str, Any]:
    """
    Handles "net.status" and returns network status.

    Request payload shall be empty.

    Response is composed of output from ifconfig and route tools.
    """
    logger.info('net_get_config')
    if message:
        logger.warning(f"Non empty message received in net_get_config: {message.decode('UTF-8')}")

    status: MutableMapping[str, Any] = {
        "interfaces": "",
        "routes": "",
        "link_speed": "",
    }
    ifconfig_output = run_command("pkexec /sbin/ifconfig").stdout.decode()
    route_output = run_command("pkexec /sbin/route -n").stdout.decode()
    link_speed = {}
    for interface in get_lan_interfaces():
        with Ethtool() as et:
            speed = et.get_link_mode(interface).speed
            link_speed[interface] = f"{speed} Mb/s" if speed else "not connected"

    link_speed_string = "\n".join(
        f"{interface}\t{speed}"
        for interface, speed in link_speed.items()
    )

    status["interfaces"] = ifconfig_output
    status["routes"] = route_output
    status["link_speed"] = link_speed_string
    return status


@empty_message_wrapper
def get_current_dns(message: bytes) -> Dict[str, Any]:
    expect_empty_message(message, "get_current_dns()")
    return {
        "dns_servers": sorted(get_dns()),
        "override_nic_config": LINK_TO_RESOLVED_CONF.is_symlink(),
    }


def add_dns(message: bytes) -> None:
    dns = str(get_ip4(json.loads(message), "dns_server"))
    current = get_dns()
    current.add(dns)
    set_dns(current)


def set_dns_config(message: bytes) -> None:
    data = get_dict(json.loads(message), "dns")
    if "dns_servers" in data:
        new_dns_servers = set(str(ip) for ip in get_ip46_list(data, "dns_servers"))
        set_dns(new_dns_servers)
    set_dns_override(get_bool(data, "override_nic_config"))


def delete_dns(message: bytes) -> None:
    to_remove = str(get_ip4(json.loads(message), "dns_server"))
    current = get_dns()
    current.discard(to_remove)
    set_dns(current)


def get_dns() -> Set[str]:
    config = CaseSensitiveConfigParser()
    config.read(RESOLVED_CONF)
    raw = config.get("Resolve", "DNS", fallback="")
    return set(x for x in raw.split() if x)


def set_dns(dns: Set[str]) -> None:
    config = CaseSensitiveConfigParser()
    config.read(RESOLVED_CONF)

    if len(dns) > 0:
        config["Resolve"]["DNS"] = " ".join(sorted(dns))
    else:
        config.remove_option("Resolve", "DNS")

    with open(RESOLVED_CONF, "w") as f:
        config.write(f)
    restart_systemd_resolved()


def set_dns_override(override: bool) -> None:
    LINK_TO_RESOLVED_CONF.unlink(missing_ok=True)
    if override:
        LINK_TO_RESOLVED_CONF.symlink_to(RESOLVED_CONF)
        run_command("systemctl enable --now systemd-resolved")
        restart_systemd_resolved()
    else:
        # Before we can disable systemd-resolved we need to clean up it's configuration
        # so we tear down the symlink, and restart service, so resolved sees that the
        # changes need to be rolled back. This looks weird, but it's systemd.
        restart_systemd_resolved()
        run_command("systemctl disable --now systemd-resolved")


def restart_systemd_resolved() -> None:
    run_command("systemctl restart systemd-resolved")


def net_wifi_client_scan(message: bytes) -> Dict[Any, defaultdict[str, List[Dict[str, Any]]]]:
    """
    Handles "net.wifi.client.scan" and returns available wifi networks.

    Example payload:

    {
        ...,
        "rescan": requested_rescan,
        ...
    }
    where requested rescan shall be "auto", "no" or "yes".
    Subobjects other than "rescan" are ignored.

    By default our cli command uses "auto" value which ensures that the access point list
    is no older than 30 seconds and triggers a network scan if necessary. The "rescan"
    parameter with "yes" or "no" can be used to either force or disable the scan regardless
    of how fresh the access point list is.

    Response is composed of networks output from PyGObject bindings connected to libnm.so.
    """
    with NET_WIFI_CLIENT_SCAN_LOCK.transaction("Global lock for scanning available wifi networks"):
        logger.info("net.wifi.client.scan")
        rescan = get_enum_str(json.loads(message), 'rescan', ['auto', 'yes', 'no'])
        return wifi_client_scan(_nmc, rescan)


def net_wifi_client_set_config(message: Optional[bytes] = None,
                               *, config: Optional[Dict[str, Any]] = None) -> str:
    """
    Handles "net.wifi.client.set_config.req" and sets wifi network config.

    Example payload:
    {
        "wifi1": {
            "ssid": requested_ssid,
            "key": requested_key,
            "authentication": requested_authentication,
            "encryption": requested_encryption
        }
    }
    where requested authentication can be "wpa-psk", "wpa2-psk" or "wpa3-sae"
    and requested encryption depending on which authentication mode has been
    choosen.
    Values like "auto", "ccmp", "tkip" or even concatenated "ccmp tkip" may be
    used only for "wpa-psk" and "wpa2-psk" authentication modes. Concatenation
    order does not matter. For "wpa3-sae" only "auto" or "ccmp" are possible.

    Allowed names of interfaces ("wifi1" in example above) depend on the hardware
    configuration, currently they are "WIFI" for WIFI card connection. Invalid
    interface names lead to errors.

    Example interface_config for wifi connections:
    {
            "ssid": "requested_ssid",
            "bssid": ignored,
            "key": "requested_key",
            "authentication": "wpa2-psk",
            "encryption": [
                "ccmp",
                "tkip"
            ],
            "dhcp": ignored,
            "current_bssid": ignored,
            "current_ip": ignored,
            "current_subnet": ignored,
            "current_gateway": ignored,
            "current_dns": ignored
            "state": "enabled"
    }

    Currently dhcp for client connection is being handled automaticaly.
    """
    # XXX: The NET_WIFI_CLIENT_STATE_LOCK is being used here,
    # we take into account the possibility, that there is an
    # already created profile created on the wifi1 interface
    # and thus we want to prevent the possibility of changing
    # its state (enable/disable)
    with NET_WIFI_CLIENT_STATE_LOCK.transaction("Global lock for setting new wifi connection profile"):
        logger.info(NET_WIFI_CLIENT_SET_CONFIG)
        # Programming errors shall not happen, so raised as RuntimeError:
        if message is None and config is None:
            raise RuntimeError(
                f"Either message or config needs to be provided to {NET_WIFI_CLIENT_SET_CONFIG}, but none were given"
            )
        elif message is not None and config is not None:
            raise RuntimeError(
                f"Either message or config needs to be provided to {NET_WIFI_CLIENT_SET_CONFIG}, but both were given"
            )
        elif config is None and message is not None:
            config = json.loads(message)
        else:
            pass

        return wifi_client_set_config(_nmc, config)  # type: ignore  # mypy wrongly recognize config type


def net_wifi_client_change_state(message: bytes) -> str:
    """
    Handles "net.wifi.client.change_state.req" which allows to enable WIFI connection
    and disable without changing its configuration (only autoconnect property is being
    changed in connection setting).

    Example payload:

    {
        ...,
        "state": requested_state,
        ...
    }
    where requested state shall be "enable" or "disable".
    Subobjects other than "state" are ignored.
    """
    with NET_WIFI_CLIENT_STATE_LOCK.transaction("Global lock for changing state of existing wifi connection profile"):
        logger.info('net_wifi_client_change_state')
        state = json.loads(message)
        ifname = 'wifi1'
        return wifi_change_state(_nmc, state, ifname)


def cellular_checklist(message: bytes) -> str:
    cellular_check = CellularCheck()
    return f'{RESPONSE_OK} {cellular_check.cellular_check()}'


def promiscous_mode_set_config(message: bytes) -> None:
    decoded_message = json.loads(message)
    interface = get_str(decoded_message, "interface")
    mode = get_bool(decoded_message, "mode")
    if interface not in ALLOWED_INTERFACES:
        raise InvalidPayloadError(f"Unknown interface {interface}, allowed values are {ALLOWED_INTERFACES}")

    mpa.network.management.set_promiscous_mode(interface, mode)


def change_ids_state(message: bytes) -> None:
    decoded_message = json.loads(message)
    interface = get_str(decoded_message, "interface")
    if interface not in ALLOWED_INTERFACES:
        raise InvalidPayloadError(f"Unknown interface {interface}, allowed values are {ALLOWED_INTERFACES}")
    mode = get_bool(decoded_message, "mode")
    is_enabled_result = run_command_unchecked(f"systemctl is-enabled suricata@{interface}.service")
    is_enabled = False
    if is_enabled_result.returncode == SUCCESS:
        if is_enabled_result.stdout.decode('ascii').strip() == "enabled":
            is_enabled = True
    if mode and is_enabled:
        raise InvalidPreconditionError(f"Suricata on {interface} is already enabled")
    elif not mode and not is_enabled:
        raise InvalidPreconditionError(f"Suricata on {interface} is already disabled")
    elif mode and not is_enabled:
        run_command(f'systemctl enable --now suricata@{interface}')
    elif not mode and is_enabled:
        run_command(f'systemctl disable --now suricata@{interface}')


def dhcp_server_verify_and_fill_config_if_needed(config: dict[str, Any]) -> None:
    network_to_interface: dict[str, str] = {}
    for interface, subnet_config in config.items():
        if interface not in LAN_INTERFACES:
            raise InvalidParameterError(f"Interface '{interface}' not in allowed intefaces '{LAN_INTERFACES}'")

        enabled = get_bool(subnet_config, "enabled")
        is_iface_dhcp = is_dhcp(interface)
        if is_iface_dhcp and enabled:
            raise InvalidParameterError("DHCP Server can only be bound to interfaces with static IP")

        if not enabled:
            continue

        get_str(subnet_config, "ip_range")
        get_int(subnet_config, "lease_time")
        dns = get_list(subnet_config, "dns")
        gateway = subnet_config.get("gateway")

        ifaces = get_configured_addresses_and_masks(interface)
        if len(ifaces) < 1:
            raise RuntimeError(f"Interface {interface} has no static IP")

        iface = ipaddress.IPv4Interface(f"{ifaces[0][0]}/{ifaces[0][1]}")
        network = str(iface.network)
        if i := network_to_interface.get(network):
            raise InvalidParameterError(f"Interfaces '{i}' and  '{interface}' are within the same network {network}")
        else:
            network_to_interface[str(network)] = interface

        if len(dns) == 0:
            configured_dns = get_configured_dns(interface)
            dns = configured_dns.split(",") if configured_dns is not None else []
        if gateway is None:
            gateway = str(iface.ip)
        elif not isinstance(gateway, str):
            raise InvalidParameterError(f"Invalid gateway {gateway}")

        config[interface].update({"network": network, "dns": dns, "gateway": gateway})


def dhcp_server_set_interface_state(message: bytes) -> None:
    payload = json.loads(message)
    interface = get_str(payload, "interface")
    enabled = get_bool(payload, "enabled")
    if interface not in LAN_INTERFACES:
        raise InvalidParameterError(f"Interface '{interface}' not in allowed intefaces '{LAN_INTERFACES}'")

    config = _dhcp_server_get_config()
    if config[interface]["ip_range"] is None:
        raise InvalidParameterError(f"DHCP Server is not configured on '{interface}'")

    config[interface]["enabled"] = enabled
    _dhcp_server_set_config(config)


def _dhcp_server_get_config() -> dict[str, Any]:
    try:
        config = Dhcp4Server().get_config()
    except Exception as e:
        config = Dhcp4Server().get_eg_config()
        logger.error(e)

    for iface in LAN_INTERFACES:
        if iface not in config:
            config[iface] = {
                "enabled": False,
                "ip_range": None,
                "lease_time": 3600,
                "dns": [],
                "gateway": None,
            }

    return config


def dhcp_server_get_config(message: bytes) -> dict[str, Any]:
    expect_empty_message(message, "dhcp_server_get_config")
    return {"dhcp_server": _dhcp_server_get_config()}


def dhcp_server_list(message: bytes) -> dict[str, Any]:
    expect_empty_message(message, "dhcp_server_list")
    return {"leases": [lease.to_dict() for lease in Dhcp4Server().get_leases()]}


def _dhcp_server_set_config(new_config: dict[str, Any]) -> None:
    current_config = _dhcp_server_get_config()
    for iface, subnet_config in current_config.items():
        if iface not in new_config:
            new_config[iface] = subnet_config
        else:
            new_config[iface] = {**subnet_config, **new_config[iface]}

    dhcp_server_verify_and_fill_config_if_needed(new_config)
    if current_config != new_config:
        try:
            Dhcp4Server().set_config(new_config)
        except ValueError as e:
            raise InvalidParameterError(str(e))


def dhcp_server_set_config(message: bytes) -> None:
    new_config = get_dict(json.loads(message), "dhcp_server")
    _dhcp_server_set_config(new_config)


def main() -> None:
    def in_bg(topic: str, fun: com_client.SyncHandlerCallable, post_respond: Optional[Callable[[Any], None]] = None) -> None:
        messages[topic] = background(fun, com_client.respond_to(_client, topic), post_respond=post_respond)

    messages = {}
    in_bg(topics.net.set_config, guarded(net_set_config))
    messages[topics.net.set_ignore_default_route] = guarded(sync(net_set_ignore_default_route))
    messages[topics.net.get_config] = guarded(get_config_step_init)
    messages[topics.net.status] = guarded(sync(net_status))
    messages[topics.net.dns.add] = guarded(sync(add_dns))
    messages[topics.net.dns.delete] = guarded(sync(delete_dns))
    messages[topics.net.dns.set_config] = guarded(sync(set_dns_config))
    messages[topics.net.dns.get_config] = guarded(sync(get_current_dns))
    messages[topics.net.cellular.set_config] = guarded(sync(net_cellular_set_config))
    messages[topics.net.cellular.change_state] = guarded(sync(net_cellular_change_state))
    in_bg(topics.net.wifi.client.scan, guarded(net_wifi_client_scan))
    in_bg(topics.net.wifi.client.set_config, guarded(net_wifi_client_set_config))
    in_bg(topics.net.wifi.client.change_state, guarded(net_wifi_client_change_state))
    messages[topics.net.cellular.check] = guarded(sync(cellular_checklist))
    messages[topics.net.promiscous_mode.set_config] = guarded(sync(promiscous_mode_set_config))
    messages[topics.net.ids.change_state] = guarded(sync(change_ids_state))
    messages[topics.net.dhcp_server.get_config] = guarded(sync(dhcp_server_get_config))
    messages[topics.net.dhcp_server.list] = guarded(sync(dhcp_server_list))
    messages[topics.net.dhcp_server.set_config] = guarded(sync(dhcp_server_set_config))
    messages[topics.net.dhcp_server.set_inerface_state] = guarded(sync(dhcp_server_set_interface_state))

    _client.register_responders(messages)

    logger.info('Processing started')

    while True:
        _client.wait_and_receive()


if __name__ == "__main__":
    main()
