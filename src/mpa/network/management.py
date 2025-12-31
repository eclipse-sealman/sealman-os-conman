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
Methods performing actual checks and changes in network configuration.
"""
from __future__ import annotations

# Standard imports
import sys
import glob
import re

from shlex import quote
from typing import Any, List, Mapping, Sequence, Optional, Union

# Local imports
from mpa.communication.process import run_command, run_command_unchecked
from mpa.common.logger import Logger
from mpa.communication.status_codes import SUCCESS
from mpa.communication.common import InvalidPayloadError, InvalidParameterError
from mpa.communication.message_parser import get_list, get_optional_str

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

PATH_TO_PRIMARY_PORT = "/sys/class/net/cellular{interface}/device/usbmisc/*"


def _use_first_element(field: Union[int, str, Sequence[str]]) -> str:
    if isinstance(field, int):
        return str(field)
    if not isinstance(field, str):
        if len(field) != 1:
            logger.info(f"Selecting first element from list {field}")
        return field[0]
    return field


# TODO use python ipaddress for verification
def _ensure_subnet_is_reasonable(subnet: str, interface: str) -> None:
    # Invalid type will raise error which we will log to use as unexpected
    # because UI shall validate types
    bits = int(subnet)
    if bits < 0 or bits > 32:
        raise InvalidParameterError(f"Subnet '{subnet}' is not between 0 and 32 for {interface}")


def assign_ip_configuration(interface: str, config: Mapping[str, Any]) -> None:
    ip_address = _use_first_element(get_list(config, "ip"))
    subnet = _use_first_element(get_list(config, "subnet"))
    _ensure_subnet_is_reasonable(subnet, interface)
    if is_device_connected(interface):
        run_command(f'nmcli con down "{interface}"')
    ip_and_subnet = quote(f"{ip_address}/{subnet}")
    run_command(f'nmcli con mod "{interface}" ipv4.addresses {ip_and_subnet}')
    gateway = get_optional_str(config, "gateway")
    run_command(f'nmcli con mod "{interface}" ipv4.gateway {quote(gateway)}')
    dns = get_optional_str(config, "dns")
    run_command(f'nmcli con mod "{interface}" ipv4.dns {quote(dns)}')
    mtu = get_optional_str(config, "mtu")
    run_command(f'nmcli con mod "{interface}" 802-3-ethernet.mtu {quote(mtu)}')
    run_command(f'nmcli con mod "{interface}" ipv4.method manual')
    run_command(f'nmcli con mod "{interface}" ipv6.method disabled')
    run_command_unchecked(f'nmcli --wait 8 con up "{interface}"')


def set_dhcp(interface: str) -> None:
    if is_device_connected(interface):
        run_command(f'nmcli con down "{interface}"')
    run_command(f'nmcli con mod "{interface}" ipv4.method auto')
    run_command(f'nmcli con mod "{interface}" ipv6.method auto')
    run_command(f'nmcli con mod "{interface}" -ipv4.gateway ""')
    run_command(f'nmcli con mod "{interface}" -ipv4.addresses ""')
    run_command(f'nmcli con mod "{interface}" -ipv4.dns ""')
    run_command_unchecked(f'nmcli --wait 8 con up "{interface}"')


def set_ignore_default_route(interface: str, state: bool) -> None:
    if interface.startswith("cellular"):
        interface_number = re.findall(r'\d+', interface)[0]
        device_name = get_cellular_primary_port(interface_number)

        # create empty connection config with APN "Internet" in case when `ignore_route` was called before `configure_cellular`
        if not create_cellular_connection_if_not_exist(interface_number, device_name, {"apn": "Internet"}):
            return
    else:
        device_name = interface

    state_value = "yes" if state else "no"
    run_command(f'nmcli con mod "{interface}" ipv4.never-default {state_value}')

    # reload interface to apply new changes
    if is_device_connected(device_name):
        run_command(f'nmcli con down "{interface}"')
    run_command_unchecked(f'nmcli --wait 8 con up "{interface}"')


def device_exists(device: str) -> bool:
    return run_command_unchecked(f"nmcli device show {quote(device)}").returncode == SUCCESS


def is_device_connected(device: str) -> bool:
    state = get_nm_param_single_value('GENERAL.STATE', command='device show', target=device)
    return state == "100 (connected)"


def is_connection_available(connection_name: str) -> bool:
    result = run_command("nmcli connection").stdout.decode()
    match = re.findall(fr"^{connection_name}", result, re.MULTILINE)
    return len(match) == 1


def get_cellular_primary_port(interface: int) -> str:
    try:
        return glob.glob(PATH_TO_PRIMARY_PORT.format(interface=interface))[0].split('/')[-1]
    except IndexError:
        raise InvalidParameterError(f"Could not find interface cellular{interface}")


def turn_on_cellular(config: Mapping[str, str], interface: int) -> None:
    primary_port = get_cellular_primary_port(interface)
    if not create_cellular_connection_if_not_exist(interface, primary_port, config):
        return

    def optionally_from_config(entry: str) -> str:
        return quote(config[entry]) if entry in config else ''

    if is_device_connected(primary_port):
        run_command(f'nmcli con down cellular{interface}')

    run_command(f'nmcli con mod cellular{interface} gsm.number {quote(config["access_number"])}')
    run_command(f'nmcli con mod cellular{interface} gsm.apn {quote(config["apn"])}')
    if len(optionally_from_config("pin")) > 0:
        run_command(f'nmcli con mod cellular{interface} gsm.pin {optionally_from_config("pin")}')
    if len(optionally_from_config("password")) > 0:
        run_command(f'nmcli con mod cellular{interface} gsm.password {optionally_from_config("password")}')
    if len(optionally_from_config("username")) > 0:
        run_command(f'nmcli con mod cellular{interface} gsm.username {optionally_from_config("username")}')
    run_command(f'nmcli con mod cellular{interface} ipv6.method disabled')
    run_command(f'nmcli con mod cellular{interface} connection.llmnr 0')
    run_command(f'nmcli con mod cellular{interface} connection.autoconnect true')
    run_command(f'nmcli con mod cellular{interface} connection.interface-name {primary_port}')
    run_command_unchecked(f'nmcli --wait 8 con up cellular{interface}')


def turn_off_cellular(interface: int) -> None:
    run_command(f'nmcli con mod cellular{interface} connection.autoconnect false')
    run_command(f"nmcli con down cellular{interface}")


def create_cellular_connection_if_not_exist(interface: int, primary_port: str, config: Mapping[str, Any]) -> bool:
    if is_connection_available(f"cellular{interface}"):
        return True
    if 'apn' not in config:
        raise InvalidPayloadError(f"Cannot create connection cellular{interface} because apn is missing in config")
    apn = quote(config['apn'])
    run_command(f"nmcli con add type gsm ifname {primary_port} con-name cellular{interface} apn {apn} ")
    return True


def generate_vpn_keys() -> None:
    run_command("./generate.sh", cwd="/opt/openvpn")


def get_nm_param_values(param: str, target: str, command: str = "connection show") -> List[str]:
    result = run_command(f'nmcli -t -f {param} {command} "{target}"')
    lines = result.stdout.decode('utf8').strip().splitlines()
    values = [lin.strip().partition(':')[2].strip() for lin in lines]
    return [val for val in values if val]


def get_nm_param_single_value(param: str, target: str, command: str = "connection show") -> Optional[str]:
    values = get_nm_param_values(param, target, command)
    if len(values) > 1:
        logger.error(f"To many values in {param}: {values}")
        # Unexpected output from nmcli, so RuntimeError
        raise RuntimeError(f"To many values in parameter {param}")
    if len(values) == 0:
        return None
    return values[0]


def reduce_to_single_value_if_possible(values: Sequence[str]) -> Union[None, str, Sequence[str]]:
    if len(values) == 0:
        return None
    if len(values) == 1:
        return values[0]
    return values


def if_nm_param_is_equal(param: str, value: str, target: str, command: str = 'connection show') -> bool:
    return get_nm_param_values(param, target, command)[0] == value


def is_dhcp(interface: str) -> bool:
    return if_nm_param_is_equal("ipv4.method", "auto", interface)


def get_name_for_dev(dev: str) -> str:
    result = run_command("nmcli -t -f DEVICE,NAME connection show --active")
    output = result.stdout.decode('utf8').strip().split("\n")
    for line in output:
        if dev in line:
            name = line.split(":")[1]
            if not isinstance(name, str) or len(name) < 1:
                # Unexpected output from nmcli, so RuntimeError
                raise RuntimeError(f"Invalid name '{name}' found for device {dev}")
            return name
    # Unexpected output from nmcli, so RuntimeError
    raise RuntimeError(f"Expected device {dev} not found")


# ipv4 is configured value, IP4 is actual value of active device
def get_configured_dns(interface: str) -> Optional[str]:
    return get_nm_param_single_value("ipv4.dns", interface)


def get_configured_gateway(interface: str) -> Optional[str]:
    return get_nm_param_single_value("ipv4.gateway", interface)


def get_configured_mtu(interface: str) -> Optional[str]:
    return get_nm_param_single_value("GENERAL.MTU", interface, command="device show")


def get_configured_addresses_and_masks(interface: str) -> Sequence[Sequence[Optional[str]]]:
    addresses_str = get_nm_param_single_value("ipv4.addresses", interface)
    if isinstance(addresses_str, str):
        addresses = addresses_str.split(',')
    else:
        addresses = []
    ips_and_masks = [ip_and_mask.split('/') for ip_and_mask in addresses]
    if len(ips_and_masks) == 1 and len(ips_and_masks[0]) == 1:
        return [(None, None)]
    return ips_and_masks


def get_ignore_default_route(interface: str) -> bool:
    route_state = get_nm_param_single_value("ipv4.never-default", interface)
    return route_state == "yes"


def get_configured_address(interface: str) -> Sequence[Optional[str]]:
    ips_and_masks = get_configured_addresses_and_masks(interface)
    return [x[0] for x in ips_and_masks]


def get_configured_subnetmask(interface: str) -> Sequence[Optional[str]]:
    ips_and_masks = get_configured_addresses_and_masks(interface)
    return [x[1] for x in ips_and_masks]


def get_actual_dns(interface: str) -> Union[None, str, Sequence[str]]:
    return reduce_to_single_value_if_possible(get_nm_param_values("IP4.DNS", interface, command="device show"))


def get_actual_mtu(interface: str) -> Union[None, str, Sequence[str]]:
    return reduce_to_single_value_if_possible(get_nm_param_values("GENERAL.MTU", interface, command="device show"))


def get_actual_gateway(interface: str) -> Union[None, str, Sequence[str]]:
    return reduce_to_single_value_if_possible(get_nm_param_values("IP4.GATEWAY", interface, command="device show"))


def get_actual_address(interface: str) -> Union[None, str, Sequence[str]]:
    output = get_nm_param_values("IP4.ADDRESS", interface, command="device show")
    ips = [x.partition("/")[0] for x in output]
    return reduce_to_single_value_if_possible(ips)


def get_actual_subnetmask(interface: str) -> Union[None, str, Sequence[str]]:
    output = get_nm_param_values("IP4.ADDRESS", interface, command="device show")
    masks = [x.partition("/")[2] for x in output]
    return reduce_to_single_value_if_possible(masks)


def set_promiscous_mode(interface: str, mode: bool) -> None:
    command = f"pkexec /usr/sbin/ip link set {interface} promisc {'on' if mode else 'off'}"
    run_command(command)


def get_promiscous_mode(interface: str) -> bool:
    command = f"/usr/sbin/ip link show {interface}"
    output = run_command(command).stdout.decode()
    return "PROMISC" in output
