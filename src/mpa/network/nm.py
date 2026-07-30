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
# Standard imports
import json
import sys
from pathlib import Path
from typing import Any, Optional, List, Union, Protocol

# Third party imports
import click

# Local imports
import mpa.communication.topics as topics
from mpa.communication.message_parser import get_dict, get_optional_bool, get_optional_dict, get_optional_str
from .common import AVAILABLE_REGDOMS, DEFAULT_VLAN_METRIC, LAN_WIFI_INTERFACES, SCOPES, TYPES
from mpa.common.cli import (
    custom_group,
    interface_number_argument_decorator,
    interface_name_option_decorator,
    readable_file_option_decorator,
    writable_file_option_decorator,
    PinType,
    unconditionally_option_decorator,
    config_option_decorator,
    add_preset_being_edited_name_argument,
    add_make_edited_name_argument,
)
from mpa.common.common import FileExtension
from mpa.common.logger import Logger
from mpa.communication import preset_cli
from mpa.communication.client import Client, RespondingHandlerCallable
from mpa.communication.common import (
    ask_for_affirmation,
    exiting_print_message,
    get_lan_interfaces,
    get_system_network_interfaces,
    is_network_address_correct,
    print_message_ok,
    read_json,
    trivial_get_config,
)

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

PRESET_SUBCOMMAND_PREFIX = "preset-"
SHOW = "show"
STATUS = "status"
GET_CONFIG = "get-config"
SHOW_GET_CONFIG_STATUS_DESC = f"""Commands `{SHOW}`, `{GET_CONFIG}` and `{STATUS}` are related to checking
                                  network configuration. The difference is on their focus. `{SHOW}` focuses
                                  on showing currently configured values to human. `{GET_CONFIG}` focuses on
                                  whole configuration backup. `{STATUS}` focues on current actual values used by
                                  system and includes also things that are not configurable (like loopback interface)."""
NETWORK_CONFIG_JSON = "network_config.json"
LAN_INTERFACES = list(get_lan_interfaces())


def print_network_status(message: Union[bytes, str]) -> None:
    msg = json.loads(message)
    click.echo(f"Interfaces status:\n{msg['interfaces']}\nRoutes status:\n{msg['routes']}\nLink speed:\n{msg['link_speed']}\n")
    sys.exit(0)


sent_queries: List[Client.QueryId] = []
partial_responses: List[Optional[bool]] = []


def partial_confirm(name: str) -> RespondingHandlerCallable:
    global sent_queries
    index = len(sent_queries)
    global partial_responses
    partial_responses.append(None)

    def handle_partial_response(message: bytes, from_part: bytes, message_id: bytes) -> None:
        if message_id == sent_queries[index].expected_response_id:
            click.echo(f"Received partial response. Response regards {name}:")
            partial_responses[index] = print_message_ok(message)
        shall_exit = True
        success = True
        for resp in partial_responses:
            if resp is None:
                shall_exit = False
                break
            if resp is False:
                success = False
        if shall_exit:
            sys.exit(0 if success else 1)
    return handle_partial_response


@custom_group
def cli() -> None:
    """Manage network.

    Configure and check network related settings except firewall and ovpn.
    """


@cli.command_with_client(
    help=f"""Show network configuration.

    Print network related configurable values of EG to console. In case of
    configuration which may result in dynamically changing values it also shows
    them at the moment when command is executed. {SHOW_GET_CONFIG_STATUS_DESC}

    Examples:
    *** --- the only way to call this command"""
)
def show(client: Client) -> None:
    client.query(topics.net.get_config, handler=exiting_print_message)


@cli.command_with_client(
    help=f"""Show current network status.

    Same as executing classic Linux commands 'ifconfig' and 'route'.
    {SHOW_GET_CONFIG_STATUS_DESC}""",
)
def status(client: Client) -> None:
    client.query(topics.net.status, handler=print_network_status)


@cli.group()
def cellular() -> None:
    """Manage cellular interface.

    Examples:
    *** set 1 on  --- to enable cellular1 interface
    *** set 2 off --- to disable cellular2 interface
    """


@cellular.command_with_client("status")
@interface_number_argument_decorator
def cellular_debug(client: Client, interface: int) -> None:
    data = {"interface": interface}
    client.query(topics.net.cellular.status, data, exiting_print_message)


# TODO add at_boot vs. now (and unify other commands which shall have this distinction)
@cellular.command_with_client("set")
@interface_number_argument_decorator
@click.argument("mode", type=click.Choice(["on", "off"]))
def cellular_set(client: Client, interface: int, mode: str) -> None:
    """Turn on/off cellular modem.

    Use mode `on` to enable connection on mobile network interface. The connection should
    be configured beforehand with `cellular-configure` command.
    Use mode `off` to disconnect mobile network interface.
    """
    data = {"is_enabled": mode == "on", "interface": interface}
    client.query(topics.net.cellular.change_state, data, exiting_print_message)


@cellular.command_with_client(
    "configure",
    help=f"""Add configuration on the device for cellular modem.
    Configures cellular connection parameters. Any previous configuration,
    will be removed, hence all of the parameters with non-default values
    should be provided each time this command is executed (otherwise default
    values will replace previously configured non-default ones). After
    configuration is done it can be checked with `{SHOW}`, or exported with
    `{GET_CONFIG}`.

    Examples:
    *** 1 --apn internet --- configure basic authentication using APN named 'internet'
    without PIN nor user/password authentication for cellular1 interface.
    *** 2 --user USER --password PASSWORD --apn welo.vzwent --- configure authentication based
    on username 'USER' and password 'PASSWORD' with apn named 'welo.vzwent' but without
    PIN for SIM card for cellular2 interface"""
)
@click.option("-a", "--apn", required=True, help="APN name")
@click.option("-p", "--pin", type=PinType(), help="""SIM card PIN, if not given means no PIN is configured on SIM card.
                                                  PIN can only contain digits. To remove the PIN from the configuration,
                                                  omit the "--pin" argument.""")
@click.option("-A", "--access-number", default="*99***1#", show_default=True, help="Phone number of APN.")
@click.option("-u", "--user", help="User name for APN")
@click.option("-P", "--password", help="Password for APN.")
@click.option("-f", "--force_pap", is_flag=True)
@click.option("-m", "--mtu", default=0, type=int, help="MTU value for cellular connection. 0 for auto.")

@interface_number_argument_decorator
def cellular_configure(client: Client, interface: int, pin: str, apn: str, access_number: str, user: str,
                       password: str, force_pap: bool, mtu: int) -> None:
    data = {
        "apn": apn,
        "pin": pin or "",
        "access_number": access_number,
        "username": user or "",
        "password": password or "",
        "interface": interface,
        "force_pap": force_pap,
        "mtu": mtu
    }
    client.query(topics.net.cellular.set_config, data, exiting_print_message)


@cellular.command_with_client("checklist")
def cellular_checklist(client: Client) -> None:
    """Run checks to fix cellular configuration.

    Gather cellular state information."""
    client.query(topics.net.cellular.check, handler=exiting_print_message)


@cli.group()
def wifi() -> None:
    """Manage wifi interface.

    Manages wifi1 interface. Supported modes are WiFi-Client role and
    Access Point (AP) role.

    Examples:
    *** client config --ssid SSID --key KEY --authentication wpa3-sae
    --- configure and connect connection profile with AP based on ssid 'SSID', key 'KEY' with
    authentication 'wpa3-sae' for wifi1 interface
    *** client enable --- enable and connect connection profile on wifi1 interface
    *** client disable --- disable and disconnect connection profile on wifi1 interface
    *** client scan --- scan for available wifi networks
    *** ap config --ssid MyAP --ip 192.168.17.1 --key mypassword --channel 11 --hidden
    --- configure and activate AP with custom settings
    *** ap enable --- enable AP mode with default settings on wifi1
    *** ap disable --- disable AP mode on wifi1
    """


@wifi.group()
def client() -> None:
    """Allows to use wifi interface in client role."""


@client.command_with_client("scan", timeout_ms=40_000)
@click.option("--rescan", type=click.Choice(["auto", "yes", "no"]), default="auto", show_default=True,
              help="used to either force or disable the scan regardless of how fresh the access point list is")
def wifi_client_scan(client: Client, rescan: str) -> None:
    """Scan for available access points."""
    client.query(topics.net.wifi.client.scan, {"rescan": rescan}, handler=exiting_print_message)


class TopicWithChangeState(Protocol):
    change_state: str


def change_state(client: Client, topic: TopicWithChangeState, is_enabled: bool) -> None:
    client.query(topic.change_state, {"is_enabled": is_enabled}, handler=exiting_print_message)


@client.command_with_client("enable")
def wifi_client_enable(client: Client) -> None:
    """Enable and connect configured profile."""
    change_state(client, topics.net.wifi.client, is_enabled=True)


@client.command_with_client("disable", timeout_ms=40_000)
def wifi_client_disable(client: Client) -> None:
    """Disable and disconnect configured profile."""
    change_state(client, topics.net.wifi.client, is_enabled=False)


# Both WPA-PSK and WPA2-PSK supports TKIP (RC4 cipher) and/or CCMP (AES-CBC), the difference is in implementation of these modes
# for more informations see link belowe:
# https://hostap.shmoo.narkive.com/86BTXmS9/difference-between-wpa1-psk-ccmp-and-wpa2-psk-ccmp
@client.command_with_client("config", timeout_ms=60_000)
@click.option("-s", "--ssid", required=True, help="SSID to connect to.")
@click.option("-k", "--key", required=True, help="wpaX-key for the connection.")
@click.option("-a", "--authentication", required=True, type=click.Choice(["wpa-psk", "wpa2-psk", "wpa3-sae"]),
              help="Authentication method WPA-PSK / WPA2-PSK / WPA3-SAE.")
@click.option("-e", "--encryption", default=["auto"], show_default=True, multiple=True,
              type=click.Choice(["auto", "ccmp", "tkip"]),
              help="Encryption mode CCMP and/or TKIP for WPA / WPA2.")
def wifi_client_config(client: Client, ssid: str, key: str, authentication: str, encryption: list[str]) -> None:
    """Configure connection profile using given details.

    Connection state will not be affected, althoguth if connection was up it
    will be truned off and on again to reapply parameters, which may change IP
    address and break TCP connections (e.g. ssh session)."""
    request = {"wifi1": {"ssid": ssid, "key": key, "authentication": authentication, "encryption": encryption}}
    client.query(topics.net.wifi.client.set_config, request, handler=exiting_print_message)


@wifi.group()
def ap() -> None:
    """Manage wifi interface in access point role."""


@ap.command_with_client("enable", timeout_ms=60_000)
def wifi_ap_enable(client: Client) -> None:
    """Enable AP mode on wifi1 using saved or default settings."""
    change_state(client, topics.net.wifi.ap, is_enabled=True)


@ap.command_with_client("disable")
def wifi_ap_disable(client: Client) -> None:
    """Disable AP mode on wifi1."""
    change_state(client, topics.net.wifi.ap, is_enabled=False)


@ap.command_with_client("show")
def wifi_ap_show(client: Client) -> None:
    """Show AP configuration."""
    def handler(message: Union[bytes, str]) -> None:
        config = json.loads(message)
        network = get_dict(config, "network")
        wifi1 = get_optional_dict(network, "wifi1")
        ap = None
        if wifi1 is not None:
            ap = get_optional_dict(wifi1, "ap")
        if ap is None:
            ap = {}
        click.echo(json.dumps(ap, indent=2))
        sys.exit(0)
    client.query(topics.net.get_config, handler=handler)


@ap.command_with_client("status")
def wifi_ap_status(client: Client) -> None:
    """Show AP status."""
    def handler(message: Union[bytes, str]) -> None:
        wifi1 = get_optional_dict(get_dict(json.loads(message), "network"), "wifi1")
        ap_is_enabled = False
        current_ip = ""
        current_subnet = ""
        if wifi1 is not None:
            mode = get_optional_str(wifi1, "mode")
            is_enabled = get_optional_bool(wifi1, "is_enabled")
            if mode == "ap" and is_enabled:
                ap_is_enabled = True
                current_ip = get_optional_str(wifi1, "current_ip")
                current_subnet = get_optional_str(wifi1, "current_subnet")
        result = {
            "is_enabled": ap_is_enabled,
            "current_ip": current_ip,
            "current_subnet": current_subnet,
        }
        click.echo(json.dumps(result, indent=2))
        sys.exit(0)
    client.query(topics.net.get_config, handler=handler)


@ap.command_with_client("config", timeout_ms=60_000)
@click.option("-s", "--ssid", default="EdgeGateway", show_default=True, help="SSID for the access point.")
@click.option("-k", "--key", default="48366Laer", help="PSK for the access point.")
@click.option("-a", "--authentication", type=click.Choice(["wpa-psk", "wpa2-psk", "wpa3-sae", "wpa2-wpa3"]),
              default="wpa2-psk", show_default=True, help="Authentication method.")
@click.option("-e", "--encryption", default=["ccmp"], show_default=True, multiple=True,
              type=click.Choice(["ccmp", "tkip"]),
              help="Encryption mode CCMP and/or TKIP.")
@click.option("-c", "--channel", type=int, default=6, show_default=True, help="WiFi channel (1-11).")
@click.option("--hidden/--no-hidden", default=False, show_default=True, help="Hide SSID in beacons.")
@click.option("-A", "--ip", required=True, help="IP Address.")
@click.option("-S", "--subnet", required=True, type=int, help="Subnet mask (number of bits, so use 24 instead of 255.255.255.0).")
def wifi_ap_config(client: Client, ssid: str, key: str, authentication: str,
                   encryption: list[str], channel: int, hidden: bool,
                   ip: str, subnet: int) -> None:
    """Configure parameters of Access Point on wifi1.

    Connection state will not be affected, although if AP was active it might be
    temporarily brought down to reapply parameters, which may break any existing
    connections of clients. In case change of IP config of wifi interface change
    DHCP config may also need to be changed, and any existing DHCP leases for
    wifi clients may be invalidated."""
    request: dict[str, Any] = {
        "wifi1": {
            "ssid": ssid,
            "key": key,
            "authentication": authentication,
            "encryption": list(encryption),
            "channel": channel,
            "hidden": hidden,
            "ip": [ip],
            "subnet": [subnet]
        }
    }
    client.query(topics.net.wifi.ap.set_config, request, handler=exiting_print_message)


@wifi.group()
def localization() -> None:
    """Configure allowed radio transmission frequencies and powers.

    To adhere to local radio emmision regulations system needs to know where
    it actually is located and which regulatory domain governs its current
    transmissions. Owner of device is responsible for proper setting of
    regulatory domain.

    Note that regulatory domain setting works like radio filter --- if for
    example access point in the system is configured to use channel not allowed
    in configured regulatory domain, the wifi card will not emit anything, which
    in practice will make AP non-functional.

    When regulatory domain is not set (empty string was used as regdom value)
    to avoid breaking local laws restrictions from all countries will be applied
    together (so called global regulatory domain) which in practice means only
    limited number of 2.4GHz band channels in low power mode will be available
    for client wifi mode, and AP mode will be totally blocked."""


@localization.command_with_client("set")
@click.argument("localization", type=click.Choice(AVAILABLE_REGDOMS))
def localization_set(client: Client, localization: str) -> None:
    """Set wifi localization to one from a list of available regulator domains.

    Note that if new regulatory domain is not allowing radio channel configured
    for AP, the AP will cease to function without raising any errors.

    Examples:
    *** DE --- configure Germany as current regulatory domain
    """
    client.query(topics.net.wifi.localization.set_config, {"wifi_localization": localization}, handler=exiting_print_message)


@localization.command_with_client("show")
def localization_show(client: Client) -> None:
    """Show current wifi localization (regulatory domain)."""
    client.query(topics.net.wifi.localization.get_config, handler=exiting_print_message)


@cli.command_with_client(timeout_ms=20_000)
@interface_name_option_decorator
@click.option("--ip", required=True, help="IP address.")
@click.option("--mtu", help="MTU.")
@click.option("--gateway", default="", show_default=True, help="Gateway.")
# TODO naming consitstency --- subnet or mask
# TODO use ip_address module to validate in daemon and allow also classic string masks
@click.option("--subnet", required=True, type=int, help="Subnet mask (number of bits, so use 24 instead of 255.255.255.0).")
@click.option("--dns", default="", show_default=True, help="""DNS to be used when interface is up (if not given,
                                                           DNS will not be associated with this interface being up
                                                           and set to null). You can also add multiple DNS servers
                                                           at once (comma separated).""")
def static_ip(client: Client, name: str, ip: str, gateway: str, mtu: str, subnet: int, dns: str) -> None:
    """Set static ip for network interface.

    Allows to configure static IP addresses on given network interface.
    Replaces any previous configuration of interface (for example to
    remove gateway execute this command with same --ip parameter as
    currently set, but without --gateway parameter).

    Examples:
    *** --name lan1 --ip 10.0.0.1 --subnet 8 --- configure static ip 10.0.0.1/8 on lan1
    without gateway!
    *** --name lan2 --ip 192.168.1.2 --gateway 192.168.1.1 --subnet 24 --- configure static ip 192.168.1.2/24
    with gateway 192.168.1.1
    """
    data = {"network": {name: {"dhcp": False, "ip": [ip], "subnet": [subnet], "gateway": gateway, "dns": dns, "mtu": mtu}}}
    client.query(topics.net.set_config, data, exiting_print_message)


@cli.command_with_client(timeout_ms=20_000,
    help=f"""Set dhcp on network interface.

    Causes given network interface to use DHCP for obtaning network
    configuration. Any static configuration will be forgotten. First DHCP
    request will be sent immediately. Command will wait up to 8 seconds for
    connection to be up. No error reporting is performed --- always verify
    connection status if you want to be sure DHCP worked as expected (e.g.
    by executing `nm {SHOW}`).

    Examples:
    *** --name lan2 --- use DHCP for lan2
    """
)
@interface_name_option_decorator
def dhcp(client: Client, name: str) -> None:
    data = {"network": {name: {"dhcp": True}}}
    # TODO add proper error reporting to network_management --- we switched to run_command_unchecked there, but it means we cannot
    # report any error!!!
    client.query(topics.net.set_config, data, exiting_print_message)


@cli.command_with_client()
@interface_name_option_decorator
@click.option("-i", "--ignore", required=True, type=bool, help="Ignore route from DHCP.")
def ignore_default_route(client: Client, name: str, ignore: bool) -> None:
    """Enable/disable deafult route from DHCP.

    Allows to ignore default route provided by DHCP (this may be required
    in case another default route is preferred).

    Examples:
    *** --name lan2 -i yes --- default route provided by DHCP on lan2 will be ignored
    *** -n lan1 --ignore no --- default route provided by DHCP on lan1 will be added to
    routing table
    """
    data = {"network": {name: {"ignore_default_route": ignore}}}
    client.query(topics.net.set_ignore_default_route, data, exiting_print_message)


@cli.command_with_client(timeout_ms=60_000)
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
@unconditionally_option_decorator
def set_config(client: Client, filename: Path, unconditionally: bool) -> None:
    """Set network configuration from a json file.

    Replaces whole network configuration of EG with the one provided by json
    file. The file could have been generated on same or another device.

    Examples:
    *** --filename file-network_config.json --- restore configuration from file 'network_config.json'
    """
    message = read_json(filename)
    message["ask_for_affirmation"] = not unconditionally
    global sent_queries
    sent_queries = []
    client.register_observer_handler(f"{topics.net.set_config}.resp", partial_confirm("network config"))
    sent_queries.append(client.query(topics.net.set_config, message))
    for name, topic in {"routes": topics.net.routing.set_config, "vlans": topics.net.vlan.set_config}.items():
        if name in message:
            client.register_observer_handler(f"{topic}.resp", partial_confirm(f"{name} config"))
            sent_queries.append(client.query(topic, message))
        else:
            logger.warning(f"Ignoring missing '{name}' config in file {filename} while performing nm set-config")


@cli.command_with_client(
    help=f"""Save network configuration in a file (default is '{NETWORK_CONFIG_JSON}')

    Stores whole network related config for e.g. backup purposes into file
    {NETWORK_CONFIG_JSON}. {SHOW_GET_CONFIG_STATUS_DESC}

    Examples:
    *** --- the only way to call this command"""
)
@writable_file_option_decorator(NETWORK_CONFIG_JSON)
def get_config(client: Client, filename: Path) -> None:
    trivial_get_config(client, topic=topics.net.get_config, file_name=filename)


@cli.group()
def static_routing() -> None:
    """Configure static routing.

    Manages static routing rules, both global and interface specific.
    Because routing rules can become quite complicated and to allow quick
    changes of configuration routing rules are stored in presets.

    Examples:
    *** enable --- enables static routing rules stored in currently selected preset
    *** add -a 192.168.0.0 -s 24 -d lan1 --- add route to 192.168.0.0/24 via `lan1` device
    *** order -i 1 -I 2 -c lan1 --- change order of rules for `lan1` device in edited preset
    *** remove -i 1 -c lan1 --- remove rule from `lan1` device in edited preset
    """


preset_cli.add_print_editable_command(static_routing, "net.routes")


@static_routing.command_with_client("add")
@click.option("-m", "--metric", type=int, default=100, show_default=True, help="Mettric of route.")
@click.option("-a", "--network_address", required=True, help="Destination network address, eg. 192.168.0.1.")
# TODO naming consitstency --- subnet or mask
@click.option("-s", "--subnet", required=True, help="Destination network subnet, eg. 24.")
@click.option("-v", "--via", help="""Gateway address. Routing means that (almost) unmodified IP packet is sent over
                                  selected physical link within physical packet addressed to gateway --- therefore
                                  gateway must be directly reachable using physical (e.g. MAC for Ethernet) address
                                  on given interface --- this is by default ensured by kernel by refusing to add
                                  route if gateway address is not in subnet configured on given interface.
                                  Note that if the gateway address is same as one of configured ip addresses of EG
                                  own interfaces the --bind option will be implied for this rule)""")
@click.option("-d", "--dev", help=f"""Device name (note that if this option is given --bind is implied too),
                                 devices available in system {get_system_network_interfaces()}""")
@click.option("-t", "--type", type=click.Choice(TYPES), default="unicast", show_default=True,
              help="Type of route, defaults to 'unicast'")
@click.option("-b", "--bind", help="""Bind route to specific interface. If rule is bound to a specific interface system will
                                   automatically add or remove this rule depending on the interface status. Note that even if
                                   this option is not given manually it may be implied based on --dev or --via options. Rules
                                   not bound to specific interfaces are global and will be applied only on EG startup or full
                                   reload of all static routes.""")
@click.option("-S", "--scope", type=click.Choice(SCOPES), help="Select rule scope.")
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def static_routing_add(
    client: Client,
    metric: int,
    network_address: str,
    subnet: int,
    via: str,
    dev: str,
    type: str,
    bind: str,
    scope: str,
    name: str,
    make_edited: bool
) -> None:
    """Add new routing roule to edited preset."""
    status, proposed_valid = is_network_address_correct(network_address, subnet)
    if status is False:
        if len(proposed_valid) > 0:
            click.echo(f"Network address is invalid (did you mean {proposed_valid}?)")
        else:
            click.echo("Network address is invalid")
        exit(1)
    request = {
        "name": name,
        "metric": metric,
        "network": network_address,
        "subnet": subnet,
        "via": via,
        "dev": dev,
        "type": type,
        "bind": bind,
        "scope": scope
    }
    preset_cli.chain_actions(
        client,
        preset_cli.make_edited_func("net.routes.preset", name, make_edited),
        preset_cli.pack(topics.net.route.add, request)
    )


@static_routing.command_with_client("remove")
@click.option("-i", "--id", type=int, required=True, help="ID of route to be deleted in currently edited preset.")
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
@config_option_decorator
def static_routing_remove(client: Client, id: int, name: str, make_edited: bool, config: str) -> None:
    """Remove rule from global or interface config in edited preset."""
    request = {"name": name, "id": id, "config": config}
    preset_cli.chain_actions(
        client,
        preset_cli.make_edited_func("net.routes.preset", name, make_edited),
        preset_cli.pack(topics.net.route.remove, request)
    )


@static_routing.command_with_client("order")
@click.option("-i", "--id", type=int, required=True, help="ID of first rule.")
@click.option("-I", "--ID", "id2", type=int, required=True, help="ID of second rule.")
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
@config_option_decorator
def static_routing_order(client: Client, id: int, id2: int, name: str, make_edited: bool, config: str) -> None:
    """Change order of two elements."""
    request = {"name": name, "id": id, "id2": id2, "config": config}
    preset_cli.chain_actions(
        client,
        preset_cli.make_edited_func("net.routes.preset", name, make_edited),
        preset_cli.pack(topics.net.route.order, request)
    )


@static_routing.command_with_client("enable")
def static_routing_enable(client: Client) -> None:
    """Enable routing rules in selected preset."""
    client.query(topics.net.route.enable, handler=exiting_print_message)


@static_routing.command_with_client("disable")
def static_routing_disable(client: Client) -> None:
    """Disable routing rules added by selected preset."""
    client.query(topics.net.route.disable, handler=exiting_print_message)


# add preset subcommands preset- ... maybe it should be a group called preset
preset_cli.generate_preset_commands(
    static_routing,
    "net.routes.preset",
    subcommand_prefix=PRESET_SUBCOMMAND_PREFIX,
    affirm_handler_generator=ask_for_affirmation,
)


@cli.command_with_client()
@click.argument("interface")
@click.argument("mode", type=click.Choice(["on", "off"]))
def promiscous_mode(client: Client, interface: str, mode: str) -> None:
    """Enable/disable promiscous mode on a given interface.

    Examples:
    *** lan1 on --- turn on promiscous mode on lan1
    *** lan2 off --- turn off promiscous mode on lan2
    """
    data = {"interface": interface, "mode": mode == "on"}
    client.query(topics.net.promiscous_mode.set_config, data, handler=exiting_print_message)


@cli.group()
def dns() -> None:
    """Manipulate EG system DNS settings.

    Add and remove DNS servers to the network configuration which will be used with priority.
    DNS entries set in resolved.conf override those from DHCP or manual.
    Ensures consistent, central DNS configuration for all interfaces.
    """


@dns.command_with_client("add")
@click.argument("ip_address")
def dns_add(client: Client, ip_address: str) -> None:
    """Add a DNS Server."""
    client.query(topics.net.dns.add, {"dns_server": ip_address}, exiting_print_message)


@dns.command_with_client("delete")
@click.argument("ip_address")
def dns_delete(client: Client, ip_address: str) -> None:
    """Remove the specified DNS Server."""
    client.query(topics.net.dns.delete, {"dns_server": ip_address}, exiting_print_message)


@dns.command_with_client("show")
def dns_show(client: Client) -> None:
    """Show the currently configured DNS Servers."""
    client.query(topics.net.dns.get_config, handler=exiting_print_message)


@dns.command_with_client("override-nic-config")
@click.argument("mode", type=click.Choice(["enable", "disable"]))
def dns_override_nic_config(client: Client, mode: str) -> None:
    """Enable or disable system DNS stub listener."""
    client.query(
        topics.net.dns.set_config,
        {"dns": {"override_nic_config": mode == "enable"}},
        exiting_print_message,
    )


@cli.command_with_client()
@click.argument("interface")
@click.argument("mode", type=click.Choice(["enable", "disable"]))
def ids(client: Client, interface: str, mode: str) -> None:
    """Enable/disable IDS on a given interface.

    Examples:
    *** lan1 enable --- turn on IDS on lan1
    *** lan2 disable --- turn off IDS on lan2
    """
    data = {"interface": interface, "mode": mode == "enable"}
    client.query(topics.net.ids.change_state, data, handler=exiting_print_message)


@cli.group()
def dhcp_server() -> None:
    """Manage DHCP server."""


@dhcp_server.command_with_client(name="show")
def dhcp_server_show(client: Client) -> None:
    """Show DHCP Server configuration."""
    client.query(topics.net.dhcp_server.get_config, handler=exiting_print_message)


@dhcp_server.command_with_client(name="list")
def dhcp_server_list(client: Client) -> None:
    """List DHCP Server leases."""
    client.query(topics.net.dhcp_server.list, handler=exiting_print_message)


@dhcp_server.command_with_client(name="enable")
@click.argument("interface", type=click.Choice(LAN_WIFI_INTERFACES))
def dhcp_server_enable(client: Client, interface: str) -> None:
    """Enable DHCP Server on a given interface."""
    client.query(
        topics.net.dhcp_server.set_inerface_state,
        {"interface": interface, "enabled": True},
        exiting_print_message
    )


@dhcp_server.command_with_client(name="disable")
@click.argument("interface", type=click.Choice(LAN_WIFI_INTERFACES))
def dhcp_server_disable(client: Client, interface: str) -> None:
    """Disable DHCP Server on a given interface."""
    client.query(
        topics.net.dhcp_server.set_inerface_state,
        {"interface": interface, "enabled": False},
        exiting_print_message
    )


@dhcp_server.command_with_client(name="config")
@click.option("-r", "--ip-range", required=True,
              help="IP range - two IP addresses seperated by '-' (eg 192.168.2.10-192.168.2.100).")
@click.option("-l", "--lease-time", default=3600, show_default=True, help="Lease time in seconds.")
@click.option("-d", "--dns", help="DNS Server(s) to be provided to the client seperated by ',' (eg 8.8.8.8,1.1.1.1).")
@click.option("-g", "--gateway", help="Gateway to be provided to the client (eg 192.168.2.1).")
@click.argument("interface", type=click.Choice(LAN_WIFI_INTERFACES))
def dhcp_server_config(client: Client, ip_range: str, lease_time: int, dns: str, gateway: str, interface: str) -> None:
    """Configure the DHCP Server.

    Use this command to configure and activate DHCP Server on a single interface.
    """
    client.query(
        topics.net.dhcp_server.set_config,
        {
            "dhcp_server": {
                interface: {
                    "ip_range": ip_range,
                    "lease_time": lease_time,
                    "dns": dns.split(",") if dns else [],
                    "gateway": gateway
                }
            }
        },
        exiting_print_message,
    )


@cli.group()
def vlan() -> None:
    """Add or remove vlan."""


@vlan.command_with_client("add")
@click.option("-i", "--interface", required=True, type=click.Choice(LAN_INTERFACES))
@click.option("-v", "--vlan-name", required=True)
@click.option("-a", "--address", required=True)
@click.option("-s", "--subnet", type=int, required=True)
@click.option("-g", "--gateway", default="")
@click.option(
    "-m", "--metric", type=int, default=DEFAULT_VLAN_METRIC, show_default=True,
    help="Metric that should be used for default route (gateway). It applies only if gateway is provided."
)
def vlan_add(client: Client, interface: str, vlan_name: str, address: str, subnet: int, gateway: str, metric: int) -> None:
    """Add a new vlan to existing interface."""
    client.query(
        topics.net.vlan.add,
        {
            "interface": interface,
            "vlan_name": vlan_name if vlan_name.startswith(f"{interface}_") else f"{interface}_{vlan_name}",
            "address": address,
            "subnet": subnet,
            "gateway": gateway,
            "metric": metric,
        },
        exiting_print_message
    )


@vlan.command_with_client("remove")
@click.argument("vlan_name")
def vlan_remove(client: Client, vlan_name: str) -> None:
    """Remove vlan from interface."""
    client.query(topics.net.vlan.remove, {"vlan_name": vlan_name}, exiting_print_message)


@vlan.command_with_client("show")
def vlan_show(client: Client) -> None:
    """Show vlans."""
    client.query(topics.net.vlan.get_config, handler=exiting_print_message)


#################################################################################
#                               DEPRECATED COMMANDS                             #
#################################################################################


@cli.command_with_client("turn_on_cellular", hidden=True, deprecated="Use `nm cellular set`.")
@interface_number_argument_decorator
def turn_on_cellular_deprecated(client: Client, interface: int) -> None:
    data = {"state": "on", "interface": interface}
    client.query(topics.net.cellular.change_state, data, exiting_print_message)


@cli.command_with_client("turn_off_cellular", hidden=True, deprecated="Use `nm cellular set`.")
@interface_number_argument_decorator
def turn_off_cellular_deprecated(client: Client, interface: int) -> None:
    data = {"state": "off", "interface": interface}
    client.query(topics.net.cellular.change_state, data, exiting_print_message)


@cli.command_with_client("configure_cellular", hidden=True, deprecated="Use `nm cellular configure`.")
@click.option("-a", "--apn", required=True)
@click.option("-p", "--pin", type=PinType())
@click.option("-A", "--access_number", default="*99***1#", show_default=True)
@click.option("-u", "--user")
@click.option("-P", "--password")
@click.option("-f", "--force_pap", is_flag=True)
@interface_number_argument_decorator
def configure_cellular_deprecated(client: Client, interface: int, pin: str, apn: str, access_number: str, user: str,
                                  password: str, force_pap: str) -> None:
    data = {
        "apn": apn,
        "pin": pin or "",
        "access_number": access_number,
        "username": user or "",
        "password": password or "",
        "interface": interface,
        "force_pap": force_pap
    }
    client.query(topics.net.cellular.set_config, data, exiting_print_message)


@cli.command_with_client("cellular_turn_on", hidden=True, deprecated="Use `nm cellular set`.")
@interface_number_argument_decorator
def cellular_turn_on_deprecated(client: Client, interface: int) -> None:
    data = {"state": "on", "interface": interface}
    client.query(topics.net.cellular.change_state, data, exiting_print_message)


@cli.command_with_client("cellular_turn_off", hidden=True, deprecated="Use `nm cellular set`.")
@interface_number_argument_decorator
def cellular_turn_off_deprecated(client: Client, interface: int) -> None:
    data = {"state": "off", "interface": interface}
    client.query(topics.net.cellular.change_state, data, exiting_print_message)


@cli.command_with_client("cellular_configure", hidden=True, deprecated="Use `nm cellular configure`.")
@click.option("-a", "--apn", required=True)
@click.option("-p", "--pin", type=PinType())
@click.option("-A", "--access_number", default="*99***1#", show_default=True)
@click.option("-u", "--user")
@click.option("-P", "--password")
@interface_number_argument_decorator
def cellular_configure_deprecated(client: Client, interface: int, pin: str, apn: str, access_number: str, user: str,
                                  password: str) -> None:
    data = {
        "apn": apn,
        "pin": pin or "",
        "access_number": access_number,
        "username": user or "",
        "password": password or "",
        "interface": interface
    }
    client.query(topics.net.cellular.set_config, data, exiting_print_message)


@cli.command_with_client("cellular_checklist", hidden=True, deprecated="Use `nm cellular checklist`.")
def cellular_checklist_deprecated(client: Client) -> None:
    client.query(topics.net.cellular.check, handler=exiting_print_message)


@cli.command_with_client("static_ip", timeout_ms=20_000, hidden=True, deprecated="Use `nm static-ip`.")
@click.option("--name", required=True, type=click.Choice(LAN_INTERFACES))
@click.option("--ip", required=True)
@click.option("--gateway", default="", show_default=True)
@click.option("--mtu")
@click.option("--subnet", required=True, type=int)
@click.option("--dns", default="", show_default=True)
def static_ip_deprecated(client: Client, name: str, ip: str, gateway: str, mtu: str, subnet: int, dns: str) -> None:
    data = {"network": {name: {"dhcp": False, "ip": [ip], "subnet": [subnet], "gateway": gateway, "dns": dns, "mtu": mtu}}}
    client.query(topics.net.set_config, data, exiting_print_message)


@cli.command_with_client("ignore_default_route", hidden=True, deprecated="Use `nm ignore-default-route`.")
@interface_name_option_decorator
@click.option("-i", "--ignore", required=True, type=bool)
def ignore_default_route_deprecated(client: Client, name: str, ignore: bool) -> None:
    data = {
        "network": {
            name: {
                "ignore_default_route": ignore
            }
        }
    }
    client.query(topics.net.set_ignore_default_route, data, exiting_print_message)


@cli.command_with_client("set_config", timeout_ms=60_000, hidden=True, deprecated="Use `nm set-config`.")
@readable_file_option_decorator()
@unconditionally_option_decorator
def set_config_deprecated(client: Client, filename: Path, unconditionally: bool) -> None:
    message = read_json(filename)
    message["ask_for_affirmation"] = not unconditionally
    global sent_queries
    sent_queries = []
    client.register_observer_handler(f"{topics.net.set_config}.resp", partial_confirm("network config"))
    sent_queries.append(client.query(topics.net.set_config, message))
    if 'routes' in message:
        client.register_observer_handler(f"{topics.net.routing.set_config}.resp", partial_confirm("routes config"))
        sent_queries.append(client.query(topics.net.routing.set_config, message))
    else:
        logger.warning(f"Ignoring missing 'routes' config in file {filename} while performing device set_config")


@cli.command_with_client("get_config", hidden=True, deprecated="Use `nm get-config`.")
@writable_file_option_decorator(NETWORK_CONFIG_JSON)
def get_config_deprecated(client: Client, filename: Path) -> None:
    trivial_get_config(client, topic=topics.net.get_config, file_name=filename)


@cli.command_with_client("promiscous_mode", hidden=True, deprecated="Use `nm promiscous-mode`.")
@click.argument("interface")
@click.argument("mode", type=click.Choice(["on", "off"]))
def promiscous_mode_deprecated(client: Client, interface: str, mode: str) -> None:
    data = {"interface": interface, "mode": mode == "on"}
    client.query(topics.net.promiscous_mode.set_config, data, handler=exiting_print_message)


@cli.group("static_routing", hidden=True, deprecated="Use `nm static-routing`.")
def static_routing_deprecated() -> None:
    ...


preset_cli.add_print_editable_command(static_routing_deprecated, "net.routes")


@static_routing_deprecated.command_with_client("add", hidden=True, deprecated="Use `nm static-routing add`.")
@click.option("-m", "--metric", type=int, default=100, show_default=True)
@click.option("-a", "--network_address", required=True)
@click.option("-s", "--subnet", required=True)
@click.option("-v", "--via")
@click.option("-d", "--dev")
@click.option("-t", "--type", type=click.Choice(TYPES), default="unicast", show_default=True)
@click.option("-b", "--bind")
@click.option("-S", "--scope", type=click.Choice(SCOPES))
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def static_routing_add_deprecated(
    client: Client,
    metric: int,
    network_address: str,
    subnet: int,
    via: str,
    dev: str,
    type: str,
    bind: str,
    scope: str,
    name: str,
    make_edited: bool
) -> None:
    status, proposed_valid = is_network_address_correct(network_address, subnet)
    if status is False:
        if len(proposed_valid) > 0:
            click.echo(f"Network address is invalid (did you mean {proposed_valid}?)")
        else:
            click.echo("Network address is invalid")
        exit(1)
    request = {
        "name": name,
        "metric": metric,
        "network": network_address,
        "subnet": subnet,
        "via": via,
        "dev": dev,
        "type": type,
        "bind": bind,
        "scope": scope
    }
    preset_cli.chain_actions(
        client,
        preset_cli.make_edited_func("net.routes.preset", name, make_edited),
        preset_cli.pack(topics.net.route.add, request)
    )


@static_routing_deprecated.command_with_client("remove", hidden=True, deprecated="Use `nm static-routing remove`.")
@click.option("-i", "--id", type=int, required=True)
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument("preset_")
@config_option_decorator
def static_routing_remove_deprecated(client: Client, id: int, name: str, make_edited: bool, config: str) -> None:
    request = {"name": name, "id": id, "config": config}
    preset_cli.chain_actions(
        client,
        preset_cli.make_edited_func("net.routes.preset", name, make_edited),
        preset_cli.pack(topics.net.route.remove, request)
    )


@static_routing_deprecated.command_with_client("order", hidden=True, deprecated="Use `nm static-routing order`.")
@click.option("-i", "--id", type=int, required=True)
@click.option("-I", "--ID", "id2", type=int, required=True)
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument("preset_")
@config_option_decorator
def static_routing_order_deprecated(client: Client, id: int, id2: int, name: str, make_edited: bool, config: str) -> None:
    """Change order of two elements."""
    request = {"name": name, "id": id, "id2": id2, "config": config}
    preset_cli.chain_actions(
        client,
        preset_cli.make_edited_func("net.routes.preset", name, make_edited),
        preset_cli.pack(topics.net.route.order, request)
    )


@static_routing_deprecated.command_with_client("enable", hidden=True, deprecated="Use `static-routing enable`.")
def static_routing_enable_deprecated(client: Client) -> None:
    client.query(topics.net.route.enable, handler=exiting_print_message)


@static_routing_deprecated.command_with_client("disable", hidden=True, deprecated="Use `nm static-routing disable`.")
def static_routing_disable_deprecated(client: Client) -> None:
    client.query(topics.net.route.disable, handler=exiting_print_message)


# add preset subcommands preset- ... maybe it should be a group called preset
preset_cli.generate_preset_commands(
    static_routing_deprecated,
    "net.routes.preset",
    subcommand_prefix="preset_",
    affirm_handler_generator=ask_for_affirmation
)
