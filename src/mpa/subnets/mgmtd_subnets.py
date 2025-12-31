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

# Standard imports
import argparse
import json
import sys
from typing import Any, Dict, Optional, Callable

# Third party imports
from pyroute2 import IPRoute, NetlinkError  # type: ignore

# Local imports
import mpa.communication.topics as topics
from mpa.common.common import RESPONSE_OK
from mpa.common.logger import Logger
from mpa.communication import client as com_client
from mpa.communication.client import guarded, background, sync
from mpa.communication.common import (
    get_macvlans,
    get_ifname,
    get_ifname_to_idx,
    get_lan_interfaces,
    is_macvlan,
    InvalidPayloadError,
)
from mpa.communication.inter_process_lock import InterProcessLock
from mpa.communication.process import run_command_unchecked
from mpa.communication.message_parser import get_str, get_optional_str, get_int, get_dict, get_optional_int
from mpa.config.common import CONFIG_DIR_ROOT
from mpa.device.common import VLANS_CONFIG
from mpa.network.common import DEFAULT_VLAN_METRIC

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")
VLANS_SET_CONFIG_LOCK = InterProcessLock(CONFIG_DIR_ROOT / "mgmtd/vlans.set_config.lock", stale_lock_seconds=60)


def add_macvlan(parent_iface: str, vlan_name: str, ip: str, prefix: int, gateway: str = "", metric: Optional[int] = None) -> None:
    ifname_to_idx = get_ifname_to_idx()
    if vlan_name in ifname_to_idx:
        raise RuntimeError(f"Interface {vlan_name} already exists")

    if parent_iface not in ifname_to_idx:
        raise RuntimeError(f"Parent interface {parent_iface} not found")

    parent_index = ifname_to_idx[parent_iface]
    with IPRoute() as ipr:
        try:
            ipr.link(
                "add",
                ifname=vlan_name,
                kind="macvlan",
                link=parent_index,
                macvlan_mode="bridge"
            )
            logger.info(f"Created macvlan {vlan_name} on {parent_iface}")
        except NetlinkError as e:
            raise RuntimeError(f"Failed to create macvlan: {e}")

        vlan_index = ipr.link_lookup(ifname=vlan_name)[0]
        ipr.addr("add", index=vlan_index, address=ip, prefixlen=prefix)
        ipr.link("set", index=vlan_index, state="up")
        logger.info(f"Assigned {ip}/{prefix} and set {vlan_name} up")
        if gateway:
            try:
                ipr.route(
                    "add", dst="default", gateway=gateway, oif=vlan_index,
                    priority=DEFAULT_VLAN_METRIC if metric is None else metric
                )
                logger.info(f"Added default route via {gateway} on {vlan_name}")
            except NetlinkError as e:
                ipr.link("set", index=vlan_index, state="down")
                ipr.link("del", index=vlan_index)
                raise RuntimeError(
                    f"Failed to set gateway on {vlan_name}: {e}. "
                    f"Make sure that metric {metric} does not collide with another one."
                )


def remove_macvlan(vlan_name: str) -> None:
    with IPRoute() as ipr:
        try:
            idx = ipr.link_lookup(ifname=vlan_name)
            if not idx:
                raise RuntimeError(f"Interface {vlan_name} does not exist")
            ipr.link("set", index=idx[0], state="down")
            ipr.link("del", index=idx[0])
            # previously NetworkManager managed vlans so pyroute2 is not able to remove them
            run_command_unchecked(f"nmcli con delete {vlan_name}")
            run_command_unchecked(f"nmcli dev delete {vlan_name}")
        except NetlinkError as e:
            raise RuntimeError(f"Failed to remove {vlan_name}: {e}")


def get_config(message: bytes) -> Dict[str, Any]:
    config: Dict[str, Any] = {"vlans": {iface: {} for iface in get_lan_interfaces()}}

    with IPRoute() as ipr:
        links = ipr.get_links()
        addrs = {addr['index']: addr for addr in ipr.get_addr(family=2)}

        for link in links:
            if not is_macvlan(link):
                continue

            vlan_name = get_ifname(link)
            parent_index = link.get_attr("IFLA_LINK")
            parent_name = next(
                (get_ifname(link) for link in links if link["index"] == parent_index), None
            )
            if not parent_name:
                continue

            addr_info = addrs.get(link["index"])
            if not addr_info or not addr_info.get("attrs"):
                # some trash, it should be removed
                logger.info(f"Removing `{vlan_name}` as it appears to be unavailable")
                remove_macvlan(vlan_name)
                continue

            ip = next((a[1] for a in addr_info["attrs"] if a[0] == "IFA_ADDRESS"), "")
            prefix = addr_info["prefixlen"]
            gateway = ""
            metric = None
            routes = ipr.get_routes(family=2)
            for route in routes:
                attrs = dict(route['attrs'])
                if route.get('dst') is None and route.get('oif') == link["index"]:
                    gateway = attrs.get('RTA_GATEWAY', "")
                    metric = attrs['RTA_PRIORITY']

            config["vlans"][parent_name][vlan_name] = {
                "ip": ip,
                "subnet": prefix,
                "gateway": gateway,
                "metric": metric,
            }

    return config


def set_config(message: bytes) -> None:
    config = json.loads(message)
    subnets_config = get_dict(config, "vlans")
    with VLANS_SET_CONFIG_LOCK.transaction("Global lock for setting vlans config"):
        for macvlan in get_macvlans():
            remove_macvlan(macvlan)

        for main_interface, vlan_configs in subnets_config.items():
            for vlan_name, vlan_config in vlan_configs.items():
                if not vlan_name.startswith(f"{main_interface}_"):
                    raise InvalidPayloadError(
                        f"VLAN `{vlan_name}` has to start with prefix `{main_interface}_`"
                    )

                ip = vlan_config["ip"]
                prefix = vlan_config["subnet"]
                gateway = vlan_config.get("gateway", "")
                metric = vlan_config.get("metric")
                add_macvlan(main_interface, vlan_name, ip, prefix, gateway, metric)

        config = {"vlans": {iface: {} for iface in get_lan_interfaces()}}
        config["vlans"] = {**config["vlans"], **subnets_config}
        VLANS_CONFIG.write_text(json.dumps(config))


def add(message: bytes) -> None:
    subnet_config = json.loads(message)
    interface = get_str(subnet_config, "interface")
    vlan_name = get_str(subnet_config, "vlan_name")
    address = get_str(subnet_config, "address")
    subnet = get_int(subnet_config, "subnet")
    gateway = get_optional_str(subnet_config, "gateway")
    metric = get_optional_int(subnet_config, "metric")
    with VLANS_SET_CONFIG_LOCK.transaction("Global lock for setting vlans config"):
        config = json.loads(VLANS_CONFIG.read_text())
        if interface not in config["vlans"]:
            raise InvalidPayloadError(f"Unknown interface `{interface}`")

        add_macvlan(interface, vlan_name, address, subnet, gateway, metric)
        config["vlans"][interface][vlan_name] = {
            "ip": address,
            "subnet": subnet,
            "gateway": gateway,
            "metric": metric,
        }

        VLANS_CONFIG.write_text(json.dumps(config))


def remove(message: bytes) -> str:
    config = json.loads(message)
    vlan_name = get_str(config, "vlan_name")
    with VLANS_SET_CONFIG_LOCK.transaction("Global lock for setting vlans config"):
        remove_macvlan(vlan_name)
        config = json.loads(VLANS_CONFIG.read_text())
        for iface in config["vlans"]:
            config["vlans"][iface].pop(vlan_name, None)

        VLANS_CONFIG.write_text(json.dumps(config))

    return f"{RESPONSE_OK} {vlan_name} removed"


def main() -> None:
    _parser = argparse.ArgumentParser(prog='VLAN config daemon')
    com_client.add_command_line_params(_parser)
    _args = _parser.parse_args()
    _client = com_client.Client(args=_args)

    def in_bg(topic: str, fun: com_client.SyncHandlerCallable, post_respond: Optional[Callable[[Any], None]] = None) -> None:
        messages[topic] = background(fun, com_client.respond_to(_client, topic), post_respond=post_respond)

    messages: Dict[str, Any] = {}
    in_bg(topics.net.vlan.get_config, guarded(get_config))
    in_bg(topics.net.vlan.set_config, guarded(set_config))
    messages[topics.net.vlan.add] = guarded(sync(add))
    messages[topics.net.vlan.remove] = guarded(sync(remove))
    _client.register_responders(messages)

    if VLANS_CONFIG.exists():
        # needed for persistent vlans between reboots
        try:
            set_config(VLANS_CONFIG.read_bytes())
        except RuntimeError as e:
            logger.error(f"Unable to set_config: {e}")
    else:
        # previously vlans were managed by NetworkManager and VLANS_CONFIG does not exist
        # so reapply current configuration
        set_config(json.dumps(get_config(b"")).encode())

    while True:
        try:
            _client.wait_and_receive()
        except _client.LostRequestList as lre:
            logger.warning(f"Received LostRequestList: {lre}")
        except _client.ConnectionResetError as cre:
            logger.warning(f"Received ConnectionResetError: {cre}")


if __name__ == "__main__":
    main()
