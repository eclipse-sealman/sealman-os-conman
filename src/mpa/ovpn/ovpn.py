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
from typing import Any, MutableMapping

# Third party imports
import click

# Local imports
from .common import get_ovpn_configs, OVPN_CONFIG_FILE_ALREADY_EXISTS, OvpnAction
from mpa.common.cli import (
    custom_group,
    readable_file_option_decorator,
    writable_file_option_decorator,
)
from mpa.common.common import FileExtension
from mpa.communication import topics
from mpa.communication.client import Client, TrivialHandlerCallable
from mpa.communication.common import (
    exiting_print_message,
    rashly,
    trivial_get_config,
    trivial_set_config,
)

AVAILABLE_TUNNELS = [file.stem for file in get_ovpn_configs()]
tunnel_option_decorator = click.option(
    "-t", "--tunnel", type=click.Choice(AVAILABLE_TUNNELS), required=True, help="Tunnel config name."
)
# TODO
# there is a bug in the upstream that causes wrong shell completion for enums
# so for now we need to stick with a list of strings
action_option_decorator = click.option(
    "-a",
    "--action",
    type=click.Choice([action.value for action in OvpnAction]),
    required=True,
    help="Action to perform. Use 'status' to check current option.",
)


def add_tunnel_response(query_message: MutableMapping[str, Any], client: Client) -> TrivialHandlerCallable:
    """Create response handler for add command."""
    def add_tunnel_response_handler(message: bytes) -> None:
        response = json.loads(message)
        if response == OVPN_CONFIG_FILE_ALREADY_EXISTS:
            click.echo(f"Config file already exists for {query_message['tunnel_name']}.")
            if click.confirm("Do you want to overwrite already existing configuration?"):
                query_message["overwrite"] = True
                client.query(topics.net.ovpn.add_tunnel, query_message, exiting_print_message)
            else:
                sys.exit(0)
        else:
            exiting_print_message(message)

    return add_tunnel_response_handler


@custom_group
def cli() -> None:
    """Manage OpenVPN tunnel configuration."""


@cli.command_with_client()
@readable_file_option_decorator(allowed_extensions=FileExtension.OVPN)
@click.option("-a", "--autostart", type=bool, required=True, help="Enable autostart for this tunnel.")
def add(client: Client, filename: Path, autostart: bool) -> None:
    """Add new OpenVPN tunnel."""
    message = {
        "tunnel_name": filename.stem,
        "autostart": autostart,
        "overwrite": False,
    }

    # TODO give some warning in case file looks big for a ovpn config file...
    # ZMQ can handle huge messages, but we shall be gentle to ourselves :)
    message["config"] = filename.read_text()

    client.query(
        topics.net.ovpn.add_tunnel,
        message,
        rashly(add_tunnel_response(message, client))
    )


@cli.command_with_client(dynamic_completion=True)
@tunnel_option_decorator
def remove(client: Client, tunnel: str) -> None:
    """Remove OpenVPN tunnel."""
    message = {"tunnel_name": tunnel}
    client.query(topics.net.ovpn.remove_tunnel, message, exiting_print_message)


@cli.command_with_client(dynamic_completion=True)
@tunnel_option_decorator
@action_option_decorator
def autostart(client: Client, tunnel: str, action: str) -> None:
    """Disable/enable OpenVPN tunnel autostart."""
    message = {"tunnel_name": tunnel, "action": action}
    client.query(topics.net.ovpn.set_autostart, message, exiting_print_message)


@cli.command_with_client(dynamic_completion=True)
@tunnel_option_decorator
@action_option_decorator
def connection(client: Client, tunnel: str, action: str) -> None:
    """Disable/enable OpenVPN tunnel connection.

    This will only enable/disable the tunnel for current session.
    If you want to have this connection on boot please check autostart option.
    """
    message = {"tunnel_name": tunnel, "action": action}
    client.query(topics.net.ovpn.set_tunnel_state, message, exiting_print_message)


@cli.command_with_client()
@writable_file_option_decorator("ovpn_config.json")
def get_config(client: Client, filename: Path) -> None:
    """Get configuration of OpenVPN tunnel and save it to JSON file."""
    trivial_get_config(client, topic=topics.net.ovpn.get_config, file_name=filename)


@cli.command_with_client()
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
def set_config(client: Client, filename: Path) -> None:
    """Restore OpenVPN tunnel configuration from file.

    This is a permanent change and will replace all existing tunnel configurations.
    """
    trivial_set_config(client, topic=topics.net.ovpn.set_config, file_name=filename)


@cli.command_with_client()
def show(client: Client) -> None:
    """Display OpenVPN tunnel configuration."""
    client.query(topics.net.ovpn.get_config, handler=exiting_print_message)


@cli.command_with_client()
def status(client: Client) -> None:
    """Display OpenVPN tunnel status."""
    client.query(topics.net.ovpn.tunnels_status, handler=exiting_print_message)


#################################################################################
#                               DEPRECATED COMMANDS                             #
#################################################################################


@cli.command_with_client("get_config", hidden=True, deprecated="Use `ovpn get-config`.")
@writable_file_option_decorator("ovpn_config.json")
def get_config_deprecated(client: Client, filename: Path) -> None:
    trivial_get_config(client, topic=topics.net.ovpn.get_config, file_name=filename)


@cli.command_with_client("set_config", hidden=True, deprecated="Use `ovpn set-config`.")
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
def set_config_deprecated(client: Client, filename: Path) -> None:
    trivial_set_config(client, topic=topics.net.ovpn.set_config, file_name=filename)
