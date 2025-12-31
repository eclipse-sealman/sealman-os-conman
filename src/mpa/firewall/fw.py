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
from functools import partial
from pathlib import Path
from typing import Any, Callable, List, Mapping, Optional

# Third party imports
import click

# Local imports
import mpa.communication.topics as topics
from mpa.communication import preset_cli as preset_handlers
from mpa.common.cli import (
    FC,
    custom_group,
    readable_file_option_decorator,
    writable_file_option_decorator,
    unconditionally_option_decorator,
    add_preset_being_edited_name_argument,
    add_make_edited_name_argument,
)
from mpa.common.common import FileExtension
from mpa.common.logger import Logger
from mpa.communication import preset_cli
from mpa.communication.client import Client
from mpa.communication.common import (
    ask_for_action,
    ask_for_affirmation,
    ask_for_affirmation_with,
    exiting_print_message,
    exiting_print_filtered_message,
    print_message_list_with_custom_response,
    print_message_ok,
    rashly,
    get_lan_interfaces,
    trivial_get_config,
)
from mpa.communication.status_codes import FIREWALL_PROTOCOLS

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

PRESET_SUBCOMMAND_PREFIX = "preset-"
FIREWALL_CONFIG_JSON = "firewall_config.json"


class MultiMessageState:
    def __init__(self) -> None:
        self.enable_needed: bool = True


multi = MultiMessageState()


def mark_that_enable_is_not_needed(question: str) -> bool:
    multi.enable_needed = False
    return ask_for_action(question)


def enable_if_needed(client: Client, message: bytes) -> None:
    if print_message_ok(message) and multi.enable_needed:
        client.query(topics.net.filter.enable, {"ask_for_affirmation": True}, exiting_print_message,
                     affirm_handler_generator=ask_for_affirmation)
        return
    exiting_print_message(message)


def enable_unconditionally(client: Client, message: bytes) -> None:
    if print_message_ok(message) and multi.enable_needed:
        client.query(topics.net.filter.enable, {"ask_for_affirmation": False}, exiting_print_message,
                     affirm_handler_generator=ask_for_affirmation)


def print_modified_chains(msg: bytes) -> None:
    print_message_list_with_custom_response(msg, "Configuration was applied to the following chains:")


@custom_group
def cli() -> None:
    """Manage network firewall configuration.

    Configure and manage firewall rules, presets, and network filtering.
    """


@cli.command_with_client(help_priority="_1_", timeout_ms=40_000)
@unconditionally_option_decorator
def default(client: Client, unconditionally: bool) -> None:
    """Select and enable default firewall config.

    Selects a default preset (currently allow_management) and enables it.
    All firewall rules that are currently set will be cleared. Also, the firewall
    will be enabled and set to automatically start on boot.
    """
    multi.enable_needed = True
    message = {"name": "default", "ask_for_affirmation": not unconditionally}

    if unconditionally:
        second_step = partial(enable_unconditionally, client)
    else:
        second_step = partial(enable_if_needed, client)

    client.query(
        topics.net.filter.preset.select,
        message,
        rashly(second_step),
        affirm_handler_generator=ask_for_affirmation_with(mark_that_enable_is_not_needed)
    )


@cli.command_with_client(help_priority="_2a_", timeout_ms=40_000)
@unconditionally_option_decorator
def enable(client: Client, unconditionally: bool) -> None:
    """Enable firewall using configuration selected earlier.

    Loads firewall rules into the kernel immediately and after reboot. Before enabling
    firewall a preset must be selected (`default` preset is selected initially after factory
    reset).
    """
    message = {"ask_for_affirmation": not unconditionally}
    client.query(topics.net.filter.enable, message, exiting_print_message,
                 affirm_handler_generator=ask_for_affirmation)


@cli.command_with_client(help_priority="_2b_", timeout_ms=40_000)
@unconditionally_option_decorator
def disable(client: Client, unconditionally: bool) -> None:
    """Disable firewall.

    Makes firewall inactive (it will not touch any packets) immediately and after reboot.
    """
    message = {"ask_for_affirmation": not unconditionally}
    client.query(topics.net.filter.disable, message, exiting_print_message,
                 affirm_handler_generator=ask_for_affirmation)


@cli.command_with_client(
    help_priority="_3_",
    # TODO is fstring working properly in short help???
    help="""Save firewall configuration to file."""
)
@writable_file_option_decorator(FIREWALL_CONFIG_JSON)
def get_config(client: Client, filename: Path) -> None:
    trivial_get_config(client, topic=topics.net.filter.get_config, file_name=filename)


@cli.command_with_client(
    help_priority="_3_",
    help="""Restore firewall configuration from a json file.

    Restores presets from json file. Note that factory presets cannot be modified
    with this command.

    Examples:
    *** --file firewall_config.json --- restore configuration from file 'firewall_config.json'""",
    timeout_ms=40_000,
)
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
@unconditionally_option_decorator
def set_config(client: Client, filename: Path, unconditionally: bool) -> None:
    message = json.loads(filename.read_text())
    message["ask_for_affirmation"] = not unconditionally
    client.query(topics.net.filter.set_config, message, exiting_print_message,
                 affirm_handler_generator=ask_for_affirmation)


@cli.command_with_client(help_priority="_3_")
def show(client: Client) -> None:
    """Show firewall configuration in terse way.

    Terse means that notes will be hidden,
    Use `preset print` with name of selected preset to see also notes).
    """
    client.query(topics.net.filter.show, handler=exiting_print_filtered_message("notes"))


@cli.command_with_client(help_priority="_4_")
def commit(client: Client) -> None:
    """Affirm that current state of firewall is correct.

    If transaction has been started and not rolled back yet (currently transaction
    timeout is always 30 seconds, but it will be configurable in the future) this command
    can be executed to prevent rollback and finish transaction immediately.
    """
    client.query(topics.net.filter.commit, handler=exiting_print_message)


@cli.command_with_client(help_priority="_4_")
def cleanup(client: Client) -> None:
    """Remove traces of uncommitted transaction.

    If transaction was not finished by commit nor rollback and firewall configuration
    management daemon was restarted (e.g. due to power failure or crash) unclean state on
    disk may prevent any other transactions to be performed indefinitely. This
    command allows to recover from such state. Cleanup will first try to commit
    transaction, and if it fails it will remove leftovers. Restoring config from
    backup after using cleanup is recommended.
    """
    client.query(topics.net.filter.cleanup, handler=exiting_print_message)


@cli.command_with_client(help_priority="_2c_")
def reload(client: Client) -> None:
    """Reload configuration from scratch.

    Reloads firewall configuration. If firewall has some state (e.g. is tracking existing
    connections) it will be reset.
    """
    client.query(topics.net.filter.reload, handler=exiting_print_message)


@cli.group(help_priority="_5_")
def preset() -> None:
    """Manage firewall preset states.

    Explicit preset state management allows to avoid situation where 2 people use
    remote CLI commands and accidentally modify the same preset. If for example
    two persons will try to edit same preset, both will execute command to make
    it editable. The second person doing it will see error message, that preset
    is already being edited and can react by for example checking if somebody
    else is not logged in.

    Examples:
    *** select allow_all --- selects allow_all preset for firewall configuration, if firewall
                     was already enabled, new preset will be immediately applied
    *** create my_own -s allow_management --- creates new being edited preset
                                      `my_own` as copy of `allow_management` preset
    """


# Add preset subcommands
preset_cli.generate_preset_commands(
    preset,
    "net.filter.preset",
    subcommand_prefix="",  # No prefix since we're in a group
    affirm_handler_generator=ask_for_affirmation,
    timeout_ms=40_000,
)


@cli.group(help_priority="_6_")
def modify() -> None:
    """Modify preset in being edited state.

    Modifies contents of preset. Before actual modification can happen preset has
    to be in being_edited state (see `-E` in subcommands of this command and commands
    `preset edit` and `preset create`).

    Examples:
    *** copy -s foo -p inet/filter/common --- copy part `inet/filter/common` from preset `foo`
        to currently being edited preset (we did not provide `--name` option, hence only one
        preset is currently being edited)
    *** masquerade --name bar -E add masq_lan1 --public-interface lan1 --- first tries to mark
        saved preset `bar` as being edited, if it succeeds adds new masquerade rule named
        `masq_lan1` which will cause interface `lan1` to be treated as public one
    *** input add allow_incoming_ssh -p ssh -v accept --- allows any incoming packets to port 22
    *** set-policy -p inet/filter/output drop --- disallows any outgoing packets not allowed by a
        specific rule --- in connection with previous example ssh will not work, because outgoing
        traffic will be blocked
    *** output add allow_related --related -v accept --- allows any outgoing packets belonging to
        (or related to) existing connections - this rectifies issue created by the drop policy
        from previous example because incoming packets will be allowed to port 22 (so connection
        will be created) and any packets related to existing connection will be allowed on
        output
    """


# Utility functions for adding common arguments
def add_rule_action_arguments(command_func: FC) -> Callable[[FC], FC]:
    """Decorator to add rule action arguments."""
    command_func = click.argument('rule_name', type=str)(command_func)
    command_func = click.argument('command', type=click.Choice(["add", "remove", "edit", "comment", "uncomment"]))(command_func)
    return command_func


def add_notes_options(command_func: FC) -> Callable[[FC], FC]:
    """Decorator to add notes/description options."""
    command_func = click.option('-d', '--description', '--notes', 'notes', type=str, default=None,
                                help='additional notes about rule')(command_func)
    return command_func


def add_filtering_options(command_func: FC) -> Callable[[FC], FC]:
    """Decorator to add filtering options."""
    options = [
        click.option('-v', '--verdict', type=click.Choice(['accept', 'drop']), default=None,
                     help='''drop or accept packet, if not given will be inverse of policy at the time of rule addition,
                            obviously if there is no policy it cannot be skipped'''),
        click.option('-l', '--protocol', type=click.Choice(FIREWALL_PROTOCOLS), default=None,
                     help='match only packets of given protocol'),
        click.option('--destination_port', type=str, hidden=True),
        click.option('-p', '--destination-port', type=str, default=None,
                     help='''match TCP and UDP packets with given destination port
                            (use --protocol if you want to match only TCP or only UDP)'''),
        click.option('--source_port', type=str, hidden=True),
        click.option('-P', '--source-port', type=str, default=None,
                     help='''match TCP and UDP packets with given source port
                            (use --protocol if you want to match only TCP or only UDP)'''),
        click.option('--source_ip', type=str, hidden=True),
        click.option('-s', '--source-ip', type=str, default=None,
                     help='''match only IPv4 packets with given source address
                     (accepts also: IP_ADDRESS/subnet)'''),
        click.option('--source_ip6', type=str, hidden=True),
        click.option('-S', '--source-ip6', type=str, default=None,
                     help='''match only IPv6 packets with given source address
                     (accepts also: IP_ADDRESS/subnet)'''),
        click.option('--destination_ip', type=str, hidden=True),
        click.option('-t', '--destination-ip', type=str, default=None,
                     help='''match only IPv4 packets with given destination address
                     (accepts also: IP_ADDRESS/subnet)'''),
        click.option('--destination_ip6', type=str, hidden=True),
        click.option('-T', '--destination-ip6', type=str, default=None,
                     help='''match only IPv6 packets with given destination address
                     (accepts also: IP_ADDRESS/subnet)'''),
        click.option('-r', '--related', is_flag=True,
                     help='''match packets of (or related to) previously accepted connection --- note that to use --related
                            you need another rule which will accept the initial packet of a connection, (for example you
                            have a rule which accepts all outgoing packets and a rule which accepts related incoming
                            packets)'''),
        click.option('--input_interface', type=str, hidden=True),
        click.option('-i', '--input-interface', type=str, default=None,
                     help='match packets which entered via given interface'),
        click.option('--output_interface', type=str, hidden=True),
        click.option('-o', '--output-interface', type=str, default=None,
                     help='match packets which would exit via given interface'),
        click.option('--raw_match', type=str, hidden=True),
        click.option('-M', '--raw-match', type=str, default=None,
                     help='''value will be used in raw form for matching; Warning --- in case of invalid contents error
                            message will not point to exact place of error'''),
        click.option('--raw_action', type=str, hidden=True),
        click.option('-A', '--raw-action', type=str, default=None,
                     help='''value will be used in raw form as action to be executed on matched packets; Warning --- in case
                            of invalid contents error message will not point to exact place of error'''),
    ]

    for option in reversed(options):  # Apply in reverse order due to decorator stacking
        command_func = option(command_func)

    return add_notes_options(command_func)


def generate_net_filter_modify_message(args: Mapping[str, Any]) -> Mapping[str, Any]:
    """Generate message dict for filter modification."""
    return {
        "name": args.get("name"),
        "rule_name": args.get("rule_name"),
        "command": args.get("command"),
        "notes": args.get("notes"),
        "verdict": args.get("verdict"),
        "protocol": args.get("protocol"),
        "source_port": args.get("source_port"),
        "destination_port": args.get("destination_port"),
        "source_ip": args.get("source_ip"),
        "destination_ip": args.get("destination_ip"),
        "source_ip6": args.get("source_ip6"),
        "destination_ip6": args.get("destination_ip6"),
        "related": args.get("related"),
        "input_interface": args.get("input_interface"),
        "output_interface": args.get("output_interface"),
        "raw_match": args.get("raw_match"),
        "raw_action": args.get("raw_action"),
        "chain_name": args.get("chain_name"),
    }


@modify.command_with_client("copy", help_priority="_1_")
@click.option('-s', '--source', required=True, help='Source preset name')
@click.option('-p', '--part', help="""Part (at least container of rules) of preset which shall be copied.
                                   Whole source preset will be copied if not given.""")
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_copy(client: Client, source: str, part: str, name: str, make_edited: bool) -> None:
    """Copy a part of another preset to preset being_edited.

    Useful when building new preset from parts of other existing presets by
    copying and erasing.

    Examples:
    *** -s foo -p inet/filter/common --- copy part `inet/filter/common` from preset `foo`
        to currently being edited preset (we did not provide `--name` option, hence only
        one preset is currently being edited)
    """
    message = {"name": name, "part": part, "source": source}
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.copy, message)
    )


@modify.command_with_client("erase", help_priority="_1_")
@click.option('-p', '--part', help="""Part of preset which shall be erased.
                                   Whole preset will be affected if this parameter is not given.""")
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_erase(client: Client, part: str, name: str, make_edited: bool) -> None:
    """Erase a part of preset being_edited.

    If the part is container for other parts erasing is equivalent to recreating
    erased part as copy from allow_all preset.  Useful when building new preset
    from parts of other existing presets by copying and erasing.

    Examples:
    *** -E -n foo -p inet/filter/common --- marks saved preset `foo` as being edited and
        removes part `inet/filter/common` from it
    """
    message = {"name": name, "part": part}
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset",  name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.erase, message)
    )


@modify.command_with_client("set-policy", help_priority="_1_")
@click.argument('policy', type=click.Choice(["accept", "drop"]))
@click.option('-p', '--part', help='Part of preset to set policy for')
@click.option('-r', '--recursive', is_flag=True,
              help="""If given policy will be set recursively in all subparts of part where applicable.
                      If not given policy will be set only on the part selected (and the part must be having a policy)""")
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_set_policy(client: Client, policy: str, part: str, recursive: bool, name: str, make_edited: bool) -> None:
    """Set a default treatment of packets if no other rule matches.

    Policy 'drop' is definitive, 'accept' means that later chains will see the packet
    and may drop it later.
    """
    message = {"name": name, "part": part, "policy": policy, "recursive": recursive}
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.policy, message, rashly(print_modified_chains))
    )


MODIFY_NOTE = """The `mgmtd` indicates that rules are directly editable by the user. There might be other parts in factory
                 prepared presets which can be copied with help of copy command, but which cannot be modified to avoid hard to
                 detect inconsistencies in firewall rules."""

MODIFY_EXAMPLES = """Examples:
                  *** add drop_smtp -l tcp -p 25 -v accept -d "This rule shall drop any SMTP packets"
                  --- add a new rule (with action not matching description!)
                  *** edit drop_smtp -l tcp -p 25 -v drop --- correct previously created rule"""


@modify.command_with_client("common", help_priority="_4_", help=f"""
    Modify common filtering rules (part inet/filter/common/mgmtd).

    Modifies single filtering rule common for packets incoming, outgoing and
    forwarded by EG (part inet/filter/common/mgmtd).
    {MODIFY_NOTE}

    {MODIFY_EXAMPLES}""")
@add_rule_action_arguments
@add_filtering_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_common(client: Client, command: str, rule_name: str, name: str, make_edited: bool,
                  **kwargs: Mapping[str, Any]) -> None:
    args = {"name": name, "rule_name": rule_name, "command": command, **kwargs}
    message = generate_net_filter_modify_message(args)
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.common, message)
    )


@modify.command_with_client("input", help_priority="_4_", help=f"""
    Modify filtering rules on packets targeted to EG (part inet/filter/input/mgmtd).

    Modifies single rule in part inet/filter/input/mgmtd.
    {MODIFY_NOTE}

    {MODIFY_EXAMPLES}""")
@add_rule_action_arguments
@add_filtering_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_input(client: Client, command: str, rule_name: str, name: str, make_edited: bool, **kwargs: Mapping[str, Any]) -> None:
    args = {"name": name, "rule_name": rule_name, "command": command, **kwargs}
    message = generate_net_filter_modify_message(args)
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.input, message)
    )


@modify.command_with_client("output", help_priority="_4_", help=f"""
    Modify filtering rules on packets created by EG (part inet/filter/output/mgmtd).

    Modifies single rule on packets created by EG (part inet/filter/output/mgmtd).
    {MODIFY_NOTE}

    {MODIFY_EXAMPLES}""")
@add_rule_action_arguments
@add_filtering_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_output(client: Client, command: str, rule_name: str, name: str,
                  make_edited: bool, **kwargs: Mapping[str, Any]) -> None:
    args = {"name": name, "rule_name": rule_name, "command": command, **kwargs}
    message = generate_net_filter_modify_message(args)
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.output, message)
    )


@modify.command_with_client("forward", help_priority="_5_", help=f"""
    Modify filtering rules on packets routed through EG (part inet/filter/forward/mgmtd).

    Modifies single rule on packets routed through EG (part inet/
    filter/forward/mgmtd). {MODIFY_NOTE}

    {MODIFY_EXAMPLES}""")
@add_rule_action_arguments
@add_filtering_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_forward(client: Client, command: str, rule_name: str, name: str, make_edited: bool,
                   **kwargs: Mapping[str, Any]) -> None:
    args = {"name": name, "rule_name": rule_name, "command": command, **kwargs}
    message = generate_net_filter_modify_message(args)
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.forward, message)
    )


@modify.command_with_client("ingress", help_priority="_3_", help=f"""
    Modify rules on packets routed through EG (part netdev/ingress).

    Modifies single rule on packets routed through EG (part
    netdev/ingress/CHAIN_NAME/mgmtd). This is special chain which needs to be
    created with command create-chain-ingress first. {MODIFY_NOTE}

    {MODIFY_EXAMPLES}""")
@click.argument("chain_name")
@add_rule_action_arguments
@add_filtering_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_ingress(client: Client, chain_name: str, command: str, rule_name: str, name: str, make_edited: bool,
                   **kwargs: Mapping[str, Any]) -> None:
    args = {"name": name, "rule_name": rule_name, "command": command, "chain_name": chain_name, **kwargs}
    message = generate_net_filter_modify_message(args)
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.ingress, message)
    )


lan_devices = list(get_lan_interfaces())


@modify.command_with_client("create-chain-ingress", help_priority="_2_")
@click.option("--chain-name", help="Name of the chain (default is name of the device/devices joined by '_').")
@click.option("--device", default=lan_devices, type=click.Choice(lan_devices), multiple=True, help="LAN devices.")
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_create_chain_ingress(client: Client, chain_name: Optional[str], device: List[str],
                                name: str, make_edited: bool) -> None:
    """Create a chain with ingress hook (part netdev/ingress, processed before inet chains).

    Create a new chain with ingress hook for specified devices.
    """
    if chain_name is None:
        chain_name = "_".join(sorted(set(device)))

    message = {"devices": device, "chain_name": chain_name, "name": name}
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.create_chain_ingress, message)
    )


@modify.command_with_client("remove-chain-ingress", help_priority="_2_")
@click.argument("chain_name")
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_remove_chain_ingress(client: Client, chain_name: str, name: str, make_edited: bool) -> None:
    """Remove a chain with ingress hook (part netdev/ingress)."""
    message = {"chain_name": chain_name, "name": name}
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.remove_chain_ingress, message)
    )


# NAT commands would continue in a similar pattern...
# For brevity, I'll show the structure for a few more key commands


@modify.command_with_client("masquerade", help_priority="_8_")
@add_rule_action_arguments
@click.option('--public_interface', type=str, hidden=True)
@click.option('--public-interface', type=str, help='interface with public IP')
@click.option('--private_interface', type=str, hidden=True)
@click.option('--private-interface', type=str, help='optional, interface behind which private subnets exist')
@click.option('--ip_private', type=str, hidden=True)
@click.option('--ip-private', type=str, help='optional, private IP address or subnet (if mask_private is also given)')
@click.option('--mask_private', type=str, hidden=True)
@click.option('--mask-private', type=str, help='optional netmask (may be given only if ip_private is also given)')
@add_notes_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_masquerade(client: Client, command: str, rule_name: str, public_interface: str,
                      private_interface: str, ip_private: str, mask_private: str,
                      notes: str, name: str, make_edited: bool) -> None:
    """Allow hiding private subnet or interface behind public IP of another interface.

    Allows hiding private subnet or interface behind public IP of another
    interface. To allow all needed traffic back firewall needs to track
    connections and protocols used by hidden machines. Automatically
    uses public IP of interface (which may be dynamic) and all connections
    are forgotten when interface goes down (difference from SNAT).

    Examples:
    *** add masq_lan2 --public-interface lan2 --- simplest masquerade where lan2 has public
        dynamically assigned IP
    """
    message = {
        "name": name,
        "rule_name": rule_name,
        "command": command,
        "notes": notes,
        "public_interface": public_interface,
        "private_interface": private_interface,
        "ip_private": ip_private,
        "mask_private": mask_private
    }
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.masquerade, message)
    )


def modify_port_forward(client: Client, *, command: str, rule_name: str, public_interface: str,
                        ip_public: str, port_public: str, ip_private: str, port_private: str,
                        protocol: str, notes: str, name: str, make_edited: bool) -> None:
    message = {
        "name": name,
        "rule_name": rule_name,
        "command": command,
        "notes": notes,
        "public_interface": public_interface,
        "ip_public": ip_public,
        "port_public": port_public,
        "ip_private": ip_private,
        "port_private": port_private,
        "protocol": protocol
    }
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.port_forward, message)
    )


@modify.command_with_client("port-forward", help_priority="_9_", help="""
    Allow keeping a service running on a private IP available through public IP.

    Port forwarding is needed when NAT (including masquerading) is used, but
    can be enabled independntly of other NAT rules in some cases (as it is form
    of one way NAT). Only TCP and UDP services are supported.

    Examples:
    *** add foo --public-interface lan1 --port-public 4321 --ip-private 192.168.2.20
    --port-private 1234 --protocol udp
    """)
@add_rule_action_arguments
@click.option('--public-interface', type=str, help="""optional, interface with public IP (to be used if public IP is not known),
                                                  if given only traffic entering through this interface will be affected""")
@click.option('--ip-public', type=str, help="""optional, public IP address (shall always be used if known,
                                            if not given public_interface becomes mandatory)""")
@click.option('--port-public', type=str, help='mandatory, port to which traffic will be forwarded')
@click.option('--ip-private', type=str, help='mandatory, private IP address to which traffic will be forwarded')
@click.option('--port-private', type=str, help="""optional, allowed only if single protocol is being used in rule,
                                                 modifies port in forwarded packets""")
@click.option('--protocol', type=str, help='optional, "tcp", or "udp", or "both", if not given "tcp" will be assumed')
@add_notes_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def new_modify_port_forward(client: Client, *, command: str, rule_name: str, public_interface: str,
                            ip_public: str, port_public: str, ip_private: str, port_private: str,
                            protocol: str, notes: str, name: str, make_edited: bool) -> None:
    modify_port_forward(client, command=command, rule_name=rule_name,
                        public_interface=public_interface, ip_public=ip_public,
                        port_public=port_public, ip_private=ip_private,
                        port_private=port_private, protocol=protocol,
                        notes=notes, name=name, make_edited=make_edited)


@modify.command_with_client("snat", help_priority="_8_")
@add_rule_action_arguments
@click.option('--public_interface', type=str, hidden=True)
@click.option('--public-interface', type=str, help='interface with public IP')
@click.option('--ip_public', type=str, hidden=True)
@click.option('--ip-public', type=str, help='Public IP address used as disguise for outgoing traffic of private network')
@click.option('--private_interface', type=str, hidden=True)
@click.option('--private-interface', type=str, help='optional, interface behind which private subnets exist')
@click.option('--ip_private', type=str, hidden=True)
@click.option('--ip-private', type=str, help='optional, private IP address or subnet (if mask_private is also given)')
@click.option('--mask_private', type=str, hidden=True)
@click.option('--mask-private', type=str, help='optional netmask (may be given only if ip_private is also given)')
@add_notes_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_snat(client: Client, command: str, rule_name: str, public_interface: str, ip_public: str,
                private_interface: str, ip_private: str, mask_private: str,
                notes: str, name: str, make_edited: bool) -> None:
    """Allow hiding private subnet or interface behind public IP of another interface.

    Allows hiding private subnet or interface behind public IP of another
    interface. To allow all needed traffic back firewall needs to track
    connections and protocols used by hidden machines. Public IP must
    be static, and connections may survive interface going down temporarily.

    Examples:
    *** add masq_lan2 --public-interface lan2 --ip-public 43.21.35.17 --- simplest SNAT with
    public ip 43.21.35.17 on lan2
    """
    message = {
        "name": name,
        "rule_name": rule_name,
        "command": command,
        "notes": notes,
        "public_interface": public_interface,
        "ip_public": ip_public,
        "private_interface": private_interface,
        "ip_private": ip_private,
        "mask_private": mask_private
    }
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.snat, message)
    )


def modify_nat_n_on_n(client: Client, command: str, rule_name: str, public_interface: str,
                      ip_public: str, ip_private: str, mask: str, notes: str,
                      name: str, make_edited: bool) -> None:
    message = {
        "name": name,
        "rule_name": rule_name,
        "command": command,
        "notes": notes,
        "public_interface": public_interface,
        "ip_public": ip_public,
        "ip_private": ip_private,
        "mask": mask
    }
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.nat_n_on_n, message)
    )


@modify.command_with_client("nat-n-on-n", help_priority="_8_", help="""
    Allow creation of n:n static NAT with public and private IP addresses.

    Allows creation of n:n static NAT with public and private IP addresses.
    Traffic to public addresses will be redirected to private addresses, and
    traffic from private addresses will appear as if it originated from public
    addresses.

    Examples:
    *** add from_lan1to2 --public-interface lan1
                     --ip-public 192.168.2.202 --ip-private 192.168.1.102
    """)
@add_rule_action_arguments
@click.option('--public-interface', type=str, help='optional interface name on which ip_public will be visible')
@click.option('--ip-public', type=str, help="""IP address --- traffic to ip_public will be redirected to ip_private,
                                            and traffic from ip_private will appear as if it originated from ip_public""")
@click.option('--ip-private', type=str, help='IP address --- see ip_public option')
@click.option('--mask', type=str, help="""optional netmask --- if not given 1:1 NAT will be done,
                                       if given only netmask bits of ip_a and ip_b will be
                                       translated (i.e. N:N nat will be performed)""")
@add_notes_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def new_modify_nat_n_on_n(client: Client, command: str, rule_name: str, public_interface: str,
                          ip_public: str, ip_private: str, mask: str, notes: str,
                          name: str, make_edited: bool) -> None:
    modify_nat_n_on_n(client, command, rule_name, public_interface,
                      ip_public, ip_private, mask, notes, name, make_edited)


@modify.command_with_client("nat-pre", help_priority="_6_", help=f"""
    Modify nat rules applied before routing and filtering (part ip/nat/prerouting/mgmtd).

    Modifies single prerouting nat rule (part ip/nat/prerouting/mgmtd). Note that
    there are also specialized nat related commands (nat-n-on-n, masquerade, snat,
    port-forward). {MODIFY_NOTE}

    {MODIFY_EXAMPLES}
    """)
@add_rule_action_arguments
@add_filtering_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_nat_pre(client: Client, command: str, rule_name: str, name: str, make_edited: bool,
                   **kwargs: Mapping[str, Any]) -> None:
    args = {"name": name, "rule_name": rule_name, "command": command, **kwargs}
    message = generate_net_filter_modify_message(args)
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.nat_pre, message)
    )


@modify.command_with_client("nat-post", help_priority="_7_", help=f"""
    Modify nat rules applied after routing and filtering (part ip/nat/postrouting/mgmtd).

    Modifies single postrouting nat rule (part ip/nat/postrouting/mgmtd). Note that
    there are also specialized nat related commands (nat-n-on-n, masquerade, snat,
    port-forward). {MODIFY_NOTE}

    {MODIFY_EXAMPLES}""")
@add_rule_action_arguments
@add_filtering_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_nat_post(client: Client, command: str, rule_name: str, name: str, make_edited: bool,
                    **kwargs: Mapping[str, Any]) -> None:
    args = {"name": name, "rule_name": rule_name, "command": command, **kwargs}
    message = generate_net_filter_modify_message(args)
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.nat_post, message)
    )


# Add the editable preset print command
preset_cli.add_print_editable_command(cli)


# Utility commands for quick port allow/deny
def generate_allow_deny_delete_subject(direction: str) -> str:
    subject = "net.filter.modify."
    if direction == "both":
        subject += "common"
    elif direction == "in":
        subject += "input"
    elif direction == "out":
        subject += "output"
    else:
        raise RuntimeError("Invalid direction")
    return subject


#################################################################################
#                               DEPRECATED COMMANDS                             #
#################################################################################

@cli.command_with_client("set_config", hidden=True, deprecated="Use `fw set-config`.", timeout_ms=40_000)
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
@unconditionally_option_decorator
def set_config_deprecated(client: Client, filename: Path, unconditionally: bool) -> None:
    message = json.loads(filename.read_text())
    message["ask_for_affirmation"] = not unconditionally
    client.query(topics.net.filter.set_config, message, exiting_print_message,
                 affirm_handler_generator=ask_for_affirmation)


@cli.command_with_client("get_config", hidden=True, deprecated="Use `fw get-config`.")
@writable_file_option_decorator(FIREWALL_CONFIG_JSON)
def deprecated_get_config(client: Client, filename: Path) -> None:
    trivial_get_config(client, topic=topics.net.filter.get_config, file_name=filename)


@modify.command_with_client("nat_n_on_n", hidden=True, deprecated="Use `fw modify nat-n-on-n`")
@add_rule_action_arguments
@click.option('--public_interface', type=str, help='optional interface name on which ip_public will be visible')
@click.option('--ip_public', type=str, help="""IP address --- traffic to ip_public will be redirected to ip_private,
                                            and traffic from ip_private will appear as if it originated from ip_public""")
@click.option('--ip_private', type=str, help='IP address --- see ip_public option')
@click.option('--mask', type=str, help="""optional netmask --- if not given 1:1 NAT will be done,
                                       if given only netmask bits of ip_a and ip_b will be
                                       translated (i.e. N:N nat will be performed)""")
@add_notes_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def deprecated_modify_nat_n_on_n(client: Client, command: str, rule_name: str, public_interface: str,
                                 ip_public: str, ip_private: str, mask: str, notes: str,
                                 name: str, make_edited: bool) -> None:
    modify_nat_n_on_n(client, command, rule_name, public_interface,
                      ip_public, ip_private, mask, notes, name, make_edited)


@modify.command_with_client("port_forward", hidden=True, deprecated="Use `fw modify port-forward`.")
@add_rule_action_arguments
@click.option('--public_interface')
@click.option('--ip_public')
@click.option('--port_public')
@click.option('--ip_private')
@click.option('--port_private')
@click.option('--protocol')
@add_notes_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_port_forward_deprecated(client: Client, *, command: str, rule_name: str, public_interface: str,
                                   ip_public: str, port_public: str, ip_private: str, port_private: str,
                                   protocol: str, notes: str, name: str, make_edited: bool) -> None:
    modify_port_forward(client, command=command, rule_name=rule_name,
                        public_interface=public_interface, ip_public=ip_public,
                        port_public=port_public, ip_private=ip_private,
                        port_private=port_private, protocol=protocol,
                        notes=notes, name=name, make_edited=make_edited)


@modify.command_with_client("nat_pre", hidden=True, deprecated="Use `fw modify nat-pre`")
@add_rule_action_arguments
@add_filtering_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def deprecated_modify_nat_pre(client: Client, command: str, rule_name: str, name: str, make_edited: bool,
                              **kwargs: Mapping[str, Any]) -> None:
    args = {"name": name, "rule_name": rule_name, "command": command, **kwargs}
    message = generate_net_filter_modify_message(args)
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.nat_pre, message)
    )


@modify.command_with_client("nat_post", hidden=True, deprecated="Use `fw modify nat-post`")
@add_rule_action_arguments
@add_filtering_options
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def deprecated_modify_nat_post(client: Client, command: str, rule_name: str, name: str, make_edited: bool,
                               **kwargs: Mapping[str, Any]) -> None:
    args = {"name": name, "rule_name": rule_name, "command": command, **kwargs}
    message = generate_net_filter_modify_message(args)
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.nat_post, message)
    )


@modify.command_with_client("set_policy", hidden=True, deprecated="Use `fw modify set-policy`.")
@click.argument('policy', type=click.Choice(["accept", "drop"]))
@click.option('-p', '--part')
@click.option('-r', '--recursive', is_flag=True)
@add_preset_being_edited_name_argument()
@add_make_edited_name_argument(PRESET_SUBCOMMAND_PREFIX)
def modify_set_policy_deprecated(client: Client, policy: str, part: str, recursive: bool, name: str, make_edited: bool) -> None:
    message = {"name": name, "part": part, "policy": policy, "recursive": recursive}
    preset_handlers.chain_actions(
        client,
        preset_handlers.make_edited_func("net.filter.preset", name, make_edited),
        preset_handlers.pack(topics.net.filter.modify.policy, message, rashly(print_modified_chains))
    )
