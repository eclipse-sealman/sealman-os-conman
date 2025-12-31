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
from typing import Any, Optional, Union, Tuple as t_Tuple

import click

from mpa.common.cli import (
    CustomGroup,
    add_preset_source_argument,
    add_preset_name_argument,
    add_preset_being_edited_name_argument,
    add_make_edited_name_argument,
    add_preset_part_argument,
    unconditionally_option_decorator,
)
from mpa.communication.client import (
    Client,
    AffirmHandlerGenerator,
    QueryHandlerCallable,
)
from mpa.communication.common import (
    exiting_print_message,
    exiting_print_sorted_message,
    print_message_exit_if_not_ok,
)

ATOMIC_ACTIONS_INFO = ("This is atomic operation -- even if more than one actor can access EG at the same time they will "
                       "receive error if they try to perform conflicting atomic actions. Atomic operations are: preset "
                       "selection, creating new preset, saving or making preset edited, reading all presets for backup or "
                       "restoring all presets from backup.")
AFFIRM_NOTE = ("This operation may require confirmation by the user after it is applied to prevent accidental loss of "
               "communication between user and EG. If such confirmation is not received it will be rolled back. If such "
               "confirmation is required, then operation starts at the moment of execution and ends at the moment it is "
               "rolled back or commited.")
SOURCE = "--source"
PART = "--part"
MAKE_EDITED = "--make-edited"


def generate_preset_commands(
    group: CustomGroup,
    topic_prefix: str,
    subcommand_prefix: str = "",
    affirm_handler_generator: Optional[AffirmHandlerGenerator] = None,
    timeout_ms: int = 40_000,
) -> None:
    @group.command_with_client(
        name=f"{subcommand_prefix}create",
        help=f"""Create new preset in being_edited state.

        This command creates a new preset in being_edited state. If
        `{SOURCE}` option is given the new one will be a copy of the pointed source preset.
        {ATOMIC_ACTIONS_INFO}

        Examples:
        *** better_foo {SOURCE} good_old_foo
        --- create a new preset named `better_foo` as a copy of `good_old_foo`""",
        timeout_ms=timeout_ms,
    )
    @add_preset_source_argument()
    @click.argument(
        "name", default="",  # help="Name of the preset to create. No patterns allowed."
    )
    def _create(client: Client, name: str, source: str) -> None:
        query_in(client, create(f"{topic_prefix}.create", name, source))

    @group.command_with_client(
        name=f"{subcommand_prefix}delete",
        help=f"""Delete preset currently being_edited',

        This command removes existing preset. Before removal preset must be in
        being_edited state (see option `{MAKE_EDITED}`). Removed preset cannot be restored ---
        use backup instead.""",
        epilog=f"""\b
        Examples:
        *** good_old_foo {MAKE_EDITED} --- first make preset good_old_foo
        editable (this step may fail, which will prevent removal), then remove it
        *** better_foo --- remove `better_foo` -- this will fail if it is not being_edited
        *** '*foo' --- remove preset which name ends with `foo` -- this will fail if there is no
        such preset being edited already""",
        timeout_ms=timeout_ms,
    )
    @add_preset_being_edited_name_argument(named=False)
    @add_make_edited_name_argument(subcommand_prefix)
    def _delete(client: Client, name: str, make_edited: bool) -> None:
        chain_actions(
            client,
            make_edited_func(topic_prefix, name, make_edited),
            simple(f"{topic_prefix}.delete", name),
        )

    @group.command_with_client(
        name=f"{subcommand_prefix}edit",
        help=f"""Mark saved preset as being_edited (allows to change its contents, but prevents selecting it as current one).

        This command can be applied on saved preset to make it editable.
        Editable presets cannot be accidentally selected, and saved presets cannot be
        accidentally edited or removed. Because of this allowing to edit selected preset
        makes no sense --- the whole idea is to prevent potentially incomplete preset from
        being selected. To modify selected preset you need to make a copy of it (see
        command `preset create -s`), then make changes, then save and
        select the copy. {ATOMIC_ACTIONS_INFO} Note that after starting the edition of the preset
        following editions are not atomic and if more than one actor performs them at the
        same time result might be unexpected --- it is user responsibilty to ensure that
        second actor will not start modifying preset already in being_edited state before
        first actor finished his editions!

        Examples:
        *** good_old_foo --- make preset good_old_foo editable""",
        timeout_ms=timeout_ms,
    )
    @add_preset_name_argument(
        named=False,
        help="""Name of saved preset. Shell glob patterns may be used but pattern must match exactly one preset name.
        If ommited defults to '*'""",
    )
    def _edit(client: Client, name: str) -> None:
        query_in(client, make_edited_func(f"{topic_prefix}", name, make_edited=True))

    @group.command_with_client(
        name=f"{subcommand_prefix}save",
        help=f"""Mark preset being_edited as saved.

        This command can be applied on being_edited preset to make it saved.
        Optionally a new name can given given to the preset during this operation.
        Editable presets cannot be accidentally selected, and saved presets cannot be
        accidentally edited or removed. {ATOMIC_ACTIONS_INFO}

        Examples:
        *** -d new_name --- assuming only one preset is being edited currently save it
        under name `new_name`
        *** 'my_*' --- save preset which name starts with `my_` (there must be exactly one such
        preset in being edited state, but there may be other being edited presets
        whose names start differently
        *** --- save the only being edited preset""",
        timeout_ms=timeout_ms,
    )
    @add_preset_being_edited_name_argument(named=False)
    @click.option(
        "-d",
        "--destination",
        help="""Optional name under which currently being_edited preset shall be saved,
        if not given current name of preset being_edited will be used""",
    )
    def _save(client: Client, name: str, destination: str) -> None:
        query_in(client, save(f"{topic_prefix}.save", name, destination))

    @group.command_with_client(
        name=f"{subcommand_prefix}select",
        help=f"""Select saved preset for use.

        This command can be applied on saved preset to apply its contents as
        current configuration of EG. Any previously selected preset will cease to be selected
        anymore. {'' if affirm_handler_generator is None else AFFIRM_NOTE}
        Selected preset cannot be made editable. {ATOMIC_ACTIONS_INFO}

        Examples:
        *** location2_config --- select and apply configuration in preset `location2_config`""",
        timeout_ms=timeout_ms,
    )
    # it is always not None
    # if affirm_handler_generator is not None:
    #     add_unconditionally(spt)
    @unconditionally_option_decorator
    @add_preset_name_argument(
        named=False,
        help="Optional shell glob pattern to limit names of presets to print (defaults to '*')",
    )
    def _select(client: Client, name: str, unconditionally: bool) -> None:
        query_in(
            client,
            simple(
                f"{topic_prefix}.select",
                name,
                unconditionally=unconditionally,
                affirm_handler_generator=affirm_handler_generator,
            ),
        )

    @group.command_with_client(f"{subcommand_prefix}list", timeout_ms=timeout_ms)
    @add_preset_name_argument(
        named=False,
        help="Optional shell glob pattern to limit names returned (defaults to '*')",
    )
    def _list(client: Client, name: str) -> None:
        """List existing presets (both saved and being_edited).

        Optionally list can be limited to presets matching glob pattern. Useful
        before executing commands to which concrete name is needed, or to check
        if preset is saved or being edited.

        Examples:
        *** --- list all presets
        *** 'a*x' --- list presets which names start with an 'a' and end with an 'x'
        """
        query_in(client, simple(f"{topic_prefix}.list", name))

    @group.command_with_client(
        name=f"{subcommand_prefix}print",
        help=f"""Print contents of preset(s) (whole or just a part)

        For presets with multipart structure, if only one part is interesting
        output may be limited by giving the {PART} argument.

        Examples:
        *** {PART} foo/bar/baz --- print contents of part `foo/bar/baz`
        in all presets *** foobar --- print contents of whole `foobar` preset""",
        timeout_ms=timeout_ms,
    )
    @add_preset_name_argument(
        named=False,
        help="Optional shell glob pattern to limit names of presets to print (defaults to '*')",
    )
    @add_preset_part_argument(
        help="Part (at least container of rules) of preset which shall be printed. Whole preset will printed if not given."
    )
    def _print(client: Client, name: str, part: str) -> None:
        query_in(client, print_all(f"{topic_prefix}.print", name, part))


def add_print_editable_command(group: CustomGroup) -> None:
    @group.command_with_client(
        name="print",
        help=f"""
        Print contents of preset being edited (whole or just a part).

        Similar to `preset_print` but intended to print only
        single currently edited preset. If there is only one preset being edited name of the
        preset can be skipped. If there is more than one preset being edited, name of the preset
        must be given and it shall match only one of them. {PART} argument allows to limit
        output, e.g. in case of huge preset.

        Examples:
        *** --- print contents of the one and only currently being edited preset"""
    )
    @add_preset_being_edited_name_argument()
    @add_preset_part_argument(help="""Part (at least container of rules) of preset which shall be printed.
                            Whole preset will printed if not given.""")
    def print_editable_command(client: Client, name: str, part: str) -> None:
        query_in(client, print_editable("net.routes.preset.print", name, part))


##############################################################
# Internal helper, but no harm if used externally
# Note that client is actually not optional, optionality was added only
# for ease of using module level _client in add_preset_subcommands() above
##############################################################

# TopicMessage = t_Tuple[str, Any]
# TopicMessageQuery = t_Tuple[str, Any, Optional[QueryHandlerCallable]]
# TopicMessageQueryAffirm = t_Tuple[str, Any, Optional[QueryHandlerCallable], Optional[AffirmHandlerGenerator]]
# QueryArgs = Union[TopicMessage, TopicMessageQuery, TopicMessageQueryAffirm]
# TODO would be nice if we could use above Union instead of hard Tuple, but seems mypy is not ready yet :)
# insdead we have pack() function for now
QueryArgs = t_Tuple[
    str, Any, Optional[QueryHandlerCallable], Optional[AffirmHandlerGenerator]
]


def query_in(client: Client, query_args: QueryArgs) -> None:
    #        topic: str,
    #        message: Any,
    #        query_handler: Optional[QueryHandlerCallable],
    #        affirm_handler_generator: Optional[AffirmHandlerGenerator]) -> None:
    assert client is not None
    topic = query_args[0]
    message = query_args[1]
    if len(query_args) > 2 and query_args[2] is not None:
        query_handler = query_args[2]
    else:
        query_handler = exiting_print_message
    if len(query_args) > 3:
        affirm_handler_generator = query_args[3]
    else:
        affirm_handler_generator = None
    client.query(
        topic, message, query_handler, affirm_handler_generator=affirm_handler_generator
    )


def chain_actions(client: Client, *actions: QueryArgs) -> None:
    """Each action consists of:
    * topic ---   its length shall be 0 if given action shall be skipped
                  (last action cannot be skipped, but with adding a bit
                  more code in this function this limitation can be removed),
    * message --- it has to be precalculated, adding ability to decide
                  about message contents based on responses from earlier
                  queries would make this function quite a bit more
                  complicated. As it was not needed yet, so it was avoided
    * handler --- which can e.g. raise exception if chain of actions shall
                  not be continued. If None it will be unchanged for for
                  last action and print_message_exit_if_not_ok for any
                  earlier actions
    * affirm_handler_generator --- if given step may require affirmation
    """

    # Detect degenerated cases:
    assert len(actions) > 0  # we expect at least one action
    assert len(actions[-1][0]) > 0  # last action cannot be skipped for now

    # First set the tail handler
    handlers = [actions[-1][2] if len(actions[-1]) > 2 else None]

    # Then prepare tail action args
    later_action = actions[-1]

    # If we have more than on action to chain, we need to generate intermediate handlers
    if len(actions) > 1:
        # We need generator to evaluate current value of args in loop, otherwise
        # handler would bind to loop scope variables evalueted long after loop
        # was fnished (so using post loop value in each and every handler)
        def generate_next_handler(earlier_action: QueryArgs,
                                  later_action: QueryArgs,
                                  next_handler: Optional[QueryHandlerCallable]) -> QueryHandlerCallable:
            current_handler = earlier_action[2]
            if current_handler is None:
                current_handler = print_message_exit_if_not_ok

            def handler(message: Union[bytes, str]) -> Optional[bool]:
                assert current_handler is not None
                retval = current_handler(message)
                if retval is not None:
                    return retval
                query_in(client, (later_action[0], later_action[1], next_handler, later_action[3]))
                return None

            return handler

        for earlier_action in reversed(actions[:-1]):
            if len(earlier_action[0]):
                handlers.append(generate_next_handler(earlier_action, later_action, handlers[-1]))
                later_action = earlier_action
            else:
                assert earlier_action[1] is None
                assert earlier_action[2] is None
                assert earlier_action[3] is None

    # And execute the initial query with the last generated handler (which will
    # call any previously generated handlers if we have more than one action)
    query_in(client, (later_action[0], later_action[1], handlers[-1], later_action[3]))


def pack(
    topic: str,
    message: Any,
    query_handler: Optional[QueryHandlerCallable] = None,
    affirm_handler_generator: Optional[AffirmHandlerGenerator] = None,
) -> QueryArgs:
    return (topic, message, query_handler, affirm_handler_generator)


def simple(
    topic: str,
    name: str,
    unconditionally: bool = False,
    affirm_handler_generator: Optional[AffirmHandlerGenerator] = None,
    query_handler: Optional[QueryHandlerCallable] = None,
    shall_be_skipped: bool = False,
) -> QueryArgs:
    #      shall_be_skipped: bool = False) -> Tuple[str, Any, QueryHandlerCallable, AffirmHandlerGenerator]:
    if shall_be_skipped:
        return ("", None, None, None)
    message: dict[str, Union[str, bool]] = {"name": name}
    if affirm_handler_generator is not None:
        message["ask_for_affirmation"] = not unconditionally
    return (topic, message, query_handler, affirm_handler_generator)


def make_edited_func(
    topic_prefix: str, name: str, make_edited: bool, unconditionally: bool = False
) -> QueryArgs:
    return simple(
        f"{topic_prefix}.edit",
        name,
        unconditionally=unconditionally,
        shall_be_skipped=not make_edited,
    )


def create(topic: str, name: str, source: str) -> QueryArgs:
    message = {"name": name, "source": source}
    return (topic, message, None, None)


def save(topic: str, name: str, destination: str) -> QueryArgs:
    message = {"name": name, "destination": destination}
    return (topic, message, None, None)


def print_all(
    topic: str,
    name: str,
    part: str,
    query_handler: Optional[QueryHandlerCallable] = exiting_print_sorted_message,
) -> QueryArgs:
    message = {"name": name, "editable_only": False, "part": part}
    return (topic, message, query_handler, None)


def print_editable(
    topic: str,
    name: str,
    part: str,
    query_handler: Optional[QueryHandlerCallable] = exiting_print_sorted_message,
) -> QueryArgs:
    message = {"name": name, "editable_only": True, "part": part}
    return (topic, message, query_handler, None)
