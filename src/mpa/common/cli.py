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
from __future__ import annotations

import functools
import re
from pathlib import Path
from typing import Any, Callable, Optional, overload, TypeVar, Union

import click

from .common import FileExtension
from mpa.communication.client import Client
from mpa.communication.common import cli_main_loop, get_lan_interfaces

# special type taken from click
FC = TypeVar("FC", bound=Union[Callable[..., Any], click.Command])


def extract_examples(ctx: click.Context) -> list[str]:
    """Extract examples from command help text."""
    if ctx.command.help is None:
        return []

    parts = re.split(r"[Ee]xamples:", ctx.command.help, maxsplit=1)
    if len(parts) != 2:
        # no examples found
        return []

    new_help, examples = parts
    ctx.command.help = new_help.strip()
    return examples.strip().splitlines()


def format_examples(ctx: click.Context, formatter: click.HelpFormatter, examples: list[str]) -> None:
    """Format a list of example strings with command path and two-space indentation."""
    if not examples:
        return

    formatted_examples = ["\b"]
    prefix = f"  {ctx.command_path}"
    for example in examples:
        if "***" in example:
            example = example.lstrip().replace("***", prefix)
        else:
            example = f"    {example.strip()}"

        formatted_examples.append(example)

    if formatted_examples:
        formatter.write_paragraph()
        formatter.write_text("Examples:")
        formatter.write_text("\n".join(formatted_examples))


class CommandWithExamples(click.Command):
    def __init__(self, *args: Any, dynamic_completion: bool = False, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.dynamic_completion = dynamic_completion
        self.examples: list[str] = []

    def format_help_text(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        self.examples = extract_examples(ctx)
        super().format_help_text(ctx, formatter)

    def format_epilog(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        super().format_epilog(ctx, formatter)
        format_examples(ctx, formatter, self.examples)


class CustomGroup(click.Group):
    """Pass a Client object as a first argument when using command_with_client() method.

    Extract examples from command help and write them in epilog.

    Use both '-h' and '--help' as help option names instead of default '--help'."""
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        context_settings = kwargs.get("context_settings", {})
        context_settings["help_option_names"] = ["-h", "--help"]
        kwargs["context_settings"] = context_settings
        super().__init__(*args, **kwargs)
        self.group_class = CustomGroup
        self.command_class = CommandWithExamples
        self.examples: list[str] = []
        self.help_priorities: dict[str, str] = {}

    def get_help(self, ctx: click.Context) -> str:
        self.list_commands = self.list_commands_for_help  # type: ignore
        try:
            return super().get_help(ctx)
        finally:
            self.list_commands = super().list_commands  # type: ignore

    def list_commands_for_help(self, ctx: click.Context) -> list[str]:
        """reorder the list of commands when listing the help"""
        commands = super().list_commands(ctx)
        return (c[1] for c in sorted(  # type: ignore
            (self.help_priorities.get(command, command), command)
            for command in commands))

    def format_help_text(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        self.examples = extract_examples(ctx)
        super().format_help_text(ctx, formatter)

    def format_epilog(self, ctx: click.Context, formatter: click.HelpFormatter) -> None:
        super().format_epilog(ctx, formatter)
        format_examples(ctx, formatter, self.examples)

    # Override the command method to automatically inject client
    @overload
    def command_with_client(self, __func: Callable[..., Any]) -> click.Command:
        ...

    @overload
    def command_with_client(
        self,
        name: Optional[str] = None,
        *,
        timeout_ms: Optional[int] = 10_000,
        help_priority: Optional[str] = None,
        **attrs: Any
    ) -> Callable[[Callable[..., Any]], click.Command]:
        ...

    def command_with_client(
        self,
        name: Union[Optional[str], Callable[..., Any]] = None,
        *,
        timeout_ms: Optional[int] = 10_000,
        help_priority: Optional[str] = None,
        **attrs: Any
    ) -> Union[click.Command, Callable[[Callable[..., Any]], click.Command]]:
        """Automatically pass client with timeout to all commands."""

        help_priorities = self.help_priorities

        # Handle the case where command is used as @command (without parentheses)
        if callable(name):
            func = name
            cmd = super().command(func, **attrs)
            if help_priority:
                help_priorities[cmd.name] = help_priority + cmd.name
            return self._wrap_command_with_client(cmd, timeout_ms)

        # Handle the case where command is used as @command() or @command(name)
        def decorator(f: Callable[..., Any]) -> click.Command:
            cmd = super(CustomGroup, self).command(name, **attrs)(f)
            if help_priority:
                assert cmd.name is not None
                self.help_priorities[cmd.name] = help_priority + cmd.name
            return self._wrap_command_with_client(cmd, timeout_ms)

        return decorator

    def _wrap_command_with_client(self, cmd: click.Command, timeout_ms: Optional[int]) -> click.Command:
        """Helper method to wrap command callback with client injection."""
        original_callback = cmd.callback
        assert original_callback is not None

        @click.pass_obj
        def wrapper(obj: Any, /, *cmd_args: Any, **cmd_kwargs: Any) -> None:
            client = Client(**obj)
            original_callback(client, *cmd_args, **cmd_kwargs)
            cli_main_loop(client, timeout_ms=timeout_ms)

        cmd.callback = wrapper
        return cmd

    # Override the group method to return CustomGroup type
    @overload
    def group(self, __func: Callable[..., Any]) -> CustomGroup:
        ...

    @overload
    def group(self, name: Optional[str] = None, **attrs: Any) -> Callable[[Callable[..., Any]], CustomGroup]:
        ...

    def group(
        self,
        name: Union[Optional[str], Callable[..., Any]] = None,
        help_priority: Optional[str] = None,
        **attrs: Any
    ) -> Union[CustomGroup, Callable[[Callable[..., Any]], CustomGroup]]:
        """Create a new group with the same type as this group."""
        attrs.setdefault("cls", self.__class__)

        # Handle the case where group is used as @group (without parentheses)
        if callable(name):
            func = name
            group_instance = super().group(func)
            assert isinstance(group_instance, CustomGroup)
            if help_priority:
                assert group_instance.name is not None
                self.help_priorities[group_instance.name] = help_priority + group_instance.name
            return group_instance

        # Handle the case where group is used as @group() or @group(name)
        def decorator(f: Callable[..., Any]) -> CustomGroup:
            group_instance = super(CustomGroup, self).group(name, **attrs)(f)
            assert isinstance(group_instance, CustomGroup)
            if help_priority:
                assert group_instance.name is not None
                self.help_priorities[group_instance.name] = help_priority + group_instance.name
            return group_instance

        return decorator


def custom_group(command: FC) -> CustomGroup:
    """Set up CustomGroup with additional click.options (--push/--sub/--req/--group/--dir/--public_id)
    used for Client creation."""
    @click.group(cls=CustomGroup)
    @click.pass_context
    @click.option(
        "--push",
        "client_push",
        hidden=True,
        help="PUSH zmq socket (will default to ipc:///dir/group.push if not given, see --dir and --group)",
    )
    @click.option(
        "--sub",
        "client_sub",
        hidden=True,
        help="SUB zmq socket (will default to ipc:///dir/group.sub if not given, see --dir and --group)",
    )
    @click.option(
        "--req",
        "client_req",
        hidden=True,
        help="REQ zmq socket (will default to ipc:///dir/group.req if not given, see --dir and --group)",
    )
    @click.option(
        "--group",
        "client_group",
        help="Group which shall be used for ipc sockets (primary user group will be used if not given)",
    )
    @click.option(
        "--dir",
        "client_dir",
        hidden=True,
        help="""Directory in which ipc sockets are present (defaults to /run/mgmtd).
            Note: sockets specified with --push, --sub or --req are not affected by this value""",
    )
    @click.option(
        "--public_id",
        "client_public_id",
        hidden=True,
        help="Preferred public id of client",
    )
    @functools.wraps(command)
    def inner(
        ctx: click.Context,
        client_push: Optional[str],
        client_sub: Optional[str],
        client_req: Optional[str],
        client_group: Optional[str],
        client_dir: Optional[str],
        client_public_id: Optional[str],
    ) -> None:
        ctx.obj = {
            "push": client_push,
            "sub": client_sub,
            "req": client_req,
            "group": client_group,
            "directory": client_dir,
            "public_id": client_public_id,
        }

    return inner


def validate_file_extension(
    extensions: Union[FileExtension, list[FileExtension]]
) -> Callable[[click.Context, click.Parameter, Optional[str]], Optional[Path]]:
    """Create a click callback to validate file extensions."""
    if isinstance(extensions, FileExtension):
        extension_strings = [extensions.value]
    else:
        extension_strings = [extension.value for extension in extensions]

    def callback(ctx: click.Context, param: click.Parameter, value: Optional[str]) -> Optional[Path]:
        if value is None:
            return value

        file_path = Path(value)
        if file_path.suffix.lower() not in extension_strings:
            ext_list = ', '.join(extension_strings)
            raise click.BadParameter(
                f"File must have one of the following extensions: {ext_list}. "
                f"Got: {file_path.suffix or 'no extension'}"
            )

        return file_path

    return callback


def readable_file_option_decorator(
    default_filename: Optional[str] = None,
    allowed_extensions: Optional[Union[FileExtension, list[FileExtension]]] = None,
    required: bool = True,
) -> Callable[[FC], FC]:
    callback = None
    help_text = "Path of the configuration file."

    if allowed_extensions is not None:
        callback = validate_file_extension(allowed_extensions)

        if isinstance(allowed_extensions, FileExtension):
            ext_text = allowed_extensions.value
        else:
            ext_text = ", ".join(ext.value for ext in allowed_extensions)

        help_text += f" Allowed extensions: {ext_text}."

    return click.option(
        "-f",
        "--filename",
        required=default_filename is None and required,
        default=default_filename,
        type=click.Path(file_okay=True, readable=True, path_type=Path),
        callback=callback,
        help=help_text,
    )


def writable_file_option_decorator(filename: str) -> Callable[[FC], FC]:
    return click.option(
        "-f",
        "--filename",
        default=filename,
        show_default=True,
        type=click.Path(writable=True, path_type=Path),
        help="Path of the output file.",
    )


interface_number_argument_decorator = click.argument(
    "interface",
    type=click.IntRange(min=1),
)

interface_name_option_decorator = click.option(
    "-n", "--name",
    required=True,
    type=click.Choice(list(get_lan_interfaces())),
    help="Network interface name.",
)

unconditionally_option_decorator = click.option(
    "--unconditionally",
    is_flag=True,
    help=""""Prevent connectivity checking after executing this command (without this option
        user may be asked to confirm that after command execution he has not lost
        connection to the device, without such confirmation command would be rolled back.)"""
)

config_option_decorator = click.option(
    "-c",
    "--config",
    help="""Name of config to be affected in currently edited preset eg `lan1`, `lan2`.
    Configs are visible after executing preset_print within edited preset.', required=True).
    """
)


def add_preset_name_argument(help: str, named: bool) -> Callable[[FC], FC]:
    if named:
        return click.option("-n", "--name", help=help)
    else:
        return click.argument("name", default=None, required=False)


def add_preset_being_edited_name_argument(named: bool = True) -> Callable[[FC], FC]:
    # We lie about defaulting to '*' because we default to nothing which in most
    # cases is same as if user gave '*', but in case of error reporting there is
    # difference between '*' and not giving value at all (i.e. error message for
    # nothing explicitly says that user did not provide any value for argument).
    help_message = """Name of the preset being_edited which will be affected.
                    Shell glob patterns may be used but shall match exactly one preset.
                    If skipped this param defaults to '*' and because normally only one
                    preset is being edited, so this argument is usally skipped."""
    return add_preset_name_argument(help=help_message, named=named)


def add_make_edited_name_argument(preset_edit_prefix: str = "") -> Callable[[FC], FC]:
    return click.option(
        "-E",
        "--make-edited",
        "make_edited",
        is_flag=True,
        help=f"""Mark saved preset as being edited one before performing other actions, giving this option is
        the same as if separate command `{preset_edit_prefix}edit` was executed by the user just
        before this command --- it may fail if preset is already being edited, or if another user tried
        to make preset edited at the same time""",
    )


def add_preset_source_argument(required: bool = False) -> Callable[[FC], FC]:
    return click.option(
        "-s",
        "--source",
        required=required,
        help="""Name of preset which shall be source of data for preset being_edited.
        Shell glob patterns may be used, but exactly one name must match pattern.""",
    )


def add_preset_part_argument(
    help: str,
    required: bool = False,
) -> Callable[[FC], FC]:
    return click.option("-p", "--part", required=required, help=help)


class PinType(click.ParamType):
    name = "pin"

    def convert(self, value: str, param: Optional[click.Parameter], ctx: Optional[click.Context]) -> str:
        if value.isdigit() and 4 <= len(value) <= 8:
            return value

        self.fail(f"{value!r} is not a valid PIN, it must be between 4 and 8 characters (digits only)", param, ctx)
