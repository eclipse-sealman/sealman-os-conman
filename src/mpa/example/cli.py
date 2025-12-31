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
from pathlib import Path

import click

from mpa.common.cli import custom_group, readable_file_option_decorator, writable_file_option_decorator
from mpa.common.common import FileExtension
from mpa.communication.client import Client


# create one instance of cli() function and decorate it with @custom_group
# it will create a custom click.Group object which will pass the Client object
# as a first argument to subcommands
# this is the base/entrypoint of your CLI
@custom_group
def cli() -> None:
    """Here place the description of your CLI app."""


# to add commands to a group use @<group-name>.command() decorator
# in this case we add a 'foo' command to 'cli' group
# the name of the command is by default a function name with '_' changed to '-'
@cli.command()
# you can add options with @click.option() and arguments with @click.argument()
# they will end up as arguments to the decorated function
# the order does not matter but it's easier to read when the direction of parameters is up/down -> left/right
@click.option("-i", "--my-int", type=int, help="Help for my-int")
@click.argument("myfloat", type=float)
def foo(version: int | None, myfloat: float) -> None:
    """Global foo command"""


# to add a group of commands to a group use @<group-name>.group() decorator
# in this case we add a 'compose' group to 'cli' group
@cli.group()
def compose() -> None:
    """Group of compose commands - add commands with @compose.command() or groups with @compose.group()."""


# to add commands which need client use command_with_client() decorator
# to add commands to compose group just use @compose.command_with_client() decorator
# as mentioned above a default name is the name of the function  with '_' changed to '-' so it would be compose-show
# this is why the name is set to 'show'
@compose.command_with_client("show")
def compose_show(client: Client) -> None:
    """Show compose config"""


@compose.command_with_client("set-config")
# if you need to read a file you can use @readable_file_option_decorator and specify a default filename and
# allowed extensions
# you can specify a default filename - if not passed will be required to provide on the command line
# the filename will be passed to the function as filename argument
@readable_file_option_decorator("compose-config.json", allowed_extensions=FileExtension.JSON)
def compose_set_config(client: Client, filename: Path) -> None:
    """Set compose config"""


@compose.command_with_client("get-config")
# for writing to a file use @writable_file_option_decorator
# you can specify a default filename - if not passed will be required to provide on the command line
@writable_file_option_decorator("compose-config.json")
def compose_get_config(client: Client, filename: Path) -> None:
    """Get compose config"""


# we don't need this part of the code if in pyproject.toml
# we will use 'cli' as entrypoint
if __name__ == "__main__":
    cli()
