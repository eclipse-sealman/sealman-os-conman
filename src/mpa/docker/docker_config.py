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
import base64
from pathlib import Path

# Third party imports
import click

# Local imports
from mpa.common.common import FileExtension
from mpa.common.cli import (
    custom_group,
    readable_file_option_decorator,
    writable_file_option_decorator,
)
from mpa.communication import topics
from mpa.communication.client import Client
from mpa.communication.common import (
    exiting_print_message,
    rashly,
    store_yaml_config,
    trivial_get_config,
    trivial_set_config,
)


@custom_group
def cli() -> None:
    """Manage docker and compose files configuration."""


@cli.command_with_client()
def apply(client: Client) -> None:
    """Restart docker service to apply changes docker DNS configuration.

    Some of the CLI commands allow to change the docker config in small increments.
    Restarting whole docker service after each of such small increments would take
    long time and could unnecesarily disrupt continuity of of work of the containers.
    Therefore documentation of such CLI commands notes, that you need to additionally
    trigger 'apply' command to restart docker service and apply all of your small
    incremental changes at convenient time.
    """
    client.query(topics.docker.restart, handler=exiting_print_message)


@cli.group()
def compose() -> None:
    """Manage docker compose files to be started automatically.

    Containers defined by docker compose files can be automatically started
    after each reboot of Edge Gateway. Admin users can provide multiple compose files, which
    will be stored in centrally managed location and started by special user named 'composed'.

    Examples:
    *** load -f ./compose.yml -n pump_regulator --- load contens of compose.yml in current directory
    under the name 'pump_regulator'
    *** delete -n pump_regulator --- delete compose file added by above example
    *** get-config --- get all compose files configured
    *** status --- show yaml of currently running containers
    """


@compose.command_with_client("recreate")
@click.option("-n", "--name", default="*", show_default=True, help="Pattern for names to be recreated.")
def compose_recreate(client: Client, name: str) -> None:
    """Force recreation of seleceted or all composed containers.

    Example reason for recreation can be long lived container which holds some internal
    invalid state and is not working properly anymore. Another common case is need to
    change configuration values (e.g. proxy setting) embeded into container during its
    creation time --- their subsequent change outside container will not be reflected
    unless recreation is forced.
    """
    client.query(topics.docker.compose.recreate, {"name": name}, exiting_print_message)


@compose.command_with_client("get")
@click.option("-n", "--name", required=True, help="Name of the compose file to get.")
def compose_get(client: Client, name: str) -> None:
    """Get contents of single  docker-compose file."""
    client.query(topics.docker.compose.get, {"name": name}, handler=rashly(store_yaml_config(f"{name}.yaml", "compose_file")))


@compose.command_with_client("status")
@writable_file_option_decorator("compose-status.yaml")
def compose_status(client: Client, filename: Path) -> None:
    """Saves artificial compose of all currently running containers."""
    client.query(topics.docker.compose.status, handler=rashly(store_yaml_config(filename, "compose_file")))


@compose.command_with_client("load")
@click.option("-n", "--name", required=True, help="Name under which this compose file shall be stored.")
@readable_file_option_decorator(allowed_extensions=[FileExtension.YML, FileExtension.YAML])
def compose_load(client: Client, name: str, filename: Path) -> None:
    """Load docker-compose config file into system.

    Contents of docker compose yaml config will be loaded under name provided by
    --name option, and respective containers will be started immediately, and then after
    each reboot.
    """
    click.echo(
        f"The composition for {name} has started. If it takes more than 15 seconds it will continue in the background."
    )
    data = {"name": name, "compose_file": filename.read_text()}
    client.query(topics.docker.compose.add, data, exiting_print_message)


@compose.command_with_client("delete")
@click.option("-n", "--name", required=True, help="Name of compose file to be removed.")
def compose_delete(client: Client, name: str) -> None:
    """Remove docker-compose config from system.

    Respective containers will be stopped and compose file removed.
    """
    client.query(topics.docker.compose.delete, {"name": name}, exiting_print_message)


@compose.command_with_client("set-config")
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
def compose_set_config(client: Client, filename: Path) -> None:
    """Replaces current compose files with new set.

    Restore docker compose files from file. This is a permanent
    change (and will remove previously present compose files (if any))
    If containers are not running they will be started using new
    configuration. If you want to restart those which are running
    use `recreate` command.
    """
    trivial_set_config(client, topic=topics.docker.compose.set_config, file_name=filename)


@compose.command_with_client("get-config")
@writable_file_option_decorator("compose_config.json")
def compose_get_config(client: Client, filename: Path) -> None:
    """Get docker compose configuration and store it in a file.

    All currently present docker compose files will be stored in
    to file named `compose_config.json`.
    """
    trivial_get_config(client, topic=topics.docker.compose.get_config, file_name=filename)


@cli.group()
def dns() -> None:
    """Add and remove DNS servers from your docker configuration.

    Examples:
    *** add <IP_ADDR> --- add <IP_ADDR> as DNS for docker
    *** delete <IP_ADDR> --- remove <IP_ADDR> from list of DNS's of docker
    *** set-config -f <FILENAME> --- replace current DNS list with one from file
    *** get-config  --- store current configuration in file ./dockerdns_config.json
    *** show --- display current nameservers from docker configuration
    """


@dns.command_with_client("add")
@click.argument("ip_address")
def dns_add(client: Client, ip_address: str) -> None:
    """Add DNS to current configuration (this command requires executing 'apply' afterwards)."""
    client.query(topics.docker.dns.add, {"ip": ip_address}, exiting_print_message)


@dns.command_with_client("delete")
@click.argument("ip_address")
def dns_delete(client: Client, ip_address: str) -> None:
    """Delete DNS from current configuration (this command requires executing 'apply' afterwards)."""
    client.query(topics.docker.dns.delete, {"ip": ip_address}, exiting_print_message)


@dns.command_with_client("set-config")
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
def dns_set_config(client: Client, filename: Path) -> None:
    """Replace current docker DNS configuration."""
    trivial_set_config(client, topic=topics.docker.dns.set_config, file_name=filename)


@dns.command_with_client("get-config")
@writable_file_option_decorator("dockerdns_config.json")
def dns_get_config(client: Client, filename: Path) -> None:
    """Store current docker DNS configuration in file dockerdns_config.json."""
    trivial_get_config(client, topic=topics.docker.dns.get_config, file_name=filename)


@dns.command_with_client("show")
def dns_show(client: Client) -> None:
    """Show current docker DNS configuration."""
    client.query(topics.docker.dns.get_config, handler=exiting_print_message)


@cli.group()
def auth() -> None:
    """Authenticate to private repositories.

    Add or remove authentication to different repositories.
    """


@auth.command_with_client("add")
@click.option("-u", "--user", required=True, help="Name of the user.")
@click.option("-p", "--password", required=True, help="Password of the user.")
@click.option("-U", "--url", default="https://index.docker.io/v1/", show_default=True, help="URL to the private repository.")
def auth_add(client: Client, user: str, password: str, url: str) -> None:
    """Authenticate to private repositories.

    Examples:
    *** -u <user> -p <password> -U <url> --- authenticate to <url> with <user> and <passowrd>
    """
    data = {"auths": {url: {"auth": base64.b64encode(f"{user}:{password}".encode()).decode()}}}
    client.query(topics.docker.compose.auth_add, data, exiting_print_message)


@auth.command_with_client("remove")
@click.option("-U", "--url", required=True, help="URL to the private repository to remove.")
def auth_remove(client: Client, url: str) -> None:
    """Remove URL to private repositories.

    Examples:
    *** -U <url> --- remove authentication to <url>
    """
    client.query(topics.docker.compose.auth_remove, {"url": url}, exiting_print_message)


@cli.group()
def params() -> None:
    """Configuration of docker daemon parameters.

    Examples:
    *** set --mtu <MTU> --- sets given MTU for docker network interface (null for removal)
    *** set --debug --- enable docker debug mode
    """


@params.command_with_client("set")
@click.option("-M", "--mtu", type=int, help="Set MTU on docker network interface.")
@click.option("-D", "--debug", is_flag=True, help="Enable docker debug.")
def params_set(client: Client, mtu: int | None, debug: bool) -> None:
    """Configure docker daemon parameters."""
    message = {}
    if mtu:
        message["dockermtu"] = mtu
    if debug:
        message["dockerdebug"] = debug

    client.query(topics.docker.params.set, {"params": message}, exiting_print_message)


@params.command_with_client("show")
def params_show(client: Client) -> None:
    """Show all configured docker daemon parameters."""
    client.query(topics.docker.params.get_config, handler=exiting_print_message)


@params.command_with_client("set-config")
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
def params_set_config(client: Client, filename: Path) -> None:
    """Set config for docker daemon.json."""
    trivial_set_config(client, topic=topics.docker.params.set_config, file_name=filename)


#################################################################################
#                               DEPRECATED COMMANDS                             #
#################################################################################


@compose.command_with_client("del", hidden=True, deprecated="Use `docker-config compose delete`.")
@click.option("-n", "--name", required=True, help="Name of compose file to be removed.")
def compose_delete_deprecated(client: Client, name: str) -> None:
    client.query(topics.docker.compose.delete, {"name": name}, exiting_print_message)


@compose.command_with_client("set_config", hidden=True, deprecated="Use `docker-config compose set-config`.")
@readable_file_option_decorator("compose_config.json", allowed_extensions=FileExtension.JSON)
def compose_set_config_deprecated(client: Client, filename: Path) -> None:
    trivial_set_config(client, topic=topics.docker.compose.set_config, file_name=filename)


@compose.command_with_client("get_config", hidden=True, deprecated="Use `docker-config compose get-config`.")
@writable_file_option_decorator("compose_config.json")
def compose_get_config_deprecated(client: Client, filename: Path) -> None:
    trivial_get_config(client, topic=topics.docker.compose.get_config, file_name=filename)


@dns.command_with_client("del", hidden=True, deprecated="Use `docker-config dns delete`.")
@click.argument("ip_address")
def dns_delete_deprecated(client: Client, ip_address: str) -> None:
    client.query(topics.docker.dns.delete, {"ip": ip_address}, exiting_print_message)


@dns.command_with_client("set_config", hidden=True, deprecated="Use `docker-config dns set-config`.")
@readable_file_option_decorator("dockerdns_config.json", allowed_extensions=FileExtension.JSON)
def dns_set_config_deprecated(client: Client, filename: Path) -> None:
    trivial_set_config(client, topic=topics.docker.dns.set_config, file_name=filename)


@dns.command_with_client("get_config", hidden=True, deprecated="Use `docker-config compose get-config`.")
@writable_file_option_decorator("dockerdns_config.json")
def dns_get_config_deprecated(client: Client, filename: Path) -> None:
    trivial_get_config(client, topic=topics.docker.dns.get_config, file_name=filename)


@params.command_with_client("set_config", hidden=True, deprecated="Use `docker-config params set-config`.")
@readable_file_option_decorator("docker_params_config.json", allowed_extensions=FileExtension.JSON)
def params_set_config_deprecated(client: Client, filename: Path) -> None:
    trivial_set_config(client, topic=topics.docker.params.set_config, file_name=filename)
