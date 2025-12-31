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
import getpass
import json
import pwd
import sys
import toml
from pathlib import Path
from typing import Any, Optional, MutableMapping, NoReturn, Union

# Third party imports
import click

# Local imports
import mpa.communication.topics as topics
from mpa.common.common import FileExtension, RESPONSE_FAILURE, RESPONSE_OK
from mpa.common.cli import (
    custom_group,
    readable_file_option_decorator,
    writable_file_option_decorator,
)
from mpa.common.logger import Logger
from mpa.communication.client import Client
from mpa.communication.common import (
    PLEASE_REPORT,
    exiting_print_message,
    trivial_get_config,
    trivial_set_config,
    rashly,
    store_json_config,
    store_toml_config,
    ask_for_affirmation,
    print_error_message,
    print_message_exit_if_not_ok,
    print_and_exit_on_falilure_report,
    get_timezones,
)
from mpa.communication.status_codes import (
    ADD_USER,
    ADMIN_GROUP,
    CERTIFICATE,
    DAY,
    DEVADMIN_GID,
    HOUR,
    MONTH,
    REMOVE_EVERYTHING,
    REMOVE_USER,
    SHOW_USERS,
    USER_GROUP,
    WEEK,
)
from mpa.device.common import (
    AuthorizedKeys,
    get_serial_devices,
    SERIAL_CONFIG_JSON,
    AZURE_CONFIG_JSON,
    CONFIG_KEY_EDGE_CA_CERT,
    CONFIG_KEY_EDGE_CA_PK,
    CONFIG_KEY_TRUST_BUNDLE_CERT,
    DEVICE_CONFIG_JSON,
    IOTEDGE_TOML,
    SSH_CONFIG_JSON,
    PROXY_CONFIG_JSON,
    SMART_EMS_JSON,
    DATETIME_CONFIG_JSON,
)
from mpa.parser import licence_parser


logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")


def get_config_impl(
    client: Client,
    handler: Optional[Client.QueryHandler.HandlerCallable],
    *,
    export_private_keys: bool,
) -> None:
    effective_export = export_private_keys and pwd.getpwnam(getpass.getuser()).pw_gid == DEVADMIN_GID
    endpoint = topics.dev.get_config_with_privates if effective_export else topics.dev.get_config
    client.query(endpoint, handler=handler)


def set_config_response_handler(client: Client, message: Union[bytes, str]) -> Optional[bool]:
    client.unregister_trivial_handler(f"{topics.dev.set_config}.rt", print_message_as_utf8)
    return exiting_print_message(message)


def updater_realtime_information(message: bytes) -> None:
    msg = message.decode().strip('"')
    click.echo(msg)


def print_message_as_utf8(message: bytes) -> None:
    click.echo(f"{message.decode('UTF-8')}")


def save_logs(data: bytes) -> NoReturn:
    print_and_exit_on_falilure_report(data)
    Path("logs.zip").write_bytes(data)
    click.echo("Requested logs saved to file logs.zip")
    sys.exit(0)


def print_list_with_indexes(data: Any) -> None:
    for user in data:
        click.echo(user)
        for i, item in enumerate(data[user]):
            click.echo(f"{i:<30}: {item:<40}")


def with_list_filter_applied(message: Union[bytes, str]) -> Union[bool, NoReturn]:
    return exiting_print_message(message, print_message=print_list_with_indexes)


def manage_certificate(
    client: Client, action: CERTIFICATE, filename: Path | None = None
) -> None:
    data = {"action": action.value}
    if action == CERTIFICATE.ADD:
        assert filename is not None
        cert_data = filename.read_text()
        data.update({"cert_content": cert_data})
    client.query(topics.smart_ems.manage_cert, data, exiting_print_message)


@custom_group
def cli() -> None:
    """Device configuration command line interface."""


@cli.group()
def serial() -> None:
    """Manage serial ports.

    Examples:
    *** console 1 at-boot on --- after next (and later) reboots console will be active
    on serial port 1, current state will not be affected
    *** console 0 both off --- turn off console on serial port 0 immediately
    and keep it that way after reboot
    *** console 1 now on --- turn on console at serial port 1 immediately,
    state after reboot will not be affected
    *** ; cat ./serial_config.json --- save serial config to file `serial_config.json`
    and print it to the screen
    """


@serial.command_with_client("console")
@click.argument("device", type=click.Choice(str(n) for n in range(0, len(get_serial_devices()))))
@click.argument("when", type=click.Choice(["now", "at-boot", "both"]))
@click.argument("mode", type=click.Choice(["on", "off"]))
def serial_console(client: Client, device: int, when: str, mode: str) -> None:
    """Enable/disable control of EG via serial port.

    By enabling/disabling the console output one can change if (and if yes on which)
    serial port system will print console output and allow the user to use it
    with help of serial terminal emulator. Configuration of console output will
    be exported to global configuration file. Those changes can be permanent or
    temporary (regarding state after reboot). Hint: Enable or disable SysRq magic key
    functionality in the local-console settings for syskeys management.
    """
    if not len(get_serial_devices()):
        click.echo("This device is misconfigured as not having any serial devices!!!")
        click.echo(f"This is unexpected, so {PLEASE_REPORT}")
        sys.exit(1)

    config = {}
    enabled = mode == "on"
    if when in ("at-boot", "both"):
        config["at_startup"] = enabled
    if when in ("now", "both"):
        config["currently"] = enabled
    request = {"serial": {f"serial{device}": {"console_output": config}}}
    client.query(topics.dev.serial.set_config, request, exiting_print_message)


@serial.command_with_client("get-config")
@writable_file_option_decorator(SERIAL_CONFIG_JSON)
def serial_get_config(client: Client, filename: Path) -> None:
    """Get configuration of serial devices and stores it in a file.

    Gets configuration of serial ports and store it in a file
    `serial_config.json` (e.g. for backup purposes).
    """
    trivial_get_config(client, topic=topics.dev.serial.get_config, file_name=filename)


@cli.command_with_client(timeout_ms=60_000)
def tpm_get(client: Client) -> None:
    """Get registration_id and endorsement key from tpm.

    This function will get the endorsement key and registration id from
    built-in TPM module and print it out. Those keys can be used to
    provide provisioning configuration for Azure IoT Edge daemon. Note
    that TPM module may respond slowly.
    """
    client.query(topics.dev.tpm.get_config, handler=exiting_print_message)


@cli.group()
def user_password_hash() -> None:
    """Get/set user password hashes from /etc/shadow file.

    This command will get the users and their password hashes
    from /etc/shadow file and print it out or set a new ones provided in a config file.
    """


@user_password_hash.command_with_client("show")
def user_password_hash_show(client: Client) -> None:
    """Get user password hashes from /etc/shadow file."""
    client.query(topics.dev.user.password_hash.get_config, handler=exiting_print_message)


@user_password_hash.command_with_client("set-config")
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
def user_password_hash_set_config(client: Client, filename: Path) -> None:
    """Set user password hashes to /etc/shadow file."""
    trivial_set_config(client, topic=topics.dev.user.password_hash.set_config, file_name=filename)


@cli.group(
    help=f"""Manage Azure IoT Edge daemon configuration.

    Examples:
    *** set-config -f {AZURE_CONFIG_JSON} --- restore config from file `{AZURE_CONFIG_JSON}`
    *** set-string 'Connection String' --- set connection string value to `Connection String`
    *** set-dps-x509 -i scope_id_from_iot_hub -p /path/to/cert_file -k /path/to/private_key_file
    *** set-certificate -t path/to/trust_bundle_cert -d path/to/device_ca_cert -p path/to/device_ca_private_key
    *** set-option -t  provisioning.attestation -e 'method = "tpm"' --- change attestation method to tpm
    *** set-option -t f.b.z -e 'l = ["a", "1"]' -d --- show partial TOML to add topic f.b.z with value
    being list of two strings
    *** set-option -t f.b.z -e 'l = ["a", 1]' -d --- show partial TOML to add topic f.b.z with value
    being list of a string and a number
    *** set-option -t f.b.z -e 'x = "a"' -e 'y = "b"' --- add topic f.b.z with two entries"""
)
def azure() -> None:
    ...


@azure.command_with_client("set-config", timeout_ms=60_000)
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
def azure_set_config(client: Client, filename: Path) -> None:
    """Set Azure configuration.

    Restore Azure IoT Edge daemon configuration from a file. This
    is a permanent change (and will overwrite existing Azure configuration.)
    """
    trivial_set_config(client, topic=topics.azure.set_config, file_name=filename)


@azure.command_with_client("get-config")
@writable_file_option_decorator(AZURE_CONFIG_JSON)
@click.option("--export-private-keys", is_flag=True)
def azure_get_config(client: Client, filename: Path, export_private_keys: bool) -> None:
    """Get Azure configuration and store it in a file.

    Azure configuration (provisioning data) will be saved
    to json file.
    """
    topic = (
        topics.azure.get_config_with_privates
        if export_private_keys
        else topics.azure.get_config
    )
    trivial_get_config(client, topic=topic, file_name=filename)


@azure.command_with_client("set-string", timeout_ms=60_000)
@click.argument("connection_string")
def azure_set_string(client: Client, connection_string: str) -> None:
    """Set Azure configuration to use provided connection string.

    Configures Azure IoT Edge daemon to use connection string as a manual
    provisioning. Remember to use quotation marks for provided string (see
    examples).
    """
    client.query(topics.azure.set_connection_string, connection_string, exiting_print_message)


@azure.command_with_client("set-dps-x509", timeout_ms=60_000)
@click.option("-k", "--identity-pk", type=click.Path(readable=True, path_type=Path), required=True)
@click.option("-p", "--identity-cert", type=click.Path(readable=True, path_type=Path), required=True)
@click.option("-i", "--id-scope", required=True)
def azure_set_dps_x509(client: Client, identity_pk: Path, identity_cert: Path, id_scope: str) -> None:
    """Set Azure configuration to use provided scope id, identity cert and identity pk.

    Configures Azure IoT Edge daemon to use X.509 certificates provisioning method.
    Three arguments are needed for configuration: id scope from IoT Hub, certificate file
    and private key file. You need read permisions for these files.
    This change is permament (performing configuration backup is up to the user).
    """
    config = {
        "scope_id": id_scope,
        "identity_cert": identity_cert.read_text(),
        "identity_pk": identity_pk.read_text(),
    }
    client.query(topics.azure.set_x509, config, exiting_print_message)


@azure.command_with_client("set-certificate", timeout_ms=30_000)
@click.option("-t", "--trust-bundle-cert", type=click.Path(readable=True, path_type=Path), required=True)
@click.option("-d", "--device-ca-cert", type=click.Path(readable=True, path_type=Path), required=True)
@click.option("-p", "--device-ca-pk", type=click.Path(readable=True, path_type=Path), required=True)
def azure_set_certificate(client: Client, trust_bundle_cert: Path, device_ca_cert: Path, device_ca_pk: Path) -> None:
    """Add certificates for Iot Edge.

    Configures Azure IoT Edge daemon to use provided certificates. Device
    private key and device CA certificate will be used by device to prove its
    own identity. Device certificate needs to be signed by trust bundle
    certificate specific for IoT Edge scenario --- public part of this
    trust bundle certificate is required on each device participating in
    the scenario too. Note that anyone knowing private key for device CA cert
    can impersonate this device in given IOT edge scenario.
    """
    data = {
        CONFIG_KEY_TRUST_BUNDLE_CERT: trust_bundle_cert.read_text(),
        CONFIG_KEY_EDGE_CA_CERT: device_ca_cert.read_text(),
        CONFIG_KEY_EDGE_CA_PK: device_ca_pk.read_text(),
    }
    client.query(topics.azure.set_cert, data, exiting_print_message)


@azure.group("configfile")
def azure_configfile() -> None:
    """Manage Azure IoT Edge config.

    Get full Azure IoT Edge configuration in toml file or upload
    preconfigured file. Notice: Exported file contains all settings, but
    some of them are ignored during import (see the details in
    description of import).
    """


@azure_configfile.command_with_client("export", timeout_ms=30_000)
@writable_file_option_decorator(IOTEDGE_TOML)
def azure_configfile_export(client: Client, filename: Path) -> None:
    """Get toml with Azure configuration.

    All entries which are set in Azure config file are present,
    so user can use for analysis or to test it outside of Edge Gateway.
    """
    client.query(topics.azure.get_config_file, handler=rashly(store_toml_config(filename, "azure_configfile")))


@azure_configfile.command_with_client("import", timeout_ms=60_000)
@readable_file_option_decorator(allowed_extensions=FileExtension.TOML)
def azure_configfile_import(client: Client, filename: Path) -> None:
    """Set Azure config based on given toml file.

    This method is designed to allow import of Azure config
    prepared on machine other than Edge Gateway, therefore
    parameters which are handled specially for Edge Gateway will
    be ignored. This affects especially hostname and
    certificates, but also some paths which shall not be
    modified. Response to this command will inform user if any
    entries were ignored. To see exactly what was ignored you can
    run export and compare your input file with reexported
    contents. If you want to export/import whole Azure
    configuration between Edge Gateways in simpler way use
    azure_get_config/azure_set_config commands instead of
    azure_configfile export/import.
    """
    client.query(topics.azure.set_config_file, {"azure_configfile": filename.read_text()}, exiting_print_message)


@azure.command_with_client("set-option")
@click.option("-t", "--topic", default="", help="Topic to setup.")
@click.option("-e", "--entry", required=True, multiple=True,
              help="""Entry being key-value pair to be set, note that TOML will NOT interpret its type.
                   You need to use proper quotation as in examples above.""")
@click.option("-d", "--dry_run", is_flag=True, help="Do not set option, but show partial TOML which would be added to config.")
def azure_set_option(client: Client, topic: str, entry: list[str], dry_run: bool) -> None:
    """Set Azure option.

    Change selected entry in IoT Edge TOML config. This option takes a string as a
    `topic` parameter which indicates topic-key in TOML tree to be changed. If
    selected topic-key does not exist system will create it in config file but
    if it does exist this command will change its value to the one specified in
    `entry` parameter. The `entry` parameter can be used more than once.
    When `topic` is not given entries are treated as global key-value pairs.
    This command does not verify if topic-key name and entry is reasonable and
    understood by Azure, but some options are protected and cannot be
    changed this way if it would not make sense in Edge Gateway (for example
    certificate paths are predefined for Edge Gateways, instead of changing those
    paths in Azure config you shall use azure_set_certificate command).
    """
    entries = "\n".join(entry)
    artificial_toml = f"[{topic}]\n{entries}" if topic else entries
    try:
        value = toml.loads(artificial_toml)
    except toml.decoder.TomlDecodeError as e:
        click.echo(
            f"Partial TOML:\n{artificial_toml}\n\n"
            f"There is an error on line {e.lineno} of partial TOML above.\n"
            f"TOML parser message is: '{e.msg}'\n"
            "If error above is not clear, please check also examples in help of this command.\n"
            "Most probably the value of --entry needs correction."
        )
        sys.exit(1)
    click.echo("Partial TOML to be added to config:")
    toml.dump(value, sys.stdout)
    if dry_run:
        click.echo("This is dry run, no changes were actually made")
        sys.exit(0)
    else:
        client.query(
            topics.azure.set_partial_config_file,
            {"azure_configfile": value},
            exiting_print_message,
        )


@azure.command_with_client("clean-keys", timeout_ms=30_000)
def azure_clean_keys(client: Client) -> None:
    """Delete empty aziot key files and restart IoT Edge.

    Removes zero-length files from `/var/lib/aziot/keyd/keys/` and restarts
    the IoT Edge services. Use this when IoT Edge gets stuck due to empty key files.
    """
    client.query(topics.azure.clean_keys, handler=exiting_print_message)


@cli.group()
def motd() -> None:
    """Manage message of the day (MotD)."""


@motd.command_with_client("set")
@readable_file_option_decorator(required=False)
@click.option("-t", "--text", help="Set new MotD from plain text.")
def motd_set(client: Client, filename: Path | None, text: str | None) -> None:
    """Set message-of-the-day.

    Set new welcome-banner (MotD), shown after login.
    """
    if (filename or text) is None:
        return

    if filename is not None:
        client.query(
            topics.dev.motd.set, {"motd": filename.read_text()}, exiting_print_message
        )
    else:
        client.query(topics.dev.motd.set, {"motd": text}, exiting_print_message)


@motd.command_with_client("get")
def motd_get(client: Client) -> None:
    """Get message-of-the-day.

    Get current welcome-banner (MotD), shown after login.
    """
    client.query(topics.dev.motd.get_config, handler=exiting_print_message)


@cli.group()
def issue() -> None:
    """Manage banner shown before login."""


@issue.command_with_client("set")
@readable_file_option_decorator(required=False)
@click.option("-t", "--text", help="Set new banner from plain text.")
def issue_set(client: Client, filename: Path | None, text: str | None) -> None:
    """Set new banner shown before login."""
    if filename is not None:
        client.query(topics.dev.issue.set, {"issue": filename.read_text()}, exiting_print_message)
    else:
        client.query(topics.dev.issue.set, {"issue": text}, exiting_print_message)


@issue.command_with_client("get")
def issue_get(client: Client) -> None:
    """Get current banner shown before login."""
    client.query(topics.dev.issue.get_config, handler=exiting_print_message)


@cli.command_with_client()
@writable_file_option_decorator(DEVICE_CONFIG_JSON)
@click.option("--export-private-keys", is_flag=True, help="Governs export of private keys and user password hashes.")
def get_config(client: Client, filename: Path, export_private_keys: bool) -> None:
    """Get configuration and store in a file.

    Whole device configuration will be saved to json file
    named `device_config.json`.
    """
    get_config_impl(client, rashly(store_json_config(filename)), export_private_keys=export_private_keys)


@cli.command_with_client(timeout_ms=120_000)
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
@click.option("--unconditionally", is_flag=True, help=(
    "Prevent connectivity checking after executing this command (without this option "
    "user may be asked to confirm that after command execution he has not lost "
    "connection to the device, without such confirmation command would be rolled back.)"
))
@click.option(
    "--use-meta-options-from-file",
    is_flag=True,
    hidden="--debug" not in sys.argv,
    help=(
        """Makes meta information about how to set config inside config file more important than
        command line options. In normal circumstances such meta information (like if
        --unconditionally was given or not via CLI) is generated automatically (and even if it
        was present in config file it would be overwritten by CLI).
        For debugging reasons user may want to manually set such meta information in config
        file. As this is debuggin option format of this meta information is not documented.
        """
        if "--debug" in sys.argv
        else None
    ),
)
def set_config(client: Client, filename: Path, unconditionally: bool, use_meta_options_from_file: bool) -> None:
    """Sets configuration stored in a file.

    Whole device configuration will be restored from a file.
    """
    message = json.loads(filename.read_text())
    if use_meta_options_from_file and "meta_options" in message:
        if "ask_for_affirmation" in message["meta_options"]:
            click.echo(
                "Ignoring command line setting of unconditional execution, which was "
                f"'{'unconditionally' if unconditionally else 'ask for affirmation'}'"
                "in favor of meta options from file, which is "
                f"'{'ask for affirmation' if message['meta_options']['ask_for_affirmation'] else 'unconditionally'}'"
            )
        else:
            message["meta_options"].update({"ask_for_affirmation": not unconditionally})
    else:
        message.update({"meta_options": {"ask_for_affirmation": not unconditionally}})
    # Handle partial information from daemons
    client.register_trivial_handler(f"{topics.dev.set_config}.rt", print_message_as_utf8)
    client.query(
        topics.dev.set_config,
        message,
        lambda message: set_config_response_handler(client, message),
        affirm_handler_generator=ask_for_affirmation,
    )


# TODO device show shall use terse output for firewall (same as fw show)
@cli.command_with_client()
@click.option("--export-private-keys", is_flag=True, help="Governs export of private keys and user password hashes.")
def show(client: Client, export_private_keys: bool) -> None:
    """Show configuration.

    Whole device configuration will be printed out.
    Note that this is quite verbose.
    """
    get_config_impl(client, exiting_print_message, export_private_keys=export_private_keys)


@cli.command()
def oss() -> None:
    """Print open source software licenses.

    Retrieves information about installed packages and their licenses.
    """
    # TODO shouldn't it be running over daemon?
    click.echo_via_pager(licence_parser.get_oss())


@cli.group()
def user() -> None:
    """Add, remove or list system users.

    Add, remove or list system users. User home directories are created
    automatically with paths specific for the group of a user. For the `user`
    group account path to home is `/home/ro_users/{usrnm}` where `{usrnm}`
    is the username. For the `admin` group account path
    to home is `/home/admins/{admnm}` where `{admnm}` is the username.

    Examples:
    *** add -g user -p 12345 -u user_ro --- adds read only user `user_ro` with password `12345`
    *** add -g admin -p 12345 -u admin --- adds admin user
    *** remove -u user_ro --- remove user but leave his home directory on disk
    *** remove -u admin -d --- remove user and all of his home files
    """


@user.command_with_client("add")
@click.option("-u", "--username", required=True,
              help="Login name (which is a unique identifier in the system) of a user to be added.")
@click.option("-g", "--group", required=True, type=click.Choice([ADMIN_GROUP, USER_GROUP]),
              help=f"""Group of a user determines permissions in the system and is mandatory when adding new user.
                    Users of group `{ADMIN_GROUP}` have full access configuration management, users of group
                    `{USER_GROUP}` can only execute commands which do not change configuration. To choose
                    account group, available options are `user` with read only access to CLI and `admin` with
                    full access to CLI.""")
@click.option("-p", "--password", required=True, help="Password is mandatory when adding user.")
def user_add(client: Client, username: str, group: str, password: str) -> None:
    """Add system users."""
    user_data = {"action": ADD_USER, "username": username, "group": group, "password": password}
    client.query(topics.dev.manage_user, user_data, exiting_print_message)


@user.command_with_client("remove")
@click.option("-u", "--username", required=True,
              help="Login name (which is a unique identifier in the system) of a user to be removed.")
@click.option("-d", "--deletehome", is_flag=True, help="Causes user home directory and its contents to be deleted.")
def user_remove(client: Client, username: str, deletehome: bool) -> None:
    """Remove system users."""
    user_data = {"action": REMOVE_USER, "username": username, "deletehome": deletehome}
    client.query(topics.dev.manage_user, user_data, exiting_print_message)


@user.command_with_client("list")
def user_list(client: Client) -> None:
    """List system users."""
    client.query(topics.dev.manage_user, {"action": SHOW_USERS}, exiting_print_message)


@cli.command_with_client(timeout_ms=60_000)
@click.argument("name")
def hostname(client: Client, name: str) -> None:
    """Set device hostname.

    Sets device hostname, this will also set hostname in IoT Edge daemon
    config. Note that it may brake Azure configuration which could be depending on
    that name.
    """
    client.query(topics.azure.set_hostname, {"hostname": name}, exiting_print_message)


@cli.command_with_client()
@click.argument("what", type=click.Choice([REMOVE_EVERYTHING]))
def erase(client: Client, what: str) -> None:
    """Remove data from persistent storage.

    Allows to perform full factory reset of device. All files created
    after installation (including user files, dockers and config for
    services) will be removed.
    """
    if click.confirm("This operation will clear all user data from the device, are you sure you want to proceed?"):
        client.query(topics.dev.perform_factory_reset, handler=exiting_print_message)
    else:
        click.echo("Aborting as requsted")
        sys.exit(0)


@cli.group()
def logrotate() -> None:
    """Manage rotation of log files.

    Changes when log files will be renamed and removed.

    Examples:
    *** set --size 100 --rotate 7 --period daily --- new log file will be created
    after current grows above 100MB or new day starts, keep only last 7 log files on disk
    *** show --- display current logrotate configuration
    """


@logrotate.command_with_client("set")
@click.option("-p", "--period", type=click.Choice([HOUR, DAY, WEEK, MONTH]), required=True,
              help="How often log files are rotated.")
@click.option("-r", "--rotate", type=int, required=True,
              help="""Logrotate rotates the log files that many times before removal.
                   If it's set to 0, old versions are removed rather than rotated.""")
@click.option("-s", "--size", type=int, required=True,
              help="""Maximum size of the log file in megabytes.
                   Logrotate rotates the log at selected period, but when the log file
                   reaches it's maximum size, logrotate rotates log despite the period.""")
def logrotate_set(client: Client, period: str, rotate: int, size: int) -> None:
    """Change config for logrotate service."""
    user_data = {"period": period, "rotate": rotate, "maxsize": size}
    client.query(topics.dev.logrotate.set_config, {"logrotate": user_data}, exiting_print_message)


@logrotate.command_with_client("show")
def logrotate_show(client: Client) -> None:
    """Show current config."""
    client.query(topics.dev.logrotate.get_config, handler=exiting_print_message)


@cli.command_with_client()
def serialnumber(client: Client) -> None:
    """Get serial number of the device.

    Serial number of the device will be printed out.
    """
    client.query(topics.dev.get_serial_number, handler=exiting_print_message)


@cli.command_with_client(hidden=True)
def grant_docker_volumes_access_to_admins(client: Client) -> None:
    """Access to /data/docker/volumes will be granted for the admin user."""
    client.query(topics.dev.docker_volumes_access, handler=exiting_print_message)


@cli.command_with_client()
@click.argument("option", type=click.Choice(["enable", "disable", "default", "status"]))
def overcommit_memory(client: Client, option: str) -> None:
    """Change memory overcommit configuration.

    This enables or disables overcommitting of the memory.
    When disabled, the machine will not run programs that would exceed available memory.
    When enabled, OOM killer might kill programs that it finds suitable to kill.
    """
    if option == "status":
        client.query(topics.dev.overcommit_memory.get, handler=exiting_print_message)
    else:
        client.query(
            topics.dev.overcommit_memory.set,
            {"overcommit_memory": option},
            exiting_print_message,
        )


@cli.group()
def local_console() -> None:
    """Manage linux local login."""


@local_console.command_with_client("set")
@click.option("-l", "--login", type=click.Choice(["enable", "disable"]), help="Enable or disable linux local login.")
@click.option("-s", "--syskeys", type=click.Choice(["enable", "disable"]),
              help="""Enable or disable Ctrl-Alt-Del, SysRq keys action.
                   This option enables or disables SysRq to both consoles: serial
                   (COM1) and local (TTY)""")
def local_console_set(client: Client, login: str, syskeys: str) -> None:
    """Enable/disable login via local console.

    This enables or disables linux local console (TTY)
    *** IMPORTANT - this command, might lock you out.
    """
    user_data: MutableMapping[str, Any] = {"local_console": {}}
    if login is not None:
        user_data["local_console"]["login"] = bool(login == "enable")
    if syskeys is not None:
        user_data["local_console"]["syskeys"] = bool(syskeys == "enable")

    client.query(topics.dev.local_console.set_config, user_data, exiting_print_message)


@local_console.command_with_client("get")
def local_console_get(client: Client) -> None:
    """Check state of local linux console."""
    client.query(topics.dev.local_console.get_config, handler=exiting_print_message)


@cli.group()
def ssh() -> None:
    """Manage ssh authentication methods and public keys.

    Allows to manage if password and public key based
    authentication is available for ssh connecitons. At least one
    method must be allowed. If password based authentication is
    going to be turned off, then at least admin account must have
    at least one valid public key present in
    "~/.ssh/authorized_keys".

    Examples:
    *** set --public_key_auth on --password_auth off --- allow key based authentication
    but disable password based one
    *** set -p off --- disable password auth (leave key based auth in same state
    as it was before - this command will fail if key based authentication was turned off already)
    *** show --- display current ssh authenctication configration
    """


@ssh.command_with_client("set-config")
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
def ssh_set_config(client: Client, filename: Path) -> None:
    """Replace ssh config and user keys with new values.

    This will first validate that at least one authentication
    method is enabled in incoming config, if yes then proceed to
    replace users ssh public keys. In case of failure for any user,
    allowed authentication methods will be set as requested but
    password based authentication will be enabled always in case
    admin user authorized_keys will be empty, to prevent total lock
    out from device. Keys of users not listed in the json will not
    be modified --- to remove keys of users they need to be present
    in json file with empty list of keys.  Warning: in case of
    issues with keys in json file it may cause state where some
    users have changed keys, and some user have old keys --- please
    analyze failures of this command carefully.
    """
    trivial_set_config(client, topic=topics.dev.ssh.set_config, file_name=filename)


@ssh.command_with_client("get-config")
@writable_file_option_decorator(SSH_CONFIG_JSON)
def ssh_get_config(client: Client, filename: str) -> None:
    """Return current ssh config."""
    trivial_get_config(client, topic=topics.dev.ssh.get_config, file_name=filename)


@ssh.command_with_client("set")
@click.option("-k", "--public-key-auth", type=click.Choice(["on", "off"]))
@click.option("-p", "--password-auth", type=click.Choice(["on", "off"]))
def ssh_set(client: Client, public_key_auth: str, password_auth: str) -> None:
    """Change allowed types of ssh authentication."""
    if public_key_auth is None and password_auth is None:
        click.echo(f"{RESPONSE_FAILURE} No action requested")
        sys.exit(1)
    if public_key_auth == "off" and password_auth == "off":
        click.echo(f"{RESPONSE_FAILURE} At least one authentication method has to be on")
        sys.exit(1)

    user_data = {
        "sshconfig": {"key_auth": public_key_auth or "", "password_auth": password_auth or ""}
    }
    client.query(topics.dev.ssh.set_config, user_data, exiting_print_message)


@ssh.command_with_client("show")
def ssh_show(client: Client) -> None:
    """Show current ssh authentication configuration."""
    client.query(topics.dev.ssh.get_config, handler=exiting_print_message)


@ssh.command_with_client("list-publickeys")
@click.option("-u", "--username", default=getpass.getuser(), show_default=True)
def ssh_list_publickeys(client: Client, username: str) -> None:
    """Display content of ~/.ssh/authorized_keys for currently logged in user."""
    if username == getpass.getuser():
        try:
            keys = AuthorizedKeys(username).read_ssh_keys()
            for i, item in enumerate(keys, start=0):
                click.echo(f"{i:<30}: {item:<40}")
            sys.exit(0)
        except Exception as exc:
            print_error_message(f"{RESPONSE_FAILURE} {repr(exc)}")
            sys.exit(1)
    else:
        client.query(topics.dev.ssh.list_keys, {"username": username}, with_list_filter_applied)


@ssh.command_with_client("add-publickey")
@readable_file_option_decorator()
@click.option("-u", "--username", default=getpass.getuser(), show_default=True)
def ssh_add_publickey(client: Client, filename: Path, username: str) -> None:
    """Adds a public key from a keypair for selected user to authorized_keys.

    If you want to update comment to already existing key
    first you have removed it with remove_key option.
    """
    key_content = filename.read_text()
    if username == getpass.getuser():
        try:
            AuthorizedKeys(username).add_ssh_key(key_content)
        except Exception as exc:
            print_error_message(f"{RESPONSE_FAILURE} {repr(exc)}")
            sys.exit(1)
        click.echo(f"{RESPONSE_OK} Key successfuly added")
        sys.exit(0)
    else:
        client.query(
            topics.dev.ssh.add_key,
            {"username": username, "key": key_content},
            exiting_print_message,
        )


@ssh.command_with_client("remove-key")
@click.option("-i", "--index", type=int, required=True)
@click.option("-u", "--username", default=getpass.getuser(), show_default=True)
def ssh_remove_key(client: Client, index: int, username: str) -> None:
    """Remove key with given index for currently logged in user."""
    if username == getpass.getuser():
        try:
            AuthorizedKeys(username).delete_ssh_key(index)
        except Exception as exc:
            print_error_message(f"{RESPONSE_FAILURE} {repr(exc)}")
            sys.exit(1)
        print(f"{RESPONSE_OK} Key successfuly removed")
        sys.exit(0)
    else:
        client.query(
            topics.dev.ssh.remove_key,
            {"username": username, "index": index},
            exiting_print_message,
        )


@ssh.command_with_client("maxsessions")
@click.argument("sessions", type=int)
def ssh_maxsessions(client: Client, sessions: int) -> None:
    """Specifies the maximum number of open shell,
    login or subsystem (e.g. sftp) sessions permitted per network connection.
    """
    client.query(topics.dev.ssh.set_config, {"sshconfig": {"maxsessions": sessions}}, exiting_print_message)


@ssh.command_with_client("maxstartups")
@click.argument("startups", type=int)
def ssh_maxstartups(client: Client, startups: int) -> None:
    """Specifies the maximum number of concurrent unauthenticated connections to the SSH daemon."""
    client.query(topics.dev.ssh.set_config, {"sshconfig": {"maxstartups": startups}}, exiting_print_message)


@cli.group()
def proxy() -> None:
    """Set http/https proxy on system level (for logged in users shells and for docker)."""


@proxy.command_with_client("add")
@click.option("-p", "--http", default="",
              help="set HTTP-Proxy to http://<SERVER>:<PORT> (e.g. http://192.168.123.254:8080 )")
@click.option("-s", "--https", default="",
              help="set HTTPS-Proxy to https://<SERVER>:<PORT> (e.g. https://192.168.123.254:8080 )")
@click.option("-n", "--no-reload", is_flag=True,
              help="""Change configuration, but do not reload it immediately in all daemons. If you give this option
                   new proxy will be used by docker containers after next reboot of the system or next restart of
                   docker subsystem (whichever comes first). To manually enforce restart of docker execute command
                   `docker-config apply`.""")
def proxy_add(client: Client, http: str, https: str, no_reload: bool) -> None:
    """Add or overrwrite proxy or proxies.

    You may give http and/or https proxy parameters.  This command
    will add them (or overwrite if any is already configured) for
    azure daemons, docker and shell environment as well as for
    docker-compose (Note: docker-compose stores its proxy
    settings in separate physical location and this forces
    docker-compose proxy to be kept in separate subsection of EG
    global json config). If you give proxy only for one protocol
    (http/https) and the other is already configured, this other
    will not be removed. For individual users' environments, logging
    in again is needed to notice configuration change.
    Immediately after storing new proxy in the configurations response
    will be sent back to the user and daemons which use proxy (docker
    and containers) will be restarted. This restart of deamons can
    take considerable amount of time (and potentially disrupt
    processing done by containers).
    """
    if http == "" and https == "":
        click.echo("No action requested")
        sys.exit(1)
    user_data = {
        "proxy_servers": {"http_proxy": http, "https_proxy": https},
        "reload_daemons": not no_reload,
    }
    click.echo("Changing global proxy settings")
    client.query(topics.dev.proxy.add, user_data, print_message_exit_if_not_ok)
    click.echo("Changing docker compose proxy settings")
    client.query(topics.docker.compose.proxy.add, user_data, exiting_print_message)


@proxy.command_with_client("delete")
@click.option("--http", is_flag=True, help="Delete http proxy.")
@click.option("--https", is_flag=True, help="Delete https proxy.")
def proxy_delete(client: Client, http: bool, https: bool) -> None:
    """Delete proxies.

    Delete http and/or https proxies.
    """
    data = {"http_proxy": http, "https_proxy": https}
    if any(data.values()):
        client.query(topics.dev.proxy.delete, data, print_message_exit_if_not_ok)
        client.query(topics.docker.compose.proxy.delete, data, exiting_print_message)


@proxy.command_with_client("set-config")
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
def proxy_set_config(client: Client, filename: Path) -> None:
    """Replace proxy config with new one.

    This will add/remove system and docker daemon proxies to match
    contents of given config. This will not change docker-compose proxy settings!
    Docker and containers will be restarted according to boolean
    entry 'reload_daemons' which can optionally be present next to the object
    proxy_servers in json file used with this command. If that entry is
    missing its value is assumed to be true.
    """
    trivial_set_config(client, topic=topics.dev.proxy.set_config, file_name=filename)


@proxy.command_with_client("get-config")
@writable_file_option_decorator(PROXY_CONFIG_JSON)
def proxy_get_config(client: Client, filename: Path) -> None:
    """Return current proxy config (except for docker-compose).

    This will return partial EG config for proxy only. Note that
    because docker-compose stores its proxy settings in separate place
    you would need to use command `docker-config compose get-config`
    to get partial config containing proxy of docker-compose.
    """
    trivial_get_config(client, topic=topics.dev.proxy.get_config, file_name=filename)


@cli.group()
def login_timeout() -> None:
    """Set automatic logout after idle timeout.

    This will set a system-wide auto-logout policy.
    Every user, after N-seconds of idle
    will be logged off.
    """


@login_timeout.command_with_client("set")
@click.option("-s", "--seconds", type=int, required=True,
              help="Amount of idle seconds for automatic logout (0 means infinity, values 1 to 9 are rejected)")
def login_timeout_set(client: Client, seconds: int) -> None:
    """Set the value for automatic idle logout.

    Configure every user login to be closed after idle time.
    """
    client.query(topics.dev.logintimeout.set_config, {"login_timeout": seconds}, exiting_print_message)


@login_timeout.command_with_client("get")
def login_timeout_get(client: Client) -> None:
    """Get the value for automatic idle logout.

    Read All-Users default idle logout time.
    """
    client.query(topics.dev.logintimeout.get_config, handler=exiting_print_message)


@cli.group()
def localcertstore() -> None:
    """Install certificate to local-device Trusted CA Store."""


@localcertstore.command_with_client("install")
@readable_file_option_decorator()
def localcertstore_install(client: Client, filename: Path) -> None:
    """Install new CRT."""
    client.query(topics.dev.install_localcert, str(filename), exiting_print_message)


@cli.command_with_client()
def get_logs(client: Client) -> None:
    """Prepare archive with logs.

    Prepares archive `logs.zip` with currently existing logs.
    """
    client.query(topics.logstreamer.download_logs, handler=rashly(save_logs))


@cli.group()
def smartems() -> None:
    """Configure SmartEMS management service.

    Examples:
    *** show --- display current configuration
    *** check --- immediately connect to SmartEMS to check for any management commands
    *** config --username user --password pass --url url --- configure smartems connection
    *** config --username user --password pass --url url --vcc-api-endpoint --- configure
    smartems connection with new api endpoint
    """


@smartems.command_with_client("config")
@click.option("-u", "--username", required=True, help="Username for SmartEMS.")
@click.option("-p", "--password", required=True, help="Password for SmartEMS.")
@click.option("-U", "--url", required=True, help="URL for SmartEMS.")
@click.option("-s", "--skip", is_flag=True,
              help="Skip checking SSL certificate for SmartEMS. DANGER! This allows man-in-the-middle attacks.")
@click.option("-i", "--interval", type=click.IntRange(10), default=3600, show_default=True,
              help="Period between two checks in seconds. The minimum is 10s.")
# With new SmartEMS the endpoint for devices with VPNCC changes, default is old endpoint.
@click.option("--vcc-api-endpoint", is_flag=True,
              help="""If present, this API endpoint will be set - /api/edgegatewayvcc/configuration. Otherwise, this one
                   will be used - /api/edgegateway/configuration. If your EdgeGateway is connected to VPN CC use this option.""")
def smartems_config(
    client: Client,
    username: str,
    password: str,
    url: str,
    skip: bool,
    interval: int,
    vcc_api_endpoint: bool,
) -> None:
    """Change config for auto update service."""
    user_data = {
        "smartems": {
            "username": username,
            "password": password,
            "url": url,
            "pollingInterval": interval,
            "edgegatewayvcc": vcc_api_endpoint,
            "skip_ssl_verification": skip,
        }
    }
    client.query(topics.smart_ems.set_config, user_data, exiting_print_message)


@smartems.command_with_client("set-config")
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
def smartems_set_config(client: Client, filename: Path) -> None:
    """Replace current SmartEMS configuration."""
    trivial_set_config(client, topic=topics.smart_ems.set_config, file_name=filename)


@smartems.command_with_client("show")
def smartems_show(client: Client) -> None:
    """Show current config."""
    client.query(topics.smart_ems.get_config, handler=exiting_print_message)


@smartems.command_with_client("check", timeout_ms=300_000)
def smartems_check(client: Client) -> None:
    """Trigger immediate check for new SmartEMS management commands.

    This command will trigger an immediate connection to the SmartEMS and perform any
    updates requested by SmartEMS (it may be config and or software update) or
    provide information requested by SmartEMS (like current configuration).
    If software update is requested then EG will download package first ---
    depending on connection speed this may consume bigger amount of time. This
    command times out after five minutes but even in such case download is still
    being performed in the background. The new firmware package is being stored in
    /tmp and has .swu extension, so you can check in that directory if it is
    growing. After firmware is downloaded it will be automatically installed and
    system will reboot.
    """
    # This handler shows partial response from daemons
    client.register_trivial_handler("smart_ems.rt", updater_realtime_information)
    client.query(topics.smart_ems.check_smart_ems, handler=exiting_print_message)


@smartems.group()
def certificate() -> None:
    """Manage security certificate used by SmartEMS.

    Examples:
    *** add -c cert.pem --- add self-signed certificate
    *** delete --- remove custom certificate
    *** show --- display content of custom certificate
    """


@certificate.command_with_client("add")
@click.option("-c", "--certificate", required=True, type=click.Path(readable=True, file_okay=True, path_type=Path),
              help="Filename with certificate.")
def certificate_add(client: Client, certificate: Path) -> None:
    """Add a new certificate."""
    manage_certificate(client, CERTIFICATE.ADD, certificate)


@certificate.command_with_client("delete")
def certificate_delete(client: Client) -> None:
    """Remove current certificate."""
    manage_certificate(client, CERTIFICATE.DELETE)


@certificate.command_with_client("show")
def certificate_show(client: Client) -> None:
    """Display current certificate."""
    manage_certificate(client, CERTIFICATE.SHOW)


@cli.command_with_client(timeout_ms=120_000)
@readable_file_option_decorator(allowed_extensions=FileExtension.SWU)
def swupdate(client: Client, filename: Path) -> None:
    """Perform software update."""
    client.query(
        topics.dev.swupdate, {"filepath": str(filename.absolute()), "reboot": True, "dryrun": True}, exiting_print_message
    )


@cli.group()
def datetime() -> None:
    """Configure date and time settings.

    Examples:
    *** show --- display current NTP status
    *** enable --- enable NTP service
    *** disable --- disable NTP service
    *** list-timezones --- list supported timezones
    *** set-timezone Europe/Berlin --- set timezone to Berlin time
    *** set-ntp --server "time1.ntp time2.ntp" --- set NTP to use provided servers
    *** set-ntp --server "time1.ntp time2.ntp" --fallback-servers "time3.ntp time4.ntp"
    --- set primary and fallback servers for NTP
    *** set-ntp --server time1.ntp --interval-minimum 16 --interval-maximum 32
    --- set minimum and maximum intervals (in seconds) beetwen two synchronization events
    """


@datetime.command_with_client("set-config")
@readable_file_option_decorator(allowed_extensions=FileExtension.JSON)
def datetime_set_config(client: Client, filename: Path) -> None:
    """Replace ntp config with new one.

    This will set configuration of ntp and select timezone.
    """
    trivial_set_config(client, topic=topics.dev.datetime.set_config, file_name=filename)


@datetime.command_with_client("get-config")
@writable_file_option_decorator(DATETIME_CONFIG_JSON)
def datetime_get_config(client: Client, filename: Path) -> None:
    """Return current ntp and timezone config."""
    trivial_get_config(client, topic=topics.dev.datetime.get_config, file_name=filename)


@datetime.command_with_client("show")
def datetime_show(client: Client) -> None:
    """Show current datetime status."""
    client.query(topics.dev.datetime.show, handler=exiting_print_message)


@datetime.command_with_client("set-ntp")
@click.option(
    "-s",
    "--server",
    help="IP address or hostname for main NTP servers, this paramter accept \
         multiple servers separated by spaces. \
         If multiple servers are provided \
         thay have to be enclosed within quotation marks",
    required=True,
)
@click.option(
    "-f",
    "--fallback-servers",
    help="IP address or hostname for fallback server, this paramter accepts \
         multiple servers separated by spaces. Those servers will be used \
         to synchronize time when main NTP server is inaccessible. \
         Defaults to: time1.google.com time2.google.com \
         time3.google.com time4.google.com. If multiple servers provided \
         that have to be enclosed with quotation mark.",
    default="time1.google.com time2.google.com time3.google.com time4.google.com",
    show_default=True,
)
@click.option(
    "-i",
    "--interval-minimum",
    type=click.IntRange(16, 2048),
    help="Minimum time in seconds between two NTP messages. Defaults to 32 \
         Minimum value is 16, maximum value is 2048. Minimum value can not \
         be grater then maximum interval.",
    default=32,
    show_default=True,
)
@click.option(
    "-I",
    "--interval-maximum",
    type=click.IntRange(16, 2048),
    help="Maximum time in seconds between two NTP messages. \
        Defaults to 2048. Minimum value is 16, maximum value is 2048.\
        Maximum time can not be lesser than minimum time.",
    default=2048,
    show_default=True,
)
def datetime_set_ntp(client: Client, server: str, fallback_servers: str, interval_minimum: int, interval_maximum: int) -> None:
    """Change NTP configuration."""
    user_data = {
        "ntp_server": server,
        "fallback_servers": fallback_servers,
        "interval_minimum": interval_minimum,
        "interval_maximum": interval_maximum,
    }
    client.query(topics.dev.datetime.set_ntp_server, user_data, exiting_print_message)


@datetime.command_with_client("enable")
def datetime_enable(client: Client) -> None:
    """Enable NTP service."""
    client.query(topics.dev.datetime.manage_ntp_service, {"ntp_enabled": True}, exiting_print_message)


@datetime.command_with_client("disable")
def datetime_disable(client: Client) -> None:
    """Disable NTP service."""
    client.query(topics.dev.datetime.manage_ntp_service, {"ntp_enabled": False}, exiting_print_message)


@datetime.command("list-timezones")
def datetime_list_timezones() -> None:
    """List all available timezones."""
    click.echo_via_pager("\n".join(get_timezones()))


@datetime.command_with_client("set-timezone")
@click.argument("timezone", type=click.Choice(get_timezones()))
def datetime_set_timezone(client: Client, timezone: str) -> None:
    """Set timezone."""
    client.query(topics.dev.datetime.set_timezone, {"timezone": timezone}, exiting_print_message)


@cli.group()
def webgui() -> None:
    """Manage WebGUI service.

    Examples:
    *** status  --- current status of webgui
    *** enable  --- enable webgui
    *** disable --- disable webgui
    *** config --port 1234 --- change webgui port to 1234
    """


@webgui.command_with_client("status")
def webgui_status(client: Client) -> None:
    """Show current status of WebGUI service."""
    client.query(topics.webgui.get_config, handler=exiting_print_message)


@webgui.command_with_client("enable")
def webgui_enable(client: Client) -> None:
    """Enable WebGUI service."""
    client.query(topics.webgui.manage_service, {"webgui": {"is_enabled": True}}, exiting_print_message)


@webgui.command_with_client("disable")
def webgui_disable(client: Client) -> None:
    """Disable WebGUI service."""
    client.query(topics.webgui.manage_service, {"webgui": {"is_enabled": False}}, exiting_print_message)


@webgui.command_with_client("config")
@click.option("-p", "--port", type=click.IntRange(1, 65535), required=True, help="Port number.")
def webgui_config(client: Client, port: int) -> None:
    """Change WebGUI configuration."""
    client.query(topics.webgui.change_port, {"webgui": {"port": port}}, exiting_print_message)


@webgui.command_with_client("redirect")
@click.option('--enable', 'mode', flag_value=True)
@click.option('--disable', 'mode', flag_value=False)
def webgui_redirect(client: Client, mode: bool | None) -> None:
    """Enable/disable redirect."""
    if mode is not None:
        client.query(topics.webgui.manage_redirect, {"webgui": {"http_redirect": mode}}, exiting_print_message)


#################################################################################
#                               DEPRECATED COMMANDS                             #
#################################################################################


@cli.command_with_client("azure_set_tpm", timeout_ms=60_000, hidden=True, deprecated="Use `device azure set-dps-x509`.")
@click.argument("id_scope")
@click.argument("registration_id")
def azure_set_tpm_deprecated(client: Client, id_scope: str, registration_id: str) -> None:
    client.query(
        topics.azure.set_tpm,
        {"scope_id": id_scope, "registration_id": registration_id},
        exiting_print_message,
    )


@cli.command_with_client("tpm_get", timeout_ms=60_000, hidden=True, deprecated="Use `device tpm-get`.")
def tpm_get_deprecated(client: Client) -> None:
    client.query(topics.dev.tpm.get_config, handler=exiting_print_message)


@cli.group("user_password_hash", hidden=True, deprecated="Use `device user-password-hash`.")
def user_password_hash_deprecated() -> None:
    ...


@user_password_hash_deprecated.command_with_client("show", hidden=True, deprecated="Use `device user-password-hash show`")
def user_password_hash_show_deprecated(client: Client) -> None:
    client.query(topics.dev.user.password_hash.get_config, handler=exiting_print_message)


@user_password_hash_deprecated.command_with_client(
    "set_config", hidden=True, deprecated="Use `device user-password-hash set-config`"
)
@readable_file_option_decorator()
def user_password_hash_set_config_deprecated(client: Client, filename: Path) -> None:
    trivial_set_config(client, topic=topics.dev.user.password_hash.set_config, file_name=filename)


@cli.command_with_client("serial_console", hidden=True, deprecated="Use `device serial console`.")
@click.argument("device", type=click.IntRange(0, len(get_serial_devices())))
@click.argument("when", type=click.Choice(["now", "at_boot", "both"]))
@click.argument("mode", type=click.Choice(["on", "off"]))
def serial_console_deprecated(client: Client, device: int, when: str, mode: str) -> None:
    if not len(get_serial_devices()):
        click.echo("This device is misconfigured as not having any serial devices!!!")
        click.echo(f"This is unexpected, so {PLEASE_REPORT}")
        sys.exit(1)
    config = {}
    enabled = mode == "on"
    if when in ("at_boot", "both"):
        config["at_startup"] = enabled
    if when in ("now", "both"):
        config["currently"] = enabled
    request = {"serial": {f"serial{device}": {"console_output": config}}}
    client.query(topics.dev.serial.set_config, request, exiting_print_message)


@cli.command_with_client("serial_get_config", hidden=True, deprecated="Use `device serial get-config`.")
@writable_file_option_decorator(SERIAL_CONFIG_JSON)
def serial_get_config_deprecated(client: Client, filename: Path) -> None:
    trivial_get_config(client, topic=topics.dev.serial.get_config, file_name=filename)


@cli.command_with_client("motd_set", hidden=True, deprecated="Use `device motd set`")
@click.option("-f", "--file", type=click.Path(readable=True, path_type=Path))
@click.option("-t", "--text")
def motd_set_deprecated(client: Client, file: Path | None, text: str | None) -> None:
    if (file or text) is None:
        return

    if file is not None:
        client.query(
            topics.dev.motd.set, {"motd": file.read_text()}, exiting_print_message
        )
    else:
        client.query(topics.dev.motd.set, {"motd": text}, exiting_print_message)


@cli.command_with_client("motd_get", hidden=True, deprecated="Use `device motd get`.")
def motd_get_deprecated(client: Client) -> None:
    client.query(topics.dev.motd.get_config, handler=exiting_print_message)


@cli.command_with_client("issue_set", hidden=True, deprecated="Use `device issue set`.")
@click.option("-f", "--file", type=click.Path(readable=True, path_type=Path))
@click.option("-t", "--text")
def issue_set_deprecated(client: Client, file: Path | None, text: str | None) -> None:
    if file is not None:
        client.query(topics.dev.issue.set, {"issue": file.read_text()}, exiting_print_message)
    else:
        client.query(topics.dev.issue.set, {"issue": text}, exiting_print_message)


@cli.command_with_client("issue_get", hidden=True, deprecated="Use `device issue get`.")
def issue_get_deprecated(client: Client) -> None:
    client.query(topics.dev.issue.get_config, handler=exiting_print_message)


@cli.command_with_client("get_config", hidden=True, deprecated="Use `device get-config`.")
@writable_file_option_decorator(DEVICE_CONFIG_JSON)
@click.option("--export-private-keys", is_flag=True)
def get_config_deprecated(client: Client, filename: Path, export_private_keys: bool) -> None:
    get_config_impl(client, rashly(store_json_config(filename)), export_private_keys=export_private_keys)


@cli.command_with_client("set_config", hidden=True, deprecated="Use `device set-config`.", timeout_ms=120_000)
@readable_file_option_decorator(DEVICE_CONFIG_JSON)
@click.option("--unconditionally", is_flag=True)
@click.option("--use-meta-options-from-file", is_flag=True, hidden=True)
def set_config_deprecated(client: Client, filename: Path, unconditionally: bool, use_meta_options_from_file: bool) -> None:
    message = json.loads(filename.read_text())
    if use_meta_options_from_file and "meta_options" in message:
        if "ask_for_affirmation" in message["meta_options"]:
            click.echo(
                "Ignoring command line setting of unconditional execution, which was "
                f"'{'unconditionally' if unconditionally else 'ask for affirmation'}'"
                "in favor of meta options from file, which is "
                f"'{'ask for affirmation' if message['meta_options']['ask_for_affirmation'] else 'unconditionally'}'"
            )
        else:
            message["meta_options"].update({"ask_for_affirmation": not unconditionally})
    else:
        message.update({"meta_options": {"ask_for_affirmation": not unconditionally}})
    # Handle partial information from daemons
    client.register_trivial_handler(f"{topics.dev.set_config}.rt", print_message_as_utf8)
    client.query(
        topics.dev.set_config,
        message,
        lambda message: set_config_response_handler(client, message),
        affirm_handler_generator=ask_for_affirmation,
    )


@smartems.command_with_client("set_config", hidden=True, deprecated="Use `device smartems set-config`.")
@readable_file_option_decorator(SMART_EMS_JSON)
def smartems_set_config_deprecated(client: Client, filename: Path) -> None:
    trivial_set_config(client, topic=topics.smart_ems.set_config, file_name=filename)


@cli.command_with_client("azure_set_config", hidden=True, deprecated="Use `device azure set-config`.", timeout_ms=60_000)
@readable_file_option_decorator(AZURE_CONFIG_JSON)
def azure_set_config_deprecated(client: Client, filename: Path) -> None:
    """Set Azure configuration."""
    trivial_set_config(client, topic=topics.azure.set_config, file_name=filename)


@cli.command_with_client("azure_get_config", hidden=True, deprecated="Use `device azure get-config`.")
@writable_file_option_decorator(AZURE_CONFIG_JSON)
@click.option("--export-private-keys", is_flag=True)
def azure_get_config_deprecated(client: Client, filename: Path, export_private_keys: bool) -> None:
    topic = (
        topics.azure.get_config_with_privates
        if export_private_keys
        else topics.azure.get_config
    )
    trivial_get_config(client, topic=topic, file_name=filename)


@cli.command_with_client("azure_set_string", timeout_ms=60_000, hidden=True, deprecated="Use `device azure set-string`.")
@click.argument("connection_string")
def azure_set_string_deprecated(client: Client, connection_string: str) -> None:
    client.query(topics.azure.set_connection_string, connection_string, exiting_print_message)


@cli.command_with_client("azure_set_dps_x509", timeout_ms=60_000, hidden=True, deprecated="Use `device azure set-dps-x509`.")
@click.option("-k", "--identity_pk", type=click.Path(readable=True, path_type=Path), required=True)
@click.option("-p", "--identity_cert", type=click.Path(readable=True, path_type=Path), required=True)
@click.option("-i", "--id_scope", required=True)
def azure_set_dps_x509_deprecated(client: Client, identity_pk: Path, identity_cert: Path, id_scope: str) -> None:
    config = {
        "scope_id": id_scope,
        "identity_cert": identity_cert.read_text(),
        "identity_pk": identity_pk.read_text(),
    }
    client.query(topics.azure.set_x509, config, exiting_print_message)


@cli.command_with_client(
    "azure_set_certificate", timeout_ms=30_000, hidden=True, deprecated="Use `device azure set-certificate`."
)
@click.option("-t", "--trust_bundle_cert", type=click.Path(readable=True, path_type=Path), required=True)
@click.option("-d", "--device_ca_cert", type=click.Path(readable=True, path_type=Path), required=True)
@click.option("-p", "--device_ca_pk", type=click.Path(readable=True, path_type=Path), required=True)
def azure_set_certificate_deprecated(client: Client, trust_bundle_cert: Path, device_ca_cert: Path, device_ca_pk: Path) -> None:
    data = {
        CONFIG_KEY_TRUST_BUNDLE_CERT: trust_bundle_cert.read_text(),
        CONFIG_KEY_EDGE_CA_CERT: device_ca_cert.read_text(),
        CONFIG_KEY_EDGE_CA_PK: device_ca_pk.read_text(),
    }
    client.query(topics.azure.set_cert, data, exiting_print_message)


@cli.group("azure_configfile", hidden=True, deprecated="Use `device azure configfile`.")
def azure_configfile_deprecated() -> None:
    ...


@azure_configfile_deprecated.command_with_client(
    "export", timeout_ms=30_000, hidden=True, deprecated="Use `device azure configfile export`."
)
@writable_file_option_decorator(IOTEDGE_TOML)
def azure_configfile_export_deprecated(client: Client, filename: Path) -> None:
    client.query(topics.azure.get_config_file, handler=rashly(store_toml_config(filename, "azure_configfile")))


@azure_configfile_deprecated.command_with_client(
    "import", timeout_ms=60_000, hidden=True, deprecated="Use `device azure configfile import`."
)
@readable_file_option_decorator()
def azure_configfile_import_deprecated(client: Client, filename: Path) -> None:
    client.query(topics.azure.set_config_file, {"azure_configfile": filename.read_text()}, exiting_print_message)


@cli.command_with_client("azure_set_option", hidden=True, deprecated="Use `device azure set-option`.")
@click.option("-t", "--topic", default="")
@click.option("-e", "--entry", required=True, multiple=True)
@click.option("-d", "--dry_run", is_flag=True)
def azure_set_option_deprecated(client: Client, topic: str, entry: list[str], dry_run: bool) -> None:
    entries = "\n".join(entry)
    artificial_toml = f"[{topic}]\n{entries}" if topic else entries
    try:
        value = toml.loads(artificial_toml)
    except toml.decoder.TomlDecodeError as e:
        click.echo(
            f"Partial TOML:\n{artificial_toml}\n\n"
            f"There is an error on line {e.lineno} of partial TOML above.\n"
            f"TOML parser message is: '{e.msg}'\n"
            "If error above is not clear, please check also examples in help of this command.\n"
            "Most probably the value of --entry needs correction."
        )
        sys.exit(1)
    click.echo("Partial TOML to be added to config:")
    toml.dump(value, sys.stdout)
    if dry_run:
        click.echo("This is dry run, no changes were actually made")
        sys.exit(0)
    else:
        client.query(
            topics.azure.set_partial_config_file,
            {"azure_configfile": value},
            exiting_print_message,
        )


@cli.command_with_client("get_serialnumber", hidden=True, deprecated="Use `device serialnumber`.")
def get_serialnumber_deprecated(client: Client) -> None:
    client.query(topics.dev.get_serial_number, handler=exiting_print_message)


@cli.command_with_client("overcommit_memory", hidden=True, deprecated="Use `device overcommit-memory`.")
@click.argument("option", type=click.Choice(["enable", "disable", "default", "status"]))
def overcommit_memory_deprecated(client: Client, option: str) -> None:
    if option == "status":
        client.query(topics.dev.overcommit_memory.get, handler=exiting_print_message)
    else:
        client.query(
            topics.dev.overcommit_memory.set,
            {"overcommit_memory": option},
            exiting_print_message,
        )


@cli.command_with_client("set_local_console", hidden=True, deprecated="Use `device local-console set`.")
@click.option("-l", "--login", type=click.Choice(["enable", "disable"]))
@click.option("-s", "--syskeys", type=click.Choice(["enable", "disable"]))
def set_local_console_deprecated(client: Client, login: str, syskeys: str) -> None:
    user_data: MutableMapping[str, Any] = {"local_console": {}}
    if login is not None:
        user_data["local_console"]["login"] = bool(login == "enable")
    if syskeys is not None:
        user_data["local_console"]["syskeys"] = bool(syskeys == "enable")

    client.query(topics.dev.local_console.set_config, user_data, exiting_print_message)


@cli.command_with_client("get_local_console", hidden=True, deprecated="Use `device local-console get`.")
def get_local_console_deprecated(client: Client) -> None:
    client.query(topics.dev.local_console.get_config, handler=exiting_print_message)


@cli.group("login_timeout", hidden=True, deprecated="Use `device login-timeout`.")
def login_timeout_deprecated() -> None:
    ...


@login_timeout_deprecated.command_with_client("set", hidden=True, deprecated="Use `device login-timeout set`.")
@click.option("-s", "--seconds", type=int, required=True)
def login_timeout_set_deprecated(client: Client, seconds: int) -> None:
    client.query(topics.dev.logintimeout.set_config, {"login_timeout": seconds}, exiting_print_message)


@login_timeout_deprecated.command_with_client("get", hidden=True, deprecated="Use `device login-timeout get`.")
def login_timeout_get_deprecated(client: Client) -> None:
    client.query(topics.dev.logintimeout.get_config, handler=exiting_print_message)


@cli.command_with_client("get_logs", hidden=True, deprecated="Use `device get-logs`.")
def get_logs_deprecated(client: Client) -> None:
    client.query(topics.logstreamer.download_logs, handler=rashly(save_logs))


@cli.group("sshauth", hidden=True, deprecated="Use `device ssh`.")
def sshauth_deprecated() -> None:
    ...


@sshauth_deprecated.command_with_client("set_config", hidden=True, deprecated="Use `device ssh set-config`.")
@readable_file_option_decorator(SSH_CONFIG_JSON)
def sshauth_set_config_deprecated(client: Client, filename: Path) -> None:
    trivial_set_config(client, topic=topics.dev.ssh.set_config, file_name=filename)


@sshauth_deprecated.command_with_client("get_config", hidden=True, deprecated="Use `device ssh get-config`.")
@writable_file_option_decorator(SSH_CONFIG_JSON)
def sshauth_get_config_deprecated(client: Client, filename: Path) -> None:
    trivial_get_config(client, topic=topics.dev.ssh.get_config, file_name=filename)


@sshauth_deprecated.command_with_client("set", hidden=True, deprecated="Use `device ssh set`.")
@click.option("-k", "--public_key_auth", type=click.Choice(["on", "off"]))
@click.option("-p", "--password_auth", type=click.Choice(["on", "off"]))
def sshauth_set_deprecated(client: Client, public_key_auth: str, password_auth: str) -> None:
    if public_key_auth is None and password_auth is None:
        click.echo(f"{RESPONSE_FAILURE} No action requested")
        sys.exit(1)
    if public_key_auth == "off" and password_auth == "off":
        click.echo(f"{RESPONSE_FAILURE} At least one authentication method has to be on")
        sys.exit(1)

    user_data = {
        "sshconfig": {"key_auth": public_key_auth or "", "password_auth": password_auth or ""}
    }
    client.query(topics.dev.ssh.set_config, user_data, exiting_print_message)


@sshauth_deprecated.command_with_client("show", hidden=True, deprecated="Use `device ssh show`.")
def sshauth_show_deprecated(client: Client) -> None:
    client.query(topics.dev.ssh.get_config, handler=exiting_print_message)


@sshauth_deprecated.command_with_client("list_publickeys", hidden=True, deprecated="Use `device ssh list-publickeys`.")
@click.option("-u", "--username", default=getpass.getuser(), show_default=True)
def sshauth_list_publickeys_deprecated(client: Client, username: str) -> None:
    if username == getpass.getuser():
        try:
            keys = AuthorizedKeys(username).read_ssh_keys()
            for i, item in enumerate(keys, start=0):
                click.echo(f"{i:<30}: {item:<40}")
            sys.exit(0)
        except Exception as exc:
            print_error_message(f"{RESPONSE_FAILURE} {repr(exc)}")
            sys.exit(1)
    else:
        client.query(topics.dev.ssh.list_keys, {"username": username}, with_list_filter_applied)


@sshauth_deprecated.command_with_client("add_publickey", hidden=True, deprecated="Use `device ssh add-publickey`.")
@readable_file_option_decorator()
@click.option("-u", "--username", default=getpass.getuser(), show_default=True)
def sshauth_add_publickey_deprecated(client: Client, filename: Path, username: str) -> None:
    key_content = filename.read_text()
    if username == getpass.getuser():
        try:
            AuthorizedKeys(username).add_ssh_key(key_content)
        except Exception as exc:
            print_error_message(f"{RESPONSE_FAILURE} {repr(exc)}")
            sys.exit(1)
        click.echo(f"{RESPONSE_OK} Key successfuly added")
        sys.exit(0)
    else:
        client.query(
            topics.dev.ssh.add_key,
            {"username": username, "key": key_content},
            exiting_print_message,
        )


@sshauth_deprecated.command_with_client("remove_key", hidden=True, deprecated="Use `device ssh remove-key`.")
@click.option("-i", "--index", type=int, required=True)
@click.option("-u", "--username", default=getpass.getuser(), show_default=True)
def sshauth_remove_key_deprecated(client: Client, index: int, username: str) -> None:
    if username == getpass.getuser():
        try:
            AuthorizedKeys(username).delete_ssh_key(index)
        except Exception as exc:
            print_error_message(f"{RESPONSE_FAILURE} {repr(exc)}")
            sys.exit(1)
        print(f"{RESPONSE_OK} Key successfuly removed")
        sys.exit(0)
    else:
        client.query(
            topics.dev.ssh.remove_key,
            {"username": username, "index": index},
            exiting_print_message,
        )


@sshauth_deprecated.command_with_client("maxsessions", hidden=True, deprecated="Use `device ssh maxsessions`.")
@click.argument("sessions", type=int)
def sshauth_maxsessions_deprecated(client: Client, sessions: int) -> None:
    """Specifies the maximum number of open shell, login or subsystem (e.g. sftp) sessions permitted per network connection."""
    client.query(topics.dev.ssh.set_config, {"sshconfig": {"maxsessions": sessions}}, exiting_print_message)


@sshauth_deprecated.command_with_client("maxstartups", hidden=True, deprecated="Use `device ssh maxstartups`.")
@click.argument("startups", type=int)
def sshauth_maxstartups_deprecated(client: Client, startups: int) -> None:
    client.query(topics.dev.ssh.set_config, {"sshconfig": {"maxstartups": startups}}, exiting_print_message)


@proxy.command_with_client("del", hidden=True, deprecated="Use `device proxy delete`.")
@click.option("--http", is_flag=True, help="Delete http proxy.")
@click.option("--https", is_flag=True, help="Delete https proxy.")
def proxy_del_deprecated(client: Client, http: bool, https: bool) -> None:
    data = {"http_proxy": http, "https_proxy": https}
    if any(data.values()):
        client.query(topics.dev.proxy.delete, data, print_message_exit_if_not_ok)
        client.query(topics.docker.compose.proxy.delete, data, exiting_print_message)


@proxy.command_with_client("set_config", hidden=True, deprecated="Use `device proxy set-config`.")
@readable_file_option_decorator(PROXY_CONFIG_JSON)
def proxy_set_config_deprecated(client: Client, filename: Path) -> None:
    trivial_set_config(client, topic=topics.dev.proxy.set_config, file_name=filename)


@proxy.command_with_client("get_config", hidden=True, deprecated="Use `device proxy get-config`.")
@writable_file_option_decorator(PROXY_CONFIG_JSON)
def proxy_get_config_deprecated(client: Client, filename: Path) -> None:
    trivial_get_config(client, topic=topics.dev.proxy.get_config, file_name=filename)


@datetime.command_with_client("set_config", hidden=True, deprecated="Use `device datetime set-config`.")
@readable_file_option_decorator(DATETIME_CONFIG_JSON)
def datetime_set_config_deprecated(client: Client, filename: Path) -> None:
    trivial_set_config(client, topic=topics.dev.datetime.set_config, file_name=filename)


@datetime.command_with_client("get_config", hidden=True, deprecated="Use `device datetime get-config`.")
@writable_file_option_decorator(DATETIME_CONFIG_JSON)
def datetime_get_config_deprecated(client: Client, filename: Path) -> None:
    trivial_get_config(client, topic=topics.dev.datetime.get_config, file_name=filename)


@datetime.command_with_client("set_ntp", hidden=True, deprecated="Use `device datetime set-ntp`.")
@click.option("-s", "--server", required=True)
@click.option("-f", "--fallback-servers", show_default=True,
              default="time1.google.com time2.google.com time3.google.com time4.google.com")
@click.option("-i", "--interval-minimum", type=click.IntRange(16, 2048), default=32, show_default=True)
@click.option("-I", "--interval-maximum", type=click.IntRange(16, 2048), default=2048, show_default=True)
def datetime_set_ntp_deprecated(
    client: Client, server: str, fallback_servers: str, interval_minimum: int, interval_maximum: int
) -> None:
    user_data = {
        "ntp_server": server,
        "fallback_servers": fallback_servers,
        "interval_minimum": interval_minimum,
        "interval_maximum": interval_maximum,
    }
    client.query(topics.dev.datetime.set_ntp_server, user_data, exiting_print_message)


@datetime.command("list_timezones", hidden=True, deprecated="Use `device datetime list-timezones`.")
def datetime_list_timezones_deprecated() -> None:
    click.echo_via_pager("\n".join(get_timezones()))


@datetime.command_with_client("set_timezone", hidden=True, deprecated="Use `device datetime set-timezone`.")
@click.argument("timezone", type=click.Choice(get_timezones()))
def datetime_set_timezone_deprecated(client: Client, timezone: str) -> None:
    client.query(topics.dev.datetime.set_timezone, {"timezone": timezone}, exiting_print_message)


@cli.command_with_client(
    "grant_docker_volumes_access_to_admins",
    hidden=True,
    deprecated="Use `grant-docker-volumes-access-to-admins`."
)
def grant_docker_volumes_access_to_admins_deprecated(client: Client) -> None:
    client.query(topics.dev.docker_volumes_access, handler=exiting_print_message)


@cli.group("certificate", hidden=True, deprecated="Use `device smartems certificate`.")
def certificate_deprecated() -> None:
    ...


@certificate_deprecated.command_with_client("add", hidden=True, deprecated="Use `device smartems certificate add`.")
@click.option("-c", "--certificate", required=True, type=click.Path(readable=True, file_okay=True, path_type=Path),
              help="Filename with certificate.")
def certificate_add_deprecated(client: Client, certificate: Path) -> None:
    manage_certificate(client, CERTIFICATE.ADD, certificate)


@certificate_deprecated.command_with_client("delete", hidden=True, deprecated="Use `device smartems certificate del`.")
def certificate_delete_deprecated(client: Client) -> None:
    manage_certificate(client, CERTIFICATE.DELETE)


@certificate_deprecated.command_with_client("show", hidden=True, deprecated="Use `device smartems certificate show`.")
def certificate_show_deprecated(client: Client) -> None:
    manage_certificate(client, CERTIFICATE.SHOW)
