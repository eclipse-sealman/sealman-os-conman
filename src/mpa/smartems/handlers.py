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
import functools
import json
from pathlib import Path
from threading import Event
from typing import Any, Protocol

from .client import SmartEmsClient
from .common import AbruptedCommandError, CommandName, CommandStatus, SmartEmsError, SystemUpdateError
from .firmware import inspect_firmware
from mpa.common.common import RESPONSE_OK
from mpa.communication import topics
from mpa.communication.client import Client as CommunicationClient
from mpa.communication.common import get_current_root_partition
from mpa.device.os_info import OsInfo
from mpa.swupdate.mgmtd_swupdate import full_update_with_reboot


class CommandHandler(Protocol):
    def process(self, transaction: dict[str, Any]) -> dict[str, Any]: ...

    def finish(self, transaction: dict[str, Any]) -> dict[str, Any]: ...


class ConfigService:
    def __init__(self, client: CommunicationClient):
        self._client = client
        self.config: dict[str, Any] | None = None
        self._message: str | None = None

    def process(self, transaction: dict[str, Any]) -> dict[str, Any]:
        command_name = transaction.get("commandName")
        if command_name is None:
            raise SmartEmsError("Missing command name in transaction")

        if command_name == CommandName.UPDATE_CONFIG:
            return self._handle_update_config(transaction)

        if command_name == CommandName.GET_CONFIG:
            return self._handle_get_config(transaction)

        raise SmartEmsError(f"Unsupported command: {command_name}")

    def finish(self, transaction: dict[str, Any]) -> dict[str, Any]:
        command_name = transaction.get("commandName")
        if command_name is None:
            raise SmartEmsError("Missing command name in transaction")

        raise AbruptedCommandError(f"{command_name} command was abrupted")

    def _get_config(self) -> dict[str, Any]:
        def get_config_callback(event: Event, message: bytes) -> None:
            config = json.loads(message)
            self.config = config
            event.set()

        event = Event()
        callback_with_event = functools.partial(get_config_callback, event)
        self._client.query(topics.dev.get_config, "", callback_with_event)
        event.wait()

        assert self.config is not None, "Failed to get config from client"
        return self.config

    def _update_config(self, config: dict[str, Any]) -> None:
        real_time_messages = []

        def gather_real_time_messages(message: bytes) -> None:
            decoded = message.decode().strip("\"'\n ")
            self._client.send("smart_ems.rt", decoded)
            real_time_messages.append(decoded)

        def set_config_callback(event: Event, message: bytes) -> None:
            self._message = message.decode().strip("\"'\n ")
            self._client.unregister_trivial_handler(f"{topics.dev.set_config}.rt", gather_real_time_messages)
            event.set()

        event = Event()
        callback_with_event = functools.partial(set_config_callback, event)
        self._client.register_trivial_handler(f"{topics.dev.set_config}.rt", gather_real_time_messages)
        self._client.query(topics.dev.set_config, config, callback_with_event)
        event.wait()
        if self._message is None or not self._message.startswith(RESPONSE_OK):
            raise SmartEmsError(f"Failed to update config: {self._message} {'\n'.join(real_time_messages)}")

    def _handle_update_config(self, transaction: dict[str, Any]) -> dict[str, Any]:
        self._client.send("smart_ems.rt", "Received config from SMART EMS - applying")
        config = transaction.pop("config", None)
        if config is None or not isinstance(config, dict):
            raise SmartEmsError("Invalid config provided")

        if "meta_options" not in config:
            config["meta_options"] = {}

        meta_options = config["meta_options"]
        if "ignore_unknown_config_sections" not in meta_options:
            meta_options["ignore_unknown_config_sections"] = True
        if "ignore_superflous_config_entries" not in meta_options:
            meta_options["ignore_superflous_config_entries"] = True

        self._update_config(config)
        transaction["commandStatus"] = CommandStatus.SUCCESS.value
        return transaction

    def _handle_get_config(self, transaction: dict[str, Any]) -> dict[str, Any]:
        self._client.send("smart_ems.rt", "Preparing config to be sent to Smart EMS")
        config = self._get_config()
        transaction["config"] = config
        transaction["commandStatus"] = CommandStatus.SUCCESS.value
        return transaction


class FirmwareService:
    def __init__(
        self,
        smartems_client: SmartEmsClient,
        os_info: OsInfo,
        client: CommunicationClient,
    ) -> None:
        self._smartems_client = smartems_client
        self._os_info = os_info
        self._client = client

    def process(self, transaction: dict[str, Any]) -> dict[str, Any]:
        firmware_url = transaction.pop("firmwareUrl", "")
        if len(firmware_url) == 0:
            raise SmartEmsError("Firmware URL is missing in the transaction")

        self._client.send("smart_ems.rt", "Starting to download the firmware")
        firmware = self._download(firmware_url)
        self._client.send("smart_ems.rt", "Firmware download finished, starting installation")
        try:
            firmware_metadata = self._inspect(firmware)
            partition = get_current_root_partition()
            sw_version = self._os_info.version_id
            install_timestamp = self._os_info.install_timestamp
            requested_version = firmware_metadata["os_version"]
            transaction["partition"] = partition
            transaction["sw_version"] = sw_version
            transaction["install_timestamp"] = install_timestamp
            transaction["requested_version"] = requested_version
            if firmware_metadata["with_gui_support"]:
                transaction["requested_gui_support"] = "TRUE"

            self._update(firmware)
            self._client.send("smart_ems.rt", "New firmware installed, the device will reboot soon")
        except Exception as e:
            firmware.unlink(missing_ok=True)
            raise e

        return transaction

    def finish(self, transaction: dict[str, Any]) -> dict[str, Any]:
        self._verify_update(transaction)
        transaction["commandStatus"] = CommandStatus.SUCCESS.value
        return transaction

    def _download(self, url: str) -> Path:
        return self._smartems_client.download(url)

    def _inspect(self, firmware_path: Path) -> dict[str, Any]:
        return inspect_firmware(firmware_path)

    def _verify_update(self, system_info: dict[str, Any]) -> None:
        try:
            requested_version = system_info.pop("requested_version")
            install_timestamp = system_info.pop("install_timestamp")
            if install_timestamp is not None:
                install_timestamp = install_timestamp.strip('"')
            with_gui_support = system_info.pop("requested_gui_support", None) == "TRUE"
            partition = system_info.pop("partition")
        except KeyError as e:
            raise AbruptedCommandError("Firmware update was not initiated properly") from e

        errors = []
        if self._os_info.version_id != requested_version:
            errors.append(f"System version: current: {self._os_info.version_id} requested: {requested_version}")
        if float(self._os_info.install_timestamp) <= float(install_timestamp):
            errors.append(f"Install timestamp: current: {self._os_info.install_timestamp} requested: {install_timestamp}")
        if self._os_info.with_gui_support != with_gui_support:
            errors.append(f"GUI support: current: {self._os_info.with_gui_support} requested: {with_gui_support}")
        if partition == get_current_root_partition():
            errors.append("System booted from the same partition")
        if errors:
            raise SystemUpdateError("\n".join(errors))

    def _update(self, firmware_path: Path) -> None:
        full_update_with_reboot(firmware_path)


def create_default_command_handlers(
    communication_client: CommunicationClient,
    smartems_client: SmartEmsClient,
    os_info: OsInfo,
) -> dict[str, CommandHandler]:
    config_service = ConfigService(communication_client)
    return {
        CommandName.GET_CONFIG.value: config_service,
        CommandName.UPDATE_CONFIG.value: config_service,
        CommandName.UPDATE_FIRMWARE.value: FirmwareService(smartems_client, os_info, communication_client),
    }
