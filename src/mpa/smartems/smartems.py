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
import json
import sys
from typing import Any

from .client import SmartEmsClient
from .common import CommandName, SmartEmsError, fill_with_error
from .config import SmartEmsConfig
from .handlers import CommandHandler
from .messenger import Messenger
from .store import Store, DefaultStore
from mpa.common.common import RESPONSE_FAILURE, RESPONSE_OK
from mpa.common.killer_thread import KillerThread
from mpa.common.logger import Logger
from mpa.communication.common import InvalidParameterError, InvalidPreconditionError, expect_empty_message
from mpa.communication.inter_process_lock import InterProcessLock
from mpa.communication.status_codes import CERTIFICATE
from mpa.config.configfiles import ConfigFiles
from mpa.device.reboot import reboot_time_left

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

config_files = ConfigFiles()
SMARTEMS_TRANSACTION_LOCK_FILE = config_files.add("lock_file", "eg/smart_ems_transaction_lock", is_expected=False)
SMARTEMS_TRANSACTION_ID = config_files.add("transaction_id", "eg/smart_ems_transaction_id", is_expected=False)
config_files.verify()

LOCK = InterProcessLock(SMARTEMS_TRANSACTION_LOCK_FILE, stale_lock_seconds=900)


class SmartEms:
    def __init__(
        self,
        config: SmartEmsConfig,
        client: SmartEmsClient,
        handlers: dict[str, CommandHandler],
        messenger: Messenger,
        store: Store | None = None,
    ) -> None:
        self._config = config
        self._smartems_client = client
        self._handlers = handlers
        self._messenger = messenger
        self._store = store or DefaultStore(SMARTEMS_TRANSACTION_ID)

    def get_ems_config(self, message: bytes) -> dict[str, Any]:
        expect_empty_message(message, "get_ems_config()")
        d = self._config.to_dict()
        d.update(
            {
                "certificate": self._config.get_certificate_content(),
                "pollingInterval": self._config.get_polling_interval(),
            }
        )
        return {"smartems": d}

    def manage_cert(self, message: bytes) -> str:
        user_data = json.loads(message)
        if user_data["action"] == CERTIFICATE.ADD.value:
            SmartEmsConfig.save_certificate_content(user_data["cert_content"])
            return f"{RESPONSE_OK} Certificate saved"
        if user_data["action"] == CERTIFICATE.DELETE.value:
            if len(SmartEmsConfig.get_certificate_content()) == 0:
                return f"{RESPONSE_OK} No custom certificate"
            SmartEmsConfig.remove_certificate()
            return f"{RESPONSE_OK} Custom certificate removed"
        if user_data["action"] == CERTIFICATE.SHOW.value:
            cert_data = SmartEmsConfig.get_certificate_content()
            return f"{RESPONSE_OK} {cert_data}"
        return f"{RESPONSE_FAILURE} Unknown action"

    def set_ems_config(self, message: bytes) -> str:
        config = json.loads(message)["smartems"]

        for key in ["username", "password", "url"]:
            if key not in config:
                raise InvalidParameterError(f"Missing {key}")

        if "edgegatewayvcc" in config:
            if not isinstance(config["edgegatewayvcc"], bool):
                raise InvalidParameterError("edgegatewayvcc must be a boolean")
        else:
            config["edgegatewayvcc"] = self._config.edgegatewayvcc

        if config["url"]:
            config["url"] = self._config.get_base_url(config["url"])

        new_config = SmartEmsConfig.from_dict(config)

        if "pollingInterval" in config:
            try:
                self._config.update_timer(config["pollingInterval"])
            except ValueError as e:
                raise InvalidParameterError(str(e)) from e

        if "certificate" in config:
            self._config.save_certificate_content(config["certificate"])

        self._config.update(new_config)
        self._config.save()
        return f"{RESPONSE_OK} Smart EMS config successfuly updated"

    def check(self, _: bytes) -> None:
        if reboot_time_left() is not None:
            raise InvalidPreconditionError("Reboot is in progress")

        with LOCK.transaction("Communicate with Smart EMS"):
            self._run()

    def finish_pending_transaction(self) -> None:
        def background_task() -> None:
            try:
                if reboot_time_left() is not None:
                    raise InvalidPreconditionError("Reboot is in progress")

                with LOCK.transaction("Finish pending Smart EMS transaction"):
                    transaction = self._safe_load()
                    if transaction is None:
                        return

                    save_count = transaction.get("save_count", 1)
                    # it is not present in old transaction
                    transaction["save_count"] = save_count
                    if save_count is not None and save_count > 5:
                        self._store.clear()
                        raise SmartEmsError("Transaction save count exceeded limit")

                    self._finish_pending_transaction(transaction)
            except Exception as e:
                logger.error(f"Failed to finish pending transaction: {e}")

        background_thread = KillerThread(target=background_task)
        background_thread.start()

    def _safe_load(self) -> Any:
        try:
            return self._store.load()
        except Exception as e:
            self._messenger.send("smart_ems.rt", f"Failed to load transaction: {e}")
            logger.error(f"Failed to load transaction: {e}")
            return None

    def _run(self) -> None:
        transaction = self._safe_load()
        if transaction is not None:
            self._finish_pending_transaction(transaction)
            return

        transaction = self._smartems_client.send_transaction({})
        self._process_transaction(transaction)

    def _finish_pending_transaction(self, transaction: dict[str, Any]) -> None:
        command_status = transaction.get("commandStatus")
        if command_status is None:
            try:
                command_name = transaction.get("commandName")
                if command_name is None:
                    raise SmartEmsError("Missing command name in transaction")
                handler = self._select_handler(command_name)
                transaction = handler.finish(transaction)

            except Exception as e:
                transaction = fill_with_error(transaction, e)
                self._messenger.send("smart_ems.rt", f"ERROR: {e}")

        self._store.save(transaction)
        transaction = self._smartems_client.send_transaction(transaction)
        self._store.clear()
        self._process_transaction(transaction)

    def _process_transaction(self, transaction: dict[str, Any]) -> None:
        while True:
            match transaction:
                # No Operation
                case {} if len(transaction) == 0:
                    self._messenger.send("smart_ems.rt", "Nothing requested by Smart EMS")
                    return
                # Error e.g. missing fields in the transaction or disabled device
                case {"error": str(error_msg)}:
                    raise SmartEmsError(error_msg)
                # Command
                case {"commandTransactionId": str(transaction_id), "commandName": str(command_name)} if transaction_id:
                    handler = self._select_handler(command_name)
                    try:
                        self._store.save(transaction)
                        transaction = handler.process(transaction)
                    except Exception as e:
                        transaction = fill_with_error(transaction, e)
                        self._messenger.send("smart_ems.rt", f"ERROR: {e}")

                    self._store.save(transaction)
                    # if there is no status in the transaction, it indicates a reboot is expected
                    # send response after reboot
                    # check _finish_pending_transaction()
                    if "commandStatus" not in transaction:
                        return

                    transaction = self._smartems_client.send_transaction(transaction)
                    self._store.clear()
                case _:
                    raise SmartEmsError(f"Unsupported SmartEMS transaction: {transaction}")

    def _select_handler(self, command_name: str) -> CommandHandler:
        if command_name not in CommandName:
            raise SmartEmsError(f"Unknown command: {command_name!r}")

        handler = self._handlers.get(command_name)
        if handler is None:
            raise SmartEmsError(f"Handler not found for command: {command_name!r}")
        return handler
