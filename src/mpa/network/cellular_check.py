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
import sys
from pathlib import Path

# Local imports
from mpa.common.logger import Logger
from mpa.network.cellular import ModemError, find_modem_by_index

logger = Logger(f"{Path(sys.argv[0]).name if __name__ == '__main__' else __name__}")


class CellularCheck:
    MODEM_STATUS_MESSAGES = {
        "locked": (
            "The SIM is locked. A PIN is required to unlock it.\n"
            "To unlock the SIM. Run these commands:\n"
            "  nm cellular set {0} off\n"
            "  nm cellular configure --pin <PIN> --apn <APN> {0}\n"
            "  nm cellular set {0} on\n"
        ),
        "registered": (
            "The modem is registered with a network but not yet fully connected.\n"
            "Please make sure your APN settings are correct.\n"
            "  nm cellular configure --apn <APN> {0}\n"
            "  nm cellular set {0} on"
        ),
        "connected": (
            "All good! The modem is connected to the cellular network.\n"
            "Modem state: connected."
        ),
        "enabled": (
            "Modem settings faulty (please check APN, AccessNumber and PIN).\n"
            "  nm cellular configure --pin <PIN> --apn <APN> --access_number <ACCESS_NO> {0}\n"
            "  nm cellular set {0} on\n"
        ),
        "disconnected": (
            "The modem is disconnected from network.\n"
            "Check if your cables/antenna is connected properly."
        ),
        "failed": "Connection attempt failed. Check the modem and network settings.",
        "disabled": "The modem is currently disabled. Enable the modem to connect.",
        "unavailable": (
            "The modem is unavailable. Check if the modem is properly inserted and "
            "recognized by the system."
        ),
    }

    def __init__(self) -> None:
        self.__user_action_needed = False
        self.__output_for_user = ""

    def _interpret_sim_status(self, status: str) -> None:
        self.__user_action_needed = status not in ("connected", "")
        msg = self.MODEM_STATUS_MESSAGES.get(status, f"Unknown status: {status}")
        self._print_to_user(msg.format("1"))

    def _print_to_user(self, append: str) -> None:
        self.__output_for_user += f"{append}\n"

    def cellular_check(self) -> str:
        self.__user_action_needed = False
        self.__output_for_user = ""
        self._cellular_check_internal()
        if self.__user_action_needed:
            logger.info("User action required")
            return f"{self.__output_for_user}Please follow the instructions above."
        return f"{self.__output_for_user}Your connection seems to work."

    def _cellular_check_internal(self) -> None:
        self._print_to_user("Discovering modem...")
        try:
            modem = find_modem_by_index(1)
        except ModemError:
            self._print_to_user("No modem found.")
            self.__user_action_needed = True
            return

        self._print_to_user("Modem found.")
        self._print_to_user("Checking for SIM card presence...")
        if modem.sim_dbus_path not in ("--", ""):
            self._print_to_user("SIM card presence: Yes")
            sim_status = modem.state
            self._interpret_sim_status(sim_status)
        else:
            self._print_to_user("SIM card presence: No")
            self.__user_action_needed = True
