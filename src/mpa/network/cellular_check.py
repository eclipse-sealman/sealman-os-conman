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
import re
import sys
from pathlib import Path
from typing import Any

# Local imports
from mpa.common.logger import Logger
from mpa.communication.process import run_command

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

    def _interpret_sim_status(self, status: str, cellular_idx: str) -> None:
        self.__user_action_needed = status not in ("connected", "")
        msg = self.MODEM_STATUS_MESSAGES.get(status, f"Unknown status: {status}")
        self._print_to_user(msg.format(cellular_idx))

    def _print_to_user(self, append: str) -> None:
        self.__output_for_user += f"{append}\n"

    def _get_modem_json(self, modem_id: str) -> dict[str, Any]:
        raw = run_command(f"mmcli -m {modem_id} -J").stdout.decode()
        data = json.loads(raw)
        assert isinstance(data, dict)
        return data

    def _get_status_state(self, modem_data: dict[str, Any]) -> str:
        status = modem_data.get("modem", {}).get("generic", {}).get("state", "failed")
        assert isinstance(status, str)
        return status

    def _check_sim_card_presence(self, modem_data: dict[str, Any]) -> bool:
        sim = modem_data.get("modem", {}).get("generic", {}).get("sim", "--")
        has_sim = sim not in ("--", "", None)
        logger.info(f"check_sim_card_presence: sim={sim!r}, has_sim={has_sim}")
        return has_sim

    def _get_cellular_index(self, modem_data: dict[str, Any]) -> str:
        ports: list[str] = modem_data.get("modem", {}).get("generic", {}).get("ports", [])
        for port in ports:
            m = re.match(r'cellular(\d+)', port)
            if m:
                idx = str(m.group(1))
                return idx

        return ""

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
        modem_id = self._find_modem()
        if modem_id is None:
            self._print_to_user("No modem found.")
            self.__user_action_needed = True
            return

        self._print_to_user("Modem found.")
        modem_data = self._get_modem_json(modem_id)
        cellular_idx = self._get_cellular_index(modem_data)

        self._print_to_user("Checking for SIM card presence...")
        if self._check_sim_card_presence(modem_data):
            self._print_to_user("SIM card presence: Yes")
            sim_status = self._get_status_state(modem_data)
            self._interpret_sim_status(sim_status, cellular_idx)
        else:
            self._print_to_user("SIM card presence: No")
            self.__user_action_needed = True

    def _find_modem(self) -> str | None:
        try:
            raw = run_command("mmcli -L -J").stdout.decode()
            out = json.loads(raw)
            # Path is like "/org/freedesktop/ModemManager1/Modem/0" — last segment is the ID
            modem_path: str = out["modem-list"][0]
            modem_id = modem_path.split("/")[-1]
            return modem_id
        except (KeyError, IndexError, json.JSONDecodeError, Exception) as e:
            logger.error(f"_find_modem: {e}")
            return None
