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
import re
import sys
from pathlib import Path

# Local imports
from mpa.common.logger import Logger
from mpa.communication.process import run_command

logger = Logger(f"{Path(sys.argv[0]).name if __name__ == '__main__' else __name__}")


class CellularCheck:
    MODEM_STATUS_MESSAGES = {
        "locked": "The SIM is locked. A PIN is required to unlock it.\n\
To unlock the SIM. Run this commands:\n\
  nm cellular_turn_on {0} \n\
  nm configure_cellular {0} --pin <PIN> --apn <APN>\n\
  nm cellular_turn_on {0}\n",
        "registered": "The modem is registered with a network but not yet fully connected\n\
Please make sure your APN settings are correct.\n\
  nm configure_cellular {0} --apn <APN>\n\
  nm cellular_turn_on {0} ",
        "connected": "All good! The modem is connected to the cellular network.\n\
Modem state: connected.",
        "enabled": "Modem settings faulty (please check APN, AccessNumber and PIN). \
  nm configure_cellular {0} --pin <PIN> --apn <APN> --access_number <ACCESS_NO>\n\
  nm cellular_turn_on {0}\n",
        "disconnected": "The modem is disconnected from network.\n\
Check if your cables/antenna is connected properly.",
        "failed": "Connection attempt failed. Check the modem and network settings.",
        "disabled": "The modem is currently disabled. Enable the modem to connect.",
        "unavailable": "The modem is unavailable. Check if the modem is properly inserted and \
recognized by the system."
    }

    def __init__(self) -> None:
        self.user_action_needed = False
        self.output_for_user = ""

    def _interpret_sim_status(self, status: str, modem_id: str) -> None:
        self.user_action_needed = False if status in ("connected", "") else True
        msg = self.MODEM_STATUS_MESSAGES.get(status, f"Unknown status: {status}")
        self._print_to_user(msg.format(modem_id))

    def _print_to_user(self, append: str) -> None:
        self.output_for_user += f'{append}\n'

    def _get_mmclim_output(self, modemID: str) -> str:
        mmclim_output = run_command(f'mmcli -m {modemID}').stdout.decode()
        mmclim_output = re.sub(r"\x1b\[\d+m", "", mmclim_output)
        logger.debug(mmclim_output)
        return mmclim_output

    def _get_status_state(self, mmclim_output: str) -> str:
        match = re.search(r'state:\s+(\w+)', mmclim_output)
        logger.info(f'get_status_state {match=}')
        if match:
            status = match.group(1)
        else:
            status = "failed"
        logger.debug(f"get_status_state {status=}")
        return status

    def _check_sim_card_presence(self, mmclim_output: str) -> bool:
        match = re.search(r'SIM.*sim path.*', mmclim_output)
        logger.info(f'check_sim_card_presence {match=}')
        return bool(match)

    def cellular_check(self) -> str:
        self.user_action_needed = False
        self.output_for_user = ""
        self._cellular_check_internal()
        if self.user_action_needed:
            logger.info("User action required")
            return f"{self.output_for_user}Please follow the instructions above."
        return f"{self.output_for_user}Your connection seems to work."

    def _cellular_check_internal(self) -> None:
        self._print_to_user("Discovering modem...")
        modem_id = self._find_modem()
        if modem_id is None:
            return
        logger.info("Modem found - get mmcli -m output")
        mmclim_output = self._get_mmclim_output(modem_id)
        self._print_to_user("Checking for SIM card presence...")
        if self._check_sim_card_presence(mmclim_output):
            self._print_to_user("SIM card presence: Yes")
            sim_status = self._get_status_state(mmclim_output)
            self._interpret_sim_status(sim_status, modem_id)
        else:
            self._print_to_user("SIM card presence: No")
            self.user_action_needed = True

    def _find_modem(self) -> str | None:
        mmcliL = run_command('mmcli -L')
        stdout = mmcliL.stdout.decode()
        logger.debug(f'{mmcliL=}, {stdout=}, {mmcliL.stderr=}')

        match = re.search(r'/Modem/(\d)', stdout)
        if match:
            modem_id = match.group(1)
            self._print_to_user(f'Modem found ID: {modem_id}')
            logger.info(f'Modem found ID: {modem_id}')
            return modem_id
        self._print_to_user("No modem found.")
        self.user_action_needed = True
        return None


if __name__ == "__main__":
    cellular_check = CellularCheck()
    print(cellular_check.cellular_check())
