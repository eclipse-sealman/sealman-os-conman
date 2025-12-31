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
"""
This class binds PresetBase and DaemonTransaction and allows for trivial
implentation of handlers of common affirmable actions in deamons which have
presets.
"""
from __future__ import annotations

# Standard imports
from pathlib import Path
import shutil
import sys
from typing import Any, Callable, Container, Mapping, Optional, Protocol, Sequence, Type

# Local imports
from mpa.common.common import RESPONSE_OK
from mpa.communication.client import Async
from mpa.communication.common import InvalidPreconditionError, InvalidPayloadError
from mpa.communication.daemon_transaction import DaemonTransaction
from mpa.common.logger import Logger
from mpa.communication.message_parser import get_bool, get_dict, get_optional_str
from mpa.communication.preset import PresetBase, PresetType

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

ROLLBACK_WARNING = "roll back in some cases may not be ideal, please ensure firewall is in expected state."


class AddPresestAction(Protocol):
    def __call__(self, parent_dir: Path, new_presets: Mapping[str, Any], excluded: Container[str] = list()) -> None:
        pass


class AffirmablePresetActionsBase:
    preset_class: Type[PresetBase]
    STATE_CHANGE: Path
    RESCUE: Path
    SET_CONFIG_PREVIOUS_PRESETS: Path
    SET_CONFIG_PREVIOUS_EDITS: Path

    def __init__(self, name: str,
                 daemon_transaction: DaemonTransaction,
                 reload_action: Callable[[], Optional[str]],
                 generate_disabled_preset_action: Callable[[Path], None],
                 add_presets_action: AddPresestAction):
        self.name = name
        self.daemon_transaction = daemon_transaction
        self.reload_action = reload_action
        self.generate_disabled_preset_action = generate_disabled_preset_action
        self.add_presets_action = add_presets_action
        self.preset_class.LOCK.set_post_lock_checker(self.ensure_no_broken_transaction)

    @classmethod
    def set_class_params(cls, *, preset_class: Type[PresetBase],
                         state_change_transaction_marker: Path,
                         rescue_preset_path: Path,
                         backup_saved_presets_path: Path,
                         backup_edited_presets_path: Path) -> None:
        cls.preset_class = preset_class
        cls.STATE_CHANGE = state_change_transaction_marker
        cls.RESCUE = rescue_preset_path
        cls.SET_CONFIG_PREVIOUS_PRESETS = backup_saved_presets_path
        cls.SET_CONFIG_PREVIOUS_EDITS = backup_edited_presets_path

    def enable(self, ask_for_affirmation: bool, topic: str, from_part: bytes, message_id: bytes) -> Any:
        if self.preset_class.is_enabled():
            return f"{RESPONSE_OK} {self.name} was already enabled, you may want to execute 'reload' instead of 'enable'"
        if ask_for_affirmation:
            with self.preset_class.LOCK.transaction("enable"):
                self.STATE_CHANGE.write_text("enable")
            self.daemon_transaction.start(topic, self.__rollback_to_disable, from_part, message_id)
            self.preset_class.enable()
            response = self.__reload()
            self.daemon_transaction.set_response(response)
            return Async()
        self.preset_class.enable()
        return self.__reload()

    def __reload(self) -> str:
        status = self.reload_action()
        if status is None:
            return RESPONSE_OK
        return f"{RESPONSE_OK} Additional information: \n {status}"

    def __disable(self) -> None:
        self.preset_class.disable()
        self.reload_action()

    def __rollback_to_disable(self, rollback: bool) -> None:
        with self.preset_class.LOCK.transaction(f"{'disable' if rollback else 'remove state change'}"):
            if self.STATE_CHANGE.exists():
                self.STATE_CHANGE.unlink(missing_ok=False)
                if rollback:
                    self.__disable()
            else:
                logger.error("Missing STATE_CHANGE in rollback_to_disable")

    def broken_transaction_detected(self) -> bool:
        if self.daemon_transaction.active:
            return False
        if self.preset_class.PREVIOUS.exists():
            return True
        if self.SET_CONFIG_PREVIOUS_PRESETS.exists():
            return True
        if self.SET_CONFIG_PREVIOUS_EDITS.exists():
            return True
        return False

    def ensure_no_broken_transaction(self) -> None:
        if self.broken_transaction_detected():
            raise InvalidPreconditionError("""There was no active transaction in this daemon but leftovers of unfished one
were detected in filesystem. Warning: This is exceptional case (can be triggered
e.g. in case of power loss while transaction was ongoing, or if there was some
crash). Command 'cleanup' will remove this invalid state, but after doing
cleanup restoring config from backup with 'set_config' is recomended.""")

    def commit(self) -> None:
        self.ensure_no_broken_transaction()
        if not self.daemon_transaction.commit():
            if self.daemon_transaction.last_transaction_rolled_back:
                raise InvalidPreconditionError("There was no active transaction and last transaction was rolled back. "
                                               f"Warning {ROLLBACK_WARNING}")
            else:
                raise InvalidPreconditionError("There was no active transaction")

    def __remove_symlink_or_dir(self, path: Path, *, ignore_errors: bool = False) -> None:
        if path.is_symlink():
            path.unlink(missing_ok=False)
        else:
            shutil.rmtree(path, ignore_errors=ignore_errors)

    def cleanup(self) -> bool:
        cleanup_made = self.daemon_transaction.commit()
        with self.preset_class.LOCK.stolen_lock("cleanup"):
            if self.STATE_CHANGE.exists():
                cleanup_made = True
                self.STATE_CHANGE.unlink(missing_ok=False)
            if self.preset_class.PREVIOUS.exists():
                cleanup_made = True
                self.__remove_symlink_or_dir(self.preset_class.PREVIOUS)
            if self.SET_CONFIG_PREVIOUS_PRESETS.exists():
                cleanup_made = True
                self.__remove_symlink_or_dir(self.SET_CONFIG_PREVIOUS_PRESETS)
            if self.SET_CONFIG_PREVIOUS_EDITS.exists():
                cleanup_made = True
                self.__remove_symlink_or_dir(self.SET_CONFIG_PREVIOUS_EDITS)
            if self.RESCUE.exists() and self.preset_class.CURRENT.resolve() != self.RESCUE.resolve():
                cleanup_made = True
                self.__remove_symlink_or_dir(self.RESCUE)
        return cleanup_made

    def disable(self, ask_for_affirmation: bool, topic: str, from_part: bytes, message_id: bytes) -> Any:
        if not self.preset_class.is_enabled():
            return f"{RESPONSE_OK} {self.name} was already disabled, you may want to execute 'reload' instead of 'enable'"
        if ask_for_affirmation:
            with self.preset_class.LOCK.transaction("disable"):
                self.STATE_CHANGE.write_text("disable")
            self.daemon_transaction.start(topic, self.__rollback_to_enable, from_part, message_id)
            self.preset_class.disable()
            response = self.__reload()
            self.daemon_transaction.set_response(response)
            return Async()
        self.preset_class.disable()
        return self.__reload()

    def __rollback_to_enable(self, rollback: bool) -> None:
        with self.preset_class.LOCK.transaction(f"{'enable' if rollback else 'remove state change'}"):
            if self.STATE_CHANGE.exists():
                self.STATE_CHANGE.unlink(missing_ok=False)
                if rollback:
                    self.preset_class.enable()
                    self.reload_action()
            else:
                logger.error("Missing STATE_CHANGE in rollback_to_enable")

    def select(self, ask_for_affirmation: bool, preset: PresetBase, topic: str, from_part: bytes, message_id: bytes) -> Any:
        if preset.is_selected():
            return (f"{RESPONSE_OK} Nothing to do, preset was already selected, "
                    "you may want to execute 'reload' if you want to ensure rules are refreshed")
        if preset.is_enabled() and ask_for_affirmation:
            preset.select()
            self.daemon_transaction.start(topic, self.__rollback_to_previous, from_part, message_id)
            response = self.__reload()
            self.daemon_transaction.set_response(response)
            return Async()
        preset.select(create_previous=False)
        if self.preset_class.is_enabled():
            return self.__reload()
        return None
        # TODO or maybe we want to save also runtime state and restore it with undo...
        # For now any runtime state is not relevant in firewall (counters only),
        # and not existing in routing (AFAIK)

    def __select_preset_path_during_rollback(self, rollback: bool, preset_path: Path) -> None:
        if preset_path.exists():
            if rollback:
                self.preset_class(preset_path, PresetType.NONE).select(already_locked=True, remove_previous=True,
                                                                       create_previous=False, allow_only_saved=False)
                if preset_path.is_symlink():
                    preset_path.unlink(missing_ok=False)
            else:
                self.__remove_symlink_or_dir(preset_path, ignore_errors=True)
        else:
            logger.error("Missing '{preset_path}' in select_preset_path_during_rollback")

    def __rollback_to_previous(self, rollback: bool) -> None:
        with self.preset_class.LOCK.transaction(f"{'rollback to previous' if rollback else 'remove previous'}"):
            self.__select_preset_path_during_rollback(rollback, self.preset_class.PREVIOUS)

    def __select_preset(self, preset_name: str, *, create_previous: bool, enable: bool) -> None:
        new_selected = self.preset_class(preset_name, PresetType.SAVED)
        if not new_selected.is_selected():
            new_selected.select(already_locked=True, create_previous=create_previous)
        if enable:
            self.preset_class.enable()
        else:
            self.preset_class.disable()

    def set_config(self, ask_for_affirmation: bool, config: Mapping[str, Any],
                   topic: str, from_part: bytes, message_id: bytes) -> Any:
        enabled = get_bool(config, "enabled")
        selected = get_optional_str(config, "selected")
        saved = get_dict(config, "saved")
        edited = get_dict(config, "edited")

        for key in edited:
            if key in saved:
                raise InvalidPayloadError(f"Same preset present in both saved and edited: {key}")

        if len(selected) > 0 and selected not in saved:
            raise InvalidPayloadError(f"Preset {key} is marked as selected but not present in saved presets")

        with self.preset_class.LOCK.transaction("set_config"):
            self.daemon_transaction.start(topic, self.__rollback_set_config_initialization, from_part, message_id)
            # In case something goes terribly wrong we set up currently selected (or
            # disabled) preset as totally external copy used for rescue purposes
            was_enabled = self.preset_class.is_enabled()
            if self.RESCUE.exists():
                rescue = self.preset_class(self.RESCUE, PresetType.NONE)
                shall_remove_rescue = False
                if not was_enabled:           # was not enabled, so is some garbage and for sure not needed
                    shall_remove_rescue = True
                if not rescue.is_selected():  # was not selected, so is some garbage and for sure not needed
                    shall_remove_rescue = True
                if shall_remove_rescue:
                    shutil.rmtree(self.RESCUE, ignore_errors=True)
            if was_enabled:
                was_selected = self.preset_class.current()
                if not self.RESCUE.exists():
                    shutil.copytree(was_selected.dir, self.RESCUE, symlinks=True)
                    (self.RESCUE / ".name").write_text(was_selected.name)
            else:
                self.generate_disabled_preset_action(self.RESCUE)

            # We don't want those mkdirs in __make_set_config_backup() so if they fail
            # we will not try to restore invalid backup
            self.SET_CONFIG_PREVIOUS_PRESETS.mkdir()
            self.SET_CONFIG_PREVIOUS_EDITS.mkdir()
            try:
                read_only_presets = self.__make_set_config_backup()
                self.add_presets_action(self.preset_class.SAVED_PARENT, saved, read_only_presets)
                self.add_presets_action(self.preset_class.EDITED_PARENT, edited)
            except Exception:
                try:
                    self.__restore_set_config_backup()
                except Exception as exc:
                    logger.exception(exc)
                raise

            response: Optional[str] = None
            if enabled:
                create_previous = False
                if ask_for_affirmation:
                    if was_enabled:
                        if was_selected.is_read_only():
                            if was_selected.name == selected:
                                self.daemon_transaction.commit()
                                return f"{RESPONSE_OK} New config set, no change in current state of {self.name}"
                            else:
                                # We can rollback to previous, because we are sure it won't change during update
                                self.daemon_transaction.set_final_action(self.__rollback_set_config_to_previous)
                                create_previous = True
                        else:
                            # Even if name is same, contents of preset could change, and ensuring that they did not would be
                            # quite hard --- hence we start transaction anyway, and use hard copy of previously selected
                            # preset as fallback option to ensure connectivity will be restorted
                            self.daemon_transaction.set_final_action(self.__rollback_set_config_to_previous_or_rescue)
                    else:
                        self.daemon_transaction.set_final_action(self.__rollback_set_config_to_disable)

                self.__select_preset(selected, create_previous=create_previous, enable=True)
                response = self.__reload()

                if ask_for_affirmation:
                    self.daemon_transaction.set_response(response)
                    return Async()
            else:
                self.__select_preset(selected, create_previous=False, enable=False)
            self.daemon_transaction.commit()
            return response

    def __make_set_config_backup(self) -> Sequence[str]:
        read_only_presets = list()
        for entry in self.preset_class.SAVED_PARENT.iterdir():
            if (entry / ".ro").exists():
                read_only_presets.append(entry.stem)
            else:
                entry.rename(self.SET_CONFIG_PREVIOUS_PRESETS / entry.stem)
        for entry in self.preset_class.EDITED_PARENT.iterdir():
            entry.rename(self.SET_CONFIG_PREVIOUS_EDITS / entry.stem)
        return read_only_presets

    def __remove_set_config_backup(self) -> None:
        shutil.rmtree(self.SET_CONFIG_PREVIOUS_PRESETS, ignore_errors=True)
        shutil.rmtree(self.SET_CONFIG_PREVIOUS_EDITS, ignore_errors=True)

    def __restore_set_config_backup(self) -> None:
        for entry in self.preset_class.SAVED_PARENT.iterdir():
            if not (entry / ".ro").exists():
                shutil.rmtree(entry)
        for entry in self.preset_class.EDITED_PARENT.iterdir():
            shutil.rmtree(entry)
        for entry in self.SET_CONFIG_PREVIOUS_PRESETS.iterdir():
            entry.rename(self.preset_class.SAVED_PARENT / entry.stem)
        for entry in self.SET_CONFIG_PREVIOUS_EDITS.iterdir():
            entry.rename(self.preset_class.EDITED_PARENT / entry.stem)
        self.SET_CONFIG_PREVIOUS_PRESETS.rmdir()
        self.SET_CONFIG_PREVIOUS_EDITS.rmdir()

    def __rollback_set_config_initialization(self, rollback: bool) -> None:
        self.__remove_set_config_backup()

    def __rollback_set_config_to(self, rollback: bool, rollback_action: Callable[[], None]) -> None:
        with self.preset_class.LOCK.transaction(f"{'rollback set config' if rollback else 'commit set config'}"):
            if rollback:
                try:
                    self.__restore_set_config_during_rollback()
                    rollback_action()
                except Exception as exc:
                    logger.error("Selecting rescue profile due to exception")
                    logger.exception(exc)
                    self.__select_preset_path_during_rollback(rollback, self.RESCUE)
            self.__remove_set_config_backup()

    def __to_named_in_rescue(self) -> None:
        if (self.RESCUE / ".name").exists():
            was_selected = self.preset_class((self.RESCUE / ".name").read_text(), PresetType.SAVED)
            if not was_selected.is_selected():
                was_selected.select(create_previous=False, already_locked=True)
            self.RESCUE.rename(self.preset_class.PREVIOUS)
            self.__remove_symlink_or_dir(self.preset_class.PREVIOUS)
        else:
            raise RuntimeError("Rescue does not contain original preset name")

    def __rollback_set_config_to_previous_or_rescue(self, rollback: bool) -> None:
        self.__rollback_set_config_to(rollback, self.__to_named_in_rescue)

    def __rollback_set_config_to_previous(self, rollback: bool) -> None:
        self.__rollback_set_config_to(rollback,
                                      lambda: self.__select_preset_path_during_rollback(rollback, self.preset_class.PREVIOUS))
        # TODO __select_preset_path_during_rollback does the same thing, but is
        # not called by __rollback_set_config_to in case rollback==False
        # We shall resolve this issue in a better way...
        if (not rollback) and self.preset_class.PREVIOUS.exists():
            self.__remove_symlink_or_dir(self.preset_class.PREVIOUS)

    def __rollback_set_config_to_disable(self, rollback: bool) -> None:
        self.__rollback_set_config_to(rollback, self.__disable)

    def __restore_set_config_during_rollback(self) -> None:
        if self.SET_CONFIG_PREVIOUS_PRESETS.exists():
            self.__restore_set_config_backup()
        else:
            raise RuntimeError("Missing SET_CONFIG_PREVIOUS_PRESETS in rollback_to_rescue")
