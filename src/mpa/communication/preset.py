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

# Standard imports
import enum
import shutil
from pathlib import Path
from tempfile import mkdtemp
from typing import Any, Callable, TypeAlias, Optional, Union

# Local imports
from mpa.common.logger import Logger
from mpa.communication.common import InvalidParameterError
from mpa.communication.common import InvalidPreconditionError
from mpa.communication.common import PLEASE_REPORT
from mpa.communication.inter_process_lock import InterProcessLock

# since version 1.5.0 mypy has a bug connected to NoReturn
# we will use alias to None until it is fixed
NoReturn: TypeAlias = None
logger = Logger(__name__)


class PresetType(enum.IntFlag):
    NONE = 0
    SAVED = 1
    EDITED = 2


class VerificationError(RuntimeError):
    pass


class CallerOfChildClassIsValid:
    def _call_is_valid_provided_by_child_class(self) -> bool:
        if 'is_valid' in dir(self):
            retval = self.is_valid()  # type: ignore
            assert isinstance(retval, bool)
            return retval
        else:
            # Coding error, so we want it reported
            raise RuntimeError("Missing verification function in {type(self)}")


class PresetHelpers:
    ENABLED: Path


class PresetBase(CallerOfChildClassIsValid):
    '''
    Base for basic preset actions.

    You need to inherit your preset from PresetBase and set three directories:
    SAVED_PARENT  --- directory in which saved (and ready to use presets are kept)
    EDITED_PARENT --- directory in  which potentially invalid presets are kept
                      (e.g. while user is modyfing them)
    LOCK          --- PresetLock object used to serialize actions which shall
                      not be performed simultaneously (like selcting a preset
                      and at the same time making it edited)
    CURRENT       --- path which will be symlink to currently selected preset
    PREVIOUS      --- path which will be symlink to previously selected preset
                      (allows easy rollbacks)
    '''
    SAVED_PARENT: Path
    EDITED_PARENT: Path
    LOCK: InterProcessLock
    CURRENT: Path
    PREVIOUS: Path
    ENABLED: Path

    def __init__(self, name: Union[Path, str],
                 requested_type: PresetType = (PresetType.EDITED | PresetType.SAVED),
                 *,
                 create: bool = False):
        self.dir: Path
        self.name: str
        self.type: PresetType
        if isinstance(name, Path):
            self.__init_from_path(name, requested_type, create=create)
        else:
            self.__init_from_str(name, requested_type, create=create)

    @classmethod
    def set_class_params(cls, *, saved_parent: Path, edited_parent: Path,
                         lock: InterProcessLock, current: Path, previous: Path,
                         enabled: Path) -> None:
        cls.SAVED_PARENT = saved_parent
        cls.EDITED_PARENT = edited_parent
        cls.LOCK = lock
        cls.CURRENT = current
        cls.PREVIOUS = previous
        cls.ENABLED = enabled

    @classmethod
    def is_enabled(cls) -> bool:
        return cls.ENABLED.exists()

    @classmethod
    def enable(cls) -> None:
        if not cls.is_enabled():
            if not cls.CURRENT.exists():
                raise InvalidPreconditionError("Unable to enable without any preset selected")
            cls.ENABLED.write_text(cls.CURRENT.stem)

    @classmethod
    def disable(cls) -> None:
        cls.ENABLED.unlink(missing_ok=True)

    @classmethod
    def current(cls) -> PresetBase:
        return cls(cls.CURRENT, PresetType.NONE)

    def __init_from_path(self, name: Path, requested_type: PresetType, *, create: bool) -> None:
        self.dir = name.resolve()
        self.name = self.dir.stem
        if self.dir.parent == self.SAVED_PARENT:
            self.type = PresetType.SAVED
        elif self.dir.parent == self.EDITED_PARENT:
            self.type = PresetType.EDITED
        elif requested_type == PresetType.NONE:
            self.type = requested_type
        else:
            # Coding error, hence RuntimeError
            raise RuntimeError("Type was requested but path does not belong to any")
        if requested_type != PresetType.NONE and not (self.type & requested_type):
            # Coding error, hence RuntimeError
            raise RuntimeError("Incompatible requested type and Path")
        if create:
            if self.type != PresetType.NONE:
                self.__create()
            else:
                self.dir.mkdir()

    def __init_from_str(self, name: str, requested_type: PresetType, *, create: bool) -> None:
        if requested_type == PresetType.NONE:
            # Coding error hence RuntimeError
            raise RuntimeError("Cannot create preset from str without preset type")
        self.name = name.strip()
        self.type = requested_type
        if create:
            self.__create()
        else:
            self.__set_dir()

    def __get_name_description(self, *, capitalized: bool = False) -> str:
        if len(self.name) > 0:
            return f"{'N' if capitalized else 'n'}ame '{self.name}'"
        return f"{'E' if capitalized else 'e'}mpty name"

    def __validate_preset_dir(self, parent_dir: Path, preset_dir: Path) -> None:
        if parent_dir / preset_dir.stem != preset_dir:
            raise InvalidParameterError(f"{self.__get_name_description(capitalized=True)} "
                                        "does not match preset name correctly "
                                        "(are there slashes in name?)")
        elif parent_dir == preset_dir:
            raise InvalidParameterError(f"{self.__get_name_description(capitalized=True)} "
                                        "does not match preset name correctly "
                                        "(is the name empty after removing special chars?)")

    def __raise_to_many_preset_names_matched(self, descriptor: str) -> NoReturn:
        if len(self.name) > 0:
            raise InvalidParameterError(f"More than one {descriptor} name matches '{self.__get_name_description()}'")
        raise InvalidParameterError(f"Name of preset was not provided, but there is more than one {descriptor}")

    def __raise_no_preset_matched(self, descriptor: str) -> NoReturn:
        if len(self.name) > 0:
            raise InvalidParameterError(f"No {descriptor} matches {self.__get_name_description()}")
        raise InvalidPreconditionError(f"There is no {descriptor}"
                                       " (name of preset was not given so any existing name would match)")

    def __raise_conflicting_state_error(self, description: str) -> NoReturn:
        raise InvalidPreconditionError(("Conflicting operation was exectuted concurrently with your request. "
                                        f"{description} "
                                        "If you are the only person modifying presets now"
                                        f"then this error shall not happen, if so {PLEASE_REPORT}?"))

    def __get_preset_dir(self, parent_dir: Path, descriptor: str) -> Optional[Path]:
        if len(self.name) > 0:
            iterator = parent_dir.glob(self.name)
        else:
            iterator = parent_dir.iterdir()
        try:
            retval = next(iterator)
        except StopIteration:
            return None
        self.__validate_preset_dir(parent_dir, retval)
        try:
            next(iterator)
        except StopIteration:
            return retval
        self.__raise_to_many_preset_names_matched(descriptor)
        return None

    def __generate_preset_dir(self, parent_dir: Path) -> Path:
        if len(self.name) < 1:
            raise InvalidParameterError("Preset name must not be empty")
        retval = parent_dir / self.name
        self.__validate_preset_dir(parent_dir, retval)
        return retval

    def __set_dir(self) -> None:
        saved = None
        edited = None
        selected = None
        tried = False
        if self.type & PresetType.SAVED:
            tried = True
            saved = self.__get_preset_dir(self.SAVED_PARENT, "saved preset")
        if self.type & PresetType.EDITED:
            tried = True
            edited = self.__get_preset_dir(self.EDITED_PARENT, "being edited preset")
        if not tried:
            # Coding error (did we extend preset types without adopting # __set_dir?)
            raise RuntimeError("Preset type unknown in __set_dir")
        if edited is None:
            selected_type = PresetType.SAVED
            selected = saved
        elif saved is None:
            selected_type = PresetType.EDITED
            selected = edited
        else:
            self.__raise_to_many_preset_names_matched("preset")
        if selected is None:
            descriptor = "preset"
            if self.type == PresetType.SAVED:
                descriptor = "saved preset"
            if self.type == PresetType.EDITED:
                descriptor = "preset being edited"
            self.__raise_no_preset_matched(descriptor)
        self.type = selected_type
        assert isinstance(selected, Path)
        self.dir = selected
        self.name = self.dir.stem

    def __generate_and_verify_creation_dir(self, to_create_type: PresetType) -> Path:
        saved = self.__generate_preset_dir(self.SAVED_PARENT)
        edited = self.__generate_preset_dir(self.EDITED_PARENT)
        if saved.exists() or edited.exists():
            raise InvalidPreconditionError(f"Preset '{saved.stem}' already exists")
        if to_create_type & PresetType.SAVED:
            return saved
        if self.type & PresetType.EDITED:
            return edited
        raise RuntimeError("Impossible happened --- unknown preset type")

    def __create(self) -> None:
        with self.LOCK.transaction("create"):
            self.dir = self.__generate_and_verify_creation_dir(self.type)
            self.dir.mkdir()

    def __dir_shall_exist_after_lock(self) -> None:
        if not self.dir.exists():
            self.__raise_conflicting_state_error("Preset no longer exists in expected state")

    def is_selected(self) -> bool:
        return self.dir.resolve() == self.CURRENT.resolve()

    def is_read_only(self) -> bool:
        return (self.dir / ".ro").exists()

    def make_writeable(self) -> None:
        (self.dir / ".ro").unlink(missing_ok=True)

    def remove(self) -> None:
        with self.LOCK.transaction(f"remove {self.name}"):
            self.__dir_shall_exist_after_lock()
            if self.is_selected():
                raise InvalidPreconditionError("Cannot remove currently selected preset")
            logger.debug(f"will remove {self.dir}")
            shutil.rmtree(self.dir)

    def edit(self) -> None:
        if self.type == PresetType.EDITED:
            raise InvalidPreconditionError(f"Preset '{self.name}' is already being edited")
        if self.is_read_only():
            raise InvalidPreconditionError(f"Preset '{self.name}' is read only")
        with self.LOCK.transaction(f"edit {self.name}"):
            self.__dir_shall_exist_after_lock()
            if self.is_selected():
                raise InvalidPreconditionError((f"Preset with {self.name} is currently selected one. Editing selected preset "
                                                "is not possible to avoid misleading state where currently applied rules "
                                                "(before editing started) were different from rules visible after some "
                                                "(not yet saved) editions. Please make a copy of selected preset (see "
                                                "option '-s' in preset create command), edit it then save and select the copy."))
            target_dir = self.__generate_preset_dir(self.EDITED_PARENT)
            if target_dir.exists():
                self.__raise_conflicting_state_error("Preset already changed state to being edited.")
            self.dir.rename(target_dir)

    def save(self, dest_name: Optional[str] = None, *,
             verifier: Optional[Callable[[Path], None]] = None) -> None:
        if self.type == PresetType.SAVED:
            raise InvalidPreconditionError(f"Preset with {self.name} is already saved")
        with self.LOCK.transaction(f"save {self.name} {dest_name}"):
            self.__dir_shall_exist_after_lock()
            if verifier is None:
                if not self._call_is_valid_provided_by_child_class():
                    raise InvalidPreconditionError("Unable to save preset which fails verification")
            else:
                verifier(self.dir)
            if dest_name is None or len(dest_name) < 1:
                target_dir = self.__generate_preset_dir(self.SAVED_PARENT)
                if target_dir.exists():
                    self.__raise_conflicting_state_error("Preset already changed state to saved.")
            else:
                self.name = dest_name
                target_dir = self.__generate_and_verify_creation_dir(PresetType.SAVED)
            self.dir.rename(target_dir)

    def select(self, *,
               create_previous: bool = True,
               remove_previous: bool = False,
               allow_only_saved: bool = True,
               already_locked: bool = False) -> None:
        if allow_only_saved and self.type != PresetType.SAVED:
            raise InvalidPreconditionError(f"Preset with {self.name} is not saved.")
        with self.LOCK.transaction(f"select {self.name}", already_locked=already_locked):
            self.__dir_shall_exist_after_lock()
            if self.PREVIOUS.exists() and not remove_previous:
                raise InvalidPreconditionError("Cannot select new preset while previous selection was not yet affirmed.")
            if self.is_selected():
                raise InvalidPreconditionError(f"Preset with {self.name} is already selected")
            if create_previous:
                self.CURRENT.rename(self.PREVIOUS)
            else:
                self.CURRENT.unlink(missing_ok=True)
            self.CURRENT.symlink_to(self.dir)
            if remove_previous and self.PREVIOUS.is_symlink():
                self.PREVIOUS.unlink(missing_ok=False)


class PresetChangeGuardBase(CallerOfChildClassIsValid):
    '''
    Allows to make changes to preset which will be rolled back if not commited
    (e.g. because while making changes error was raised) or if preset fails
    verification.

    Note that you shall inherit from this class and provide verify() -> bool
    function which will return true if preset is correct.

    There are 2 types of rollback:
    1. This is totally new preset --- we will just notice it in __enter__ and
       rollback will remove its directory
    2. This is existing preset being modified --- we will make backup copy of
       preset in __enter__ and rollback will restore preset from that copy.
    '''
    def __init__(self, preset: Path):
        self.path = preset
        self.backup_made = False
        # We coud test for self.backup is None instead of backup_dir_empty but
        # this way shows code intentions clearer to the reader
        self.backup_dir_empty = True
        self.tmpdir: Optional[Path] = None
        self.backup: Optional[Path] = None

    def __enter__(self) -> PresetChangeGuardBase:
        if self.backup_made:
            raise RuntimeError("Recursive guard not supported")
        if self.path.exists():
            self.tmpdir = Path(mkdtemp())
            self.backup = self.tmpdir / "backup"
            shutil.copytree(self.path, self.backup, symlinks=True)
            self.backup_dir_empty = False
        else:
            self.path.mkdir()
            self.backup_dir_empty = True
        self.backup_made = True
        return self

    def __exit__(self, exception_type: Any, exception_value: Any, tb: Any) -> None:
        error: Optional[Exception] = None
        try:
            if tb is None:
                if self._call_is_valid_provided_by_child_class():
                    # All OK --- no roll back
                    return
                # If this happens we failed to give more detailed information on
                # what is wrong with user input, hence we usally want it
                # reported by user to add detection of unpredicted way of
                # breaking config
                error = VerificationError("Preset failed verification")
            # Either we exit due to exception or is_valid is False --- rollback is needed
            self.rollback()
        except Exception as exc:
            if error is None:
                error = exc
        finally:
            self.__cleanup()
        if error is not None:
            raise error

    def __cleanup(self) -> None:
        if self.tmpdir and self.tmpdir.exists():
            shutil.rmtree(self.tmpdir)
            self.tmpdir = None
            self.backup = None
        self.backup_dir_empty = True
        self.backup_made = False

    def __ensure_backup(self, message: str) -> None:
        if self.backup_dir_empty:
            # If this happens we have some error in code or some strange issues with device (like no space on disk...)
            raise RuntimeError(message)

    def rollback(self) -> None:
        if self.backup_made:
            if self.backup_dir_empty:
                shutil.rmtree(self.path)
            else:
                self.copy_backup_to(self.path)

    def restore_main_notes(self) -> None:
        self.__ensure_backup("Cannot restore from non-existing backup")
        assert self.backup is not None
        path_main_notes_file = self.path / ".notes"
        backup_main_notes_file = self.backup / ".notes"
        path_main_notes_file.unlink(missing_ok=True)
        if backup_main_notes_file.exists():
            shutil.copy(backup_main_notes_file, path_main_notes_file)

    def copy_backup_to(self, dest: Path) -> None:
        self.__ensure_backup("Cannot copy non-existing backup")
        assert self.backup is not None
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(self.backup, dest, symlinks=True)
