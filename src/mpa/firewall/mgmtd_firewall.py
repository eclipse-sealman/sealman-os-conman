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
"""
Daemon responsible for network firewall configuration.
"""

from __future__ import annotations

# Standard imports
import argparse
import ipaddress
import json
import shutil
import sys
from pathlib import Path
from subprocess import CalledProcessError
from typing import Any, Callable, Container, Mapping, MutableMapping, MutableSequence, Optional, Sequence, Union

# Local imports
import mpa.communication.topics as topics
from mpa.common.common import RESPONSE_OK, add_or_merge
from mpa.communication import client as com_client
from mpa.communication.client import guarded
from mpa.communication.client import sync
from mpa.communication.common import InvalidParameterError
from mpa.communication.common import InvalidPayloadError
from mpa.communication.common import InvalidPreconditionError
from mpa.communication.common import get_system_network_interfaces
from mpa.communication.daemon_transaction import DaemonTransaction
from mpa.common.logger import Logger
from mpa.communication.affirmable_preset_actions import AffirmablePresetActionsBase, ROLLBACK_WARNING
from mpa.communication.message_parser import (get_bool,
                                              get_dict,
                                              get_str,
                                              get_optional_ip4_with_optional_mask,
                                              get_optional_ip6_with_optional_mask,
                                              get_optional_port,
                                              get_optional_str,
                                              get_optional_enum_str,
                                              get_str_with_default,
                                              get_list)
from mpa.communication.preset import PresetBase
from mpa.communication.preset import PresetChangeGuardBase
from mpa.communication.preset import PresetType
from mpa.communication.preset import VerificationError
from mpa.communication.inter_process_lock import InterProcessLock
from mpa.communication.process import run_command
from mpa.communication.status_codes import FIREWALL_PROTOCOLS
from mpa.config.configfiles import ConfigFiles


logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

_parser = argparse.ArgumentParser(prog='Firewall config daemon')
com_client.add_command_line_params(_parser)
_args = _parser.parse_args()
_client = com_client.Client(args=_args)

_firewall_transaction = DaemonTransaction(f"Connectivity confirmation was not received. Warning: {ROLLBACK_WARNING}", _client)

NFT = ["pkexec",  "/usr/sbin/nft"]
IPTABLES = ["sudo", "/usr/sbin/iptables"]
config_files = ConfigFiles()
NFT_CONF = config_files.add("nft_main_config", "nftables.conf")
NFT_DIR = config_files.add("nft_config_dir", "nft")
ENABLED = config_files.add("nft_enabled_flag", NFT_DIR / "enabled", is_expected=False)
CURRENT = config_files.add("nft_current_preset_link", NFT_DIR / "current")
PREVIOUS = config_files.add("nft_previous_preset_link", NFT_DIR / "previous", is_expected=False)
STATE_CHANGE = NFT_DIR / "state_change"
RESCUE = NFT_DIR / "rescue"
PRESETS = config_files.add("nft_presets_dir", NFT_DIR / "presets")
ALLOW_ALL = config_files.add("nft_allow_all_preset", PRESETS / "allow_all")
DEFAULT_PRESET = config_files.add("nft_default_preset", PRESETS / "default")
DISABLED = config_files.add("nft_disabled_preset", PRESETS / "disabled")
EDITS = config_files.add("nft_edited_presets_dir", NFT_DIR / "edits")
SET_CONFIG_PREVIOUS_PRESETS = NFT_DIR / "set_config_previous_presets"
SET_CONFIG_PREVIOUS_EDITS = NFT_DIR / "set_config_previous_edits"
config_files.verify()
INITIALLY_CREATED_AS = "Initially created as "
INVALID_FIRST_CHARS_OF_PART = ['.', '/']
RULE_COMMANDS = ["add", "remove", "edit", "comment", "uncomment"]

LOCK = InterProcessLock(Path(NFT_DIR / "lock"))

######################
# We have following levels of safety checks:
#
# firewall_transaction --- single process transaction status --- as long as
# daemon does not break this allows to perform correct rollback
#
# LOCK --- inter process short term lock for action which affect presets if we
# accidentally start more than one daeon with ability to change presets it shall
# serialize actions performed by daemons,
#
# PREVIOUS and SET_CONFIG_PREVIOUS_* --- inter process marks that transaction
# was started, if we start transaction and crash before it is commited or rolled
# back, or if there are 2 active daemons at the same time this allows us to
# prevent starting new long time transaction before old one is finished
#
# To enable faster commit in case daemon did not crash there is commit method,
# and to to deal with crashes there is cleanup method.
######################


class Preset(PresetBase):
    def is_valid(self) -> bool:
        return is_nft_config_valid(self.dir)


Preset.set_class_params(saved_parent=PRESETS,
                        edited_parent=EDITS,
                        lock=LOCK,
                        enabled=ENABLED,
                        current=CURRENT,
                        previous=PREVIOUS)


def nft_preset_execute_options(preset_dir: Path) -> Sequence[Any]:
    return ("-I", preset_dir, "-f", NFT_CONF)


# TODO add test config
class PresetChangeGuard(PresetChangeGuardBase):
    def is_valid(self) -> bool:
        return is_nft_config_valid(self.path)


class AffirmableFirewallActions(AffirmablePresetActionsBase):
    pass


AffirmableFirewallActions.set_class_params(preset_class=Preset,
                                           state_change_transaction_marker=STATE_CHANGE,
                                           rescue_preset_path=RESCUE,
                                           backup_saved_presets_path=SET_CONFIG_PREVIOUS_PRESETS,
                                           backup_edited_presets_path=SET_CONFIG_PREVIOUS_EDITS)


def is_nft_config_valid(preset_dir: Path) -> bool:
    try:
        run_command(*NFT, '--check', *nft_preset_execute_options(preset_dir))
        return True
    except CalledProcessError as exc:
        logger.info(f"failed nft verification\nstdout:\n{exc.stdout}\nstderr\ni{exc.stderr}")
        return False


def reload_action() -> None:
    if Preset.is_enabled():
        run_command(*NFT, *nft_preset_execute_options(CURRENT))
    else:
        run_command(*NFT, "flush", "ruleset")


def generate_disabled_preset(target: Path) -> None:
    shutil.copytree(DISABLED, target, symlinks=True)


def add_presets_action(parent_dir: Path, new_presets: Mapping[str, Any], excluded: Container[str] = list()) -> None:
    for name, value in new_presets.items():
        if name in excluded:
            continue
        new_preset_dir = parent_dir / name
        if new_preset_dir.exists():
            raise InvalidPayloadError(f"Preset '{name}' already exists so cannot be added")
        try:
            with PresetChangeGuard(new_preset_dir):
                fill_preset_from_dict(new_preset_dir, value)
        except VerificationError:
            raise InvalidPayloadError(f"Preset '{name}' failed verification")


affirmable_firewall_transaction = AffirmableFirewallActions("Firewall",
                                                            _firewall_transaction,
                                                            reload_action,
                                                            generate_disabled_preset,
                                                            add_presets_action)


def get_config_or_show(*, terse: bool) -> Mapping[str, Any]:
    config: MutableMapping[str, Any] = dict()
    config['enabled'] = Preset.is_enabled()
    config['selected'] = CURRENT.resolve().stem
    saved: MutableMapping[str, Sequence[str]] = {}
    if terse:
        saved.update(single_preset_print(CURRENT.resolve(), ''))
    else:
        for entry in PRESETS.iterdir():
            saved.update(single_preset_print(entry, ''))
        edited: MutableMapping[str, Sequence[str]] = {}
        for entry in EDITS.iterdir():
            edited.update(single_preset_print(entry, ''))
        config['edited'] = edited
    config['saved'] = saved
    return {"firewall": config}


def get_config(message: bytes) -> Mapping[str, Any]:
    if message:
        logger.warning(f"Non empty message received by get_config(): {message!r}")
    return get_config_or_show(terse=False)


def show(message: bytes) -> Mapping[str, Any]:
    if message:
        logger.warning(f"Non empty message received by show(): {message!r}")
    return get_config_or_show(terse=True)


def set_config(message: bytes, from_part: bytes, message_id: bytes) -> Any:
    config = json.loads(message)
    ask_for_affirmation = get_bool(config, "ask_for_affirmation")
    firewall_config = get_dict(config, "firewall")
    return affirmable_firewall_transaction.set_config(ask_for_affirmation, firewall_config, topics.net.filter.set_config,
                                                      from_part, message_id)


def preset_select(message: bytes, from_part: bytes, message_id: bytes) -> Any:
    transaction: Mapping[str,  str] = json.loads(message)
    ask_for_affirmation = get_bool(transaction, "ask_for_affirmation")
    preset = Preset(get_optional_str(transaction, "name"), PresetType.SAVED)
    return affirmable_firewall_transaction.select(
        ask_for_affirmation,
        preset,
        topics.net.filter.preset.select,
        from_part,
        message_id
    )


def preset_create(message: bytes) -> None:
    transaction: Mapping[str,  str] = json.loads(message)
    source = get_optional_str(transaction, "source")
    if len(source) > 0:
        source_dir = Preset(source, PresetType.SAVED).dir
    else:
        source_dir = DEFAULT_PRESET
    new_preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED, create=True)
    main_notes_file = new_preset.dir / ".notes"
    new_preset.dir.rmdir()
    shutil.copytree(source_dir, new_preset.dir, symlinks=True)
    main_notes_file.write_text(f"{INITIALLY_CREATED_AS}copy of {source_dir.stem}\n")
    new_preset.make_writeable()


def preset_delete(message: bytes) -> None:
    transaction: Mapping[str,  str] = json.loads(message)
    try:
        preset: Optional[Preset] = None
        preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED)
    except Exception as exc:
        if preset is not None and len(preset.name) > 0 and (PRESETS / preset.name).exists():
            logger.exception(exc)
            raise InvalidPreconditionError("If you want to delete saved preset you need to mark it as editable first")
        raise exc
    preset.remove()


def preset_edit(message: bytes) -> str:
    transaction: Mapping[str,  str] = json.loads(message)
    preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED | PresetType.SAVED)
    preset.edit()
    return f"{RESPONSE_OK} Preset {preset.name} can be edited now"


# TODO extract common code with routing.py
def preset_save(message: bytes) -> str:
    transaction: Mapping[str,  str] = json.loads(message)
    preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED)
    destination = get_optional_str(transaction, 'destination')
    if len('destination') > 0:
        orig_name = preset.name
        preset.save(destination)
        return f"{RESPONSE_OK} Preset {orig_name} saved as {preset.name}"
    else:
        preset.save()
        return f"{RESPONSE_OK} Preset {preset.name} is now saved"


def preset_list(message: bytes) -> Mapping[str, Sequence[str]]:
    transaction: Mapping[str,  str] = json.loads(message)
    name = get_str_with_default(transaction, "name", default='*')
    retval = {}
    retval["saved"] = [entry.stem for entry in PRESETS.glob(name)]
    retval["being_edited"] = [entry.stem for entry in EDITS.glob(name)]
    return retval


def append_or_create(parent: MutableMapping[str, MutableSequence[str]], parent_key: str, value: str) -> None:
    if parent_key not in parent:
        parent[parent_key] = []
    parent[parent_key].append(value)


class InvalidConfig(Exception):
    def __init__(self, part_dir: Path, encapsulated: Exception):
        self.part_dir = part_dir
        self.encapsulated = encapsulated


def subparts_print(part_dir: Path) -> Optional[Mapping[str, Any]]:
    try:
        retval: MutableMapping[str, Any] = {}
        for entry in part_dir.glob('*'):
            if entry.is_dir():
                entry_out = subparts_print(entry)
                if entry_out is not None:
                    add_or_merge(retval, {entry.stem: entry_out})
            if entry.is_file():
                # We have few special nodes:
                # * notes --- we can have it both on directory level (as hidden
                #             .notes file) or on rule level (as rule_name.notes
                #             file next to rule_name.conf file) --- having notes
                #             in both places for same part is an error (and we
                #             will raise exception if we detect it). It may
                #             happen only via manual (e.g. as root) tweaking of
                #             preset
                # * based_on, as_of --- present only for currently selected
                #             preset (accessed via get_config) we use hidden
                #             file .based_on for it and do not expect it
                #             anywhere else, so if some preset contains such
                #             hidden file (created e.g. manually as root) as
                #             well as part/rule with same name as those special
                #             nodes we will raise error
                if entry.name in ('.allow_conf', '.ro', ".devices"):
                    pass
                elif entry.name == '.notes':
                    add_or_merge(retval, {'notes':  entry.read_text().strip()})
                elif entry.name == '.based_on':
                    add_or_merge(retval, {'based_on':  entry.read_text().strip()})
                    add_or_merge(retval, {'as_of':  entry.stat().st_mtime})
                elif entry.suffix == '.conf':
                    add_or_merge(retval, {entry.stem: {'contents': entry.read_text().strip()}})
                elif entry.suffix == ".ingress":
                    add_or_merge(
                        retval, {entry.stem: {'devices': json.loads((entry.parent / entry.stem / ".devices").read_text())}}
                    )
                elif entry.suffix == '.notes':
                    add_or_merge(retval, {entry.stem: {'notes': entry.read_text().strip()}})
                elif entry.name == 'policy_conf':
                    add_or_merge(retval, {'policy': entry.read_text().strip().rpartition(' ')[2]})
                else:
                    append_or_create(retval, 'hidden', entry.name)
        if len(retval) > 0:
            return retval
        return None
    except InvalidConfig:
        raise
    except Exception as exc:
        logger.error(f"Failed reading config {part_dir}: {exc}")
        raise InvalidConfig(part_dir, exc)


def fill_dir_notes(part_dir: Path, value: str) -> None:
    notes_file = part_dir / '.notes'
    notes_file.write_text(value + "\n")


def fill_preset_from_dict(preset_dir: Path, config: Mapping[str, Any]) -> None:
    for element in ALLOW_ALL.iterdir():
        if element.is_dir():
            shutil.copytree(element, preset_dir / element.name, symlinks=True)
    based_on_file = preset_dir / '.based_on'
    for key, value in config.items():
        if key == "based_on":
            based_on_file.write_text(f"External copy of: {value}\n")
        elif key == "as_of":
            pass
        elif key == "notes":
            fill_dir_notes(preset_dir, value)
        else:
            validate_part_name(key)
            fill_subpart_from_dict(preset_dir, Path(key), value)


def validate_part_name(name: str) -> None:
    if not name or len(name) == 0:
        raise InvalidParameterError("Part name cannot be empty")
    if name[0] in INVALID_FIRST_CHARS_OF_PART:
        raise InvalidParameterError(f"Part name cannot start with {name[0]}")


def fill_subpart_from_dict(preset_dir: Path, part: Path, config: Mapping[str, Any]) -> None:
    if part == Path("netdev"):
        part = Path("netdev/ingress")
        config = config["ingress"]
        for chain_name, chain_config in config.items():
            create_ingress_chain(preset_dir, chain_name, set(chain_config["devices"]))

    part_dir = preset_dir / part
    if not part_dir.exists():
        raise InvalidParameterError(f"Unrecognized part in config: {part}")
    allow_conf = (part_dir / ".allow_conf").exists()
    try:
        for key, value in config.items():
            if (part_dir / key).exists():
                fill_subpart_from_dict(preset_dir, part / key, value)
            elif key == 'policy':
                set_policy(preset_dir, part, value)
            elif key == 'notes':
                fill_dir_notes(part_dir, value)
            elif allow_conf:
                validate_part_name(key)
                fill_leaf(part_dir, key, value)
    except InvalidConfig:
        raise
    except Exception as exc:
        logger.error(f"Invalid config at part {part}: {exc}")
        raise InvalidConfig(part, exc)


def fill_leaf(part_dir: Path, rule_name: str, config: Mapping[str, str]) -> None:
    if 'contents' not in config:
        raise RuntimeError(f"Missing contents in {rule_name}")
    for key, value in config.items():
        if key == 'contents':
            validate_rule_contents(value)
            out_file = part_dir / f"{rule_name}.conf"
        elif key == 'notes':
            out_file = part_dir / f"{rule_name}.notes"
        else:
            raise RuntimeError(f"Unrecognized key {key}")
        out_file.write_text(value + "\n")


def single_preset_print(preset_dir: Path, part: str) -> Mapping[str, Any]:
    try:
        guard = PresetChangeGuard(preset_dir)
        if guard.is_valid():
            key = ''
        else:
            key = '!'
        part_dir = preset_dir / part
        if part and len(part) > 0:
            key += f"{preset_dir.stem}/{part}"
        else:
            key += preset_dir.stem
        if part_dir.exists() and part_dir.is_dir():
            return {key: subparts_print(part_dir)}
        return {key: None}
    except InvalidConfig as exc:
        # We failed verification it change guard or other place, this shall not
        # happen, so RuntimeError
        message = f"Invalid preset {preset_dir.stem}: in {exc.part_dir.relative_to(preset_dir)}: {str(exc.encapsulated)}"
        raise RuntimeError(message)


def preset_print(message: bytes) -> Mapping[str, Sequence[str]]:
    transaction: Mapping[str,  str] = json.loads(message)
    # We don't use get_str_with_default for name  because we differentiate between no name
    # at all and name given as '*' in error messages to make them more user friendly
    name = get_optional_str(transaction, "name")
    editable_only = get_bool(transaction, "editable_only")
    part = get_optional_str(transaction, "part")
    if editable_only:
        preset = Preset(name, PresetType.EDITED)
        return single_preset_print(preset.dir, part)
    # We set name to '*' now to get nicer error reports from Preset() above
    if len(name) < 1:
        name = '*'
    retval: MutableMapping[str, Sequence[str]] = {}
    for entry in PRESETS.glob(name):
        retval.update(single_preset_print(entry, part))
    for entry in EDITS.glob(name):
        retval.update(single_preset_print(entry, part))
    if len(retval) == 0:
        raise InvalidPreconditionError(f"There is no preset matching name '{name}'")
    return retval


def is_part_conf_file(part: Path) -> bool:
    conf_file = part.with_suffix('.conf')
    if conf_file.exists() and conf_file.is_file():
        return True
    return False


def shall_append_action(main_notes_file: Path) -> bool:
    if not main_notes_file.exists():
        return False
    with open(main_notes_file) as mnf:
        first_line = mnf.readline(len(INITIALLY_CREATED_AS))
        if first_line.startswith(INITIALLY_CREATED_AS):
            return True
    return False


def modify_action(preset_dir: Path, action: str) -> None:
    main_notes_file = preset_dir / ".notes"
    if not shall_append_action(main_notes_file):
        return
    with open(main_notes_file, "a") as mnf:
        mnf.write(action)
        mnf.write("\n")


def modify_copy(message: bytes) -> None:
    transaction: Mapping[str,  str] = json.loads(message)
    preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED)
    source = Preset(get_optional_str(transaction, "source"))
    part = get_optional_str(transaction, "part")
    part_dir = source.dir / part
    if not part_dir.exists():
        if is_part_conf_file(part_dir):
            raise InvalidParameterError("Copy does not work on individual rule level")
        raise InvalidPreconditionError(f"Part '{part}' does not exist in preset {source.name}")
    if not part_dir.is_dir():
        raise InvalidPreconditionError(f"Name '{part}' does not point to a copyable part in {source.name}")
    with PresetChangeGuard(preset.dir) as guard:
        # If we migrate to python3.8 we can use copytree here...
        # shutil.copytree(part_dir, preset.dir / part, symlinks=True, dirs_exist_ok=True)
        run_command("cp", "-a", part_dir, preset.dir / part)
        guard.restore_main_notes()
        modify_action(preset.dir, f"Added copy of {source.name}/{part}")


def modify_erase(message: bytes) -> None:
    transaction: Mapping[str,  str] = json.loads(message)
    preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED)
    part = get_optional_str(transaction, "part")
    source_dir = ALLOW_ALL
    part_dir = preset.dir / part
    if not source_dir.exists():
        raise RuntimeError("Impossible happened, allow_all preset does not exist")
    if not part_dir.exists():
        if not is_part_conf_file(part_dir):
            raise InvalidPreconditionError(f"Unable to erase non-existing part {part} of preset {preset.name}")
        # Removal of files in directory
        with PresetChangeGuard(preset.dir):
            for to_remove in part_dir.parent.glob(f"{part_dir.name}.*"):
                modify_action(preset.dir, f"Erased /{to_remove.relative_to(preset.dir)}")
                to_remove.unlink(missing_ok=False)
        return
    if not part_dir.is_dir():
        raise InvalidPreconditionError(f"Name '{part}' does not point to a removable part in {preset.name}")
    # Removal of directory tree
    with PresetChangeGuard(preset.dir):
        modify_action(preset.dir, f"Erased /{part}")
        shutil.rmtree(preset.dir / part)
        if (source_dir / part).exists():
            shutil.copytree(source_dir / part,  preset.dir / part, symlinks=True)


def set_policy_in_policy_conf(policy_conf: Path, policy: str) -> None:
    if policy not in ("accept", "drop"):
        raise RuntimeError(f"Unknown policy: {policy}")
    policy_conf.write_text(f"policy {policy}\n")


def get_policy(part_dir: Path) -> str:
    policy_conf = part_dir / "policy_conf"
    if not policy_conf.exists():
        raise NoPolicyInPartError(part_dir)
    policy = policy_conf.read_text().strip()
    if policy not in ("policy accept", "policy drop"):
        raise RuntimeError(f"Unknown policy: {policy}")
    return policy


def set_policy(preset_dir: Path, part: Union[str, Path], policy: str) -> None:
    policy_conf = preset_dir / part / "policy_conf"
    if not policy_conf.exists():
        raise InvalidPreconditionError(f"Part {part} has no settable policy")
    set_policy_in_policy_conf(policy_conf, policy)


def modify_policy(message: bytes) -> Sequence[str]:
    transaction: Mapping[str,  str] = json.loads(message)
    preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED)
    part = get_optional_str(transaction, "part")
    if part == "postrouting" or part == "prerouting":
        part = "ip/nat/" + part
    if part == "input" or part == "output" or part == "forward":
        part = "inet/filter/" + part
    if part == "filter":
        part = "inet/" + part
    if part == "nat":
        part = "ip/" + part
    policy = get_str(transaction, "policy")
    recursive = get_bool(transaction, "recursive")
    if not recursive:
        with PresetChangeGuard(preset.dir):
            set_policy(preset.dir, part, policy)
            modify_action(preset.dir, f"Set policy {policy} to /{part}")
        return [part]
    retval = []
    with PresetChangeGuard(preset.dir):
        for policy_conf in (preset.dir / part).glob('**/policy_conf'):
            set_policy_in_policy_conf(policy_conf, policy)
            modify_action(preset.dir, f"Set policy {policy} to /{policy_conf.parent.relative_to(preset.dir)}")
            retval.append(str(policy_conf.relative_to(preset.dir).parent))
    if len(retval) == 0:
        raise InvalidPreconditionError(f"No policy matched recursively part {part}")
    return retval


def validate_command(command: str) -> None:
    if command not in RULE_COMMANDS:
        raise RuntimeError(f"Unknown rule command {command}")


def validate_rule_and_action(command: str, rule_match: str, rule_action: str) -> None:
    if command == "add":
        if len(rule_match) == 0 or len(rule_action) == 0:
            raise InvalidParameterError("Cannot add rule without a match and action")
    if len(rule_match) == 0:
        if len(rule_action) == 0:
            return
        raise InvalidParameterError("You cannot provide action without match")
    if len(rule_action) == 0:
        raise InvalidParameterError("You cannot provide match without action")


def validate_match_interdeps(protocol: str,
                             source_port: str,
                             source_ip: Optional[ipaddress.IPv4Network],
                             source_ip6: Optional[ipaddress.IPv6Network],
                             destination_port: str,
                             destination_ip: Optional[ipaddress.IPv4Network],
                             destination_ip6: Optional[ipaddress.IPv6Network]) -> None:
    PORT_PROTOCOLS = ("tcp", "udp", "udplite", "sctp", "dccp")
    if len(destination_port) or len(source_port):
        if len(protocol):
            if protocol not in PORT_PROTOCOLS:
                raise InvalidParameterError(f"Ports can be used only in protocols {PORT_PROTOCOLS}")
            if protocol == "ip":
                if source_ip6 or destination_ip6:
                    raise InvalidParameterError("Mixing IPv4 protocol and IPv6 address in single rule is not allowed")
            if protocol == "ip6":
                if source_ip or destination_ip:
                    raise InvalidParameterError("Mixing IPv6 protocol and IPv4 address in single rule is not allowed")
    if source_ip or destination_ip:
        if source_ip6 or destination_ip6:
            raise InvalidParameterError("Mixing IPv4 and IPv6 address in single rule is not allowed")


def validate_single_line(text: str, what: str) -> None:
    if text.find('\n') != -1:
        raise InvalidPayloadError("New line is not allowed in {what}")


def validate_rule_match(match: str) -> None:
    validate_single_line(match, "rule_match")


def validate_rule_action(action: str) -> None:
    validate_single_line(action, "rule_action")


def validate_rule_contents(rule: str) -> None:
    validate_single_line(rule, "contents")


def validate_add_or_modify(command: str, rule: str, conf_file: Path) -> None:
    if command == "add":
        if conf_file.exists():
            raise InvalidPreconditionError(f"Cannot add existing rule {rule}")
    else:
        if not conf_file.exists():
            raise InvalidPreconditionError(f"Cannot {command} non-existing rule {rule}")


def perform_single_rule_remove(preset: Preset, notes_file: Path, conf_file: Path, *, partial_remove: bool = False) -> None:
    def remove() -> None:
        notes_file.unlink(missing_ok=True)
        conf_file.unlink(missing_ok=True)
    if partial_remove:
        remove()
        return
    # Normal independend remove of part
    with PresetChangeGuard(preset.dir):
        remove()
        modify_action(preset.dir, f"Removed rule {conf_file}")
        return


class NoPolicyInPartError(RuntimeError):
    pass


def modify_single_rule(part: str, message: bytes) -> None:
    transaction: Mapping[str,  str] = json.loads(message)
    preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED)
    rule_name = get_str(transaction, "rule_name")
    command = get_str(transaction, "command")
    notes = get_optional_str(transaction, 'notes')
    # Rule specific data
    verdict = get_optional_str(transaction, "verdict")
    protocol = get_optional_enum_str(transaction, "protocol", FIREWALL_PROTOCOLS)
    source_port = get_optional_port(transaction, "source_port")
    destination_port = get_optional_port(transaction, "destination_port")
    source_ip = get_optional_ip4_with_optional_mask(transaction, "source_ip")
    destination_ip = get_optional_ip4_with_optional_mask(transaction, "destination_ip")
    source_ip6 = get_optional_ip6_with_optional_mask(transaction, "source_ip6")
    destination_ip6 = get_optional_ip6_with_optional_mask(transaction, "destination_ip6")
    related = get_bool(transaction, "related")
    known_interfaces = get_system_network_interfaces()
    input_interface = get_optional_enum_str(transaction, "input_interface", known_interfaces)
    output_interface = get_optional_enum_str(transaction, "output_interface", known_interfaces)
    raw_match = get_optional_str(transaction, 'raw_match')
    raw_action = get_optional_str(transaction, 'raw_action')

    # Validate things needed always
    validate_part_name(rule_name)
    validate_command(command)
    part_dir = preset.dir / part
    if not part_dir.exists():
        raise InvalidPreconditionError(f"Part {part} does not exist!")
    # TODO name generation duplication with fill_leaf
    conf_file = part_dir / f"{rule_name}.conf"
    notes_file = part_dir / f"{rule_name}.notes"
    validate_add_or_modify(command, f"{part}/{rule_name}", conf_file)

    if command == "remove":
        perform_single_rule_remove(preset, notes_file, conf_file)
        return
    if command == "comment" or command == "uncomment":
        # TODO add implementation
        raise RuntimeError(f"Command {command} is not implemented yet")

    # We are adding new, or changing existing rule
    validate_match_interdeps(protocol,
                             source_port, source_ip, source_ip6,
                             destination_port, destination_ip, destination_ip6)

    rule_match = raw_match
    options_notes = ""
    if len(input_interface):
        options_notes += f"input_interface: {input_interface}; "
        rule_match += f" iifname {input_interface}"
    if len(output_interface):
        options_notes += f"output_interface: {output_interface}; "
        rule_match += f" oifname {output_interface}"
    if len(protocol):
        options_notes += f"protocol: {protocol}; "
        if len(source_port) + len(destination_port) > 0:
            rule_match += f" {protocol}"
            if len(source_port):
                options_notes += f"source_port: {source_port}; "
                rule_match += f" sport {source_port}"
            if len(destination_port):
                options_notes += f"destination_port: {destination_port}; "
                rule_match += f" dport {destination_port}"
        elif protocol in ("ip", "ip6"):
            if (source_ip or destination_ip or source_ip6 or destination_ip6):
                # We will specify adddress, so no need for separate match
                pass
            elif protocol == "ip":
                rule_match += " meta nfproto ipv4"
            elif protocol == "ip6":
                rule_match += " meta nfproto ipv6"
            else:
                raise RuntimeError("Coding error (missing elif branch for {protocol}?)")
        else:
            rule_match += f" meta l4proto {protocol}"
    elif len(source_port) or len(destination_port):
        rule_match += " meta l4proto {tcp, udp}"
        if len(source_port):
            options_notes += f"source_port: {source_port}; "
            rule_match += f" th sport {source_port}"
        if len(destination_port):
            options_notes += f"destination_port: {destination_port}; "
            rule_match += f" th dport {destination_port}"
    if source_ip or destination_ip:
        if protocol != "ip":
            rule_match += " ip"
        if source_ip:
            options_notes += f"source_ip: {source_ip}; "
            rule_match += f" saddr {source_ip}"
        if destination_ip:
            options_notes += f"destination_ip: {destination_ip}; "
            rule_match += f" daddr {destination_ip}"
    elif source_ip6 or destination_ip6:
        if protocol != "ip6":
            rule_match += " ip6"
        if source_ip6:
            options_notes += f"source_ip6: {source_ip6}; "
            rule_match += f" saddr {source_ip6}"
        if destination_ip6:
            options_notes += f"destination_ip6: {destination_ip6}; "
            rule_match += f" daddr {destination_ip6}"
    if related:
        options_notes += "only related; "
        rule_match += " ct state {related, established}"

    if len(rule_match) and len(verdict) == 0 and len(raw_action) == 0:
        try:
            policy = get_policy(part_dir.parent)
        except NoPolicyInPartError:
            raise InvalidParameterError("Verdict must be given explicitly for parts which do not have policy (like `common`)")
        if policy == "policy accept":
            verdict = "drop"
        elif policy == "policy drop":
            verdict = "accept"
        else:
            raise RuntimeError("Unable to deduce verdict")
    rule_action = raw_action + " " + verdict

    validate_rule_and_action(command, rule_match, rule_action)

    if len(rule_match) == 0 and len(notes) == 0:
        raise InvalidParameterError("Nothing to do")

    try:
        with PresetChangeGuard(preset.dir):
            if len(rule_match):
                # Match and action are needed only for add and edit
                validate_rule_match(rule_match)
                validate_rule_action(rule_action)
                conf_file.write_text(f"{rule_match} {rule_action}\n")
            if len(notes):
                notes_file.write_text(notes + "\n")
            if len(notes) > 0:
                extended_notes = f"{notes}\n"
            else:
                extended_notes = options_notes
            extended_notes += "Generated by net.filter.modify\n"
            if (not notes_file.exists()) or len(notes) > 0 or command == "edit":
                notes_file.write_text(extended_notes)
            modify_action(preset.dir, f"Executed {command} on rule {part}/{rule_name}")
    except VerificationError:
        if len(raw_action) or len(raw_match):
            raise InvalidParameterError("Rule with raw match or action failed verification")
        else:
            raise


def modify_ingress(message: bytes) -> None:
    transaction: Mapping[str,  str] = json.loads(message)
    chain_name = get_str(transaction, "chain_name")
    modify_single_rule(f"netdev/ingress/{chain_name}/mgmtd", message)


def create_ingress_chain(preset_dir: Path, chain_name: str, devices: set[str]) -> None:
    configuration_file: Path = preset_dir / f"netdev/ingress/{chain_name}.ingress"
    if configuration_file.exists():
        raise InvalidPreconditionError(f"Chain {chain_name} already exists!")

    devices_string = ', '.join(sorted(devices))
    content = f"""chain {chain_name} {{
    type filter hook ingress devices = {{ {devices_string} }} priority 0
    include "netdev/ingress/{chain_name}/policy_conf"
    include "netdev/ingress/{chain_name}/mgmtd/*.conf"\n}}
    """

    ingress_dir = Path(preset_dir / "netdev/ingress")
    if not ingress_dir.exists():
        ingress_dir.mkdir(parents=True)

    configuration_file.write_text(content)
    rule_name_dir = configuration_file.parent / chain_name / "mgmtd"
    rule_name_dir.mkdir(parents=True)
    (rule_name_dir.parent / ".devices").write_text(json.dumps(sorted(devices)))
    (rule_name_dir / ".allow_conf").touch()
    set_policy_in_policy_conf(preset_dir / f"netdev/ingress/{chain_name}/policy_conf", "accept")


def modify_create_chain_ingress(message: bytes) -> None:
    transaction: Mapping[str,  str] = json.loads(message)
    preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED)
    devices = get_list(transaction, "devices")
    name = get_str(transaction, "chain_name")
    create_ingress_chain(preset.dir, name, set(devices))


def modify_remove_chain_ingress(message: bytes) -> None:
    transaction: Mapping[str,  str] = json.loads(message)
    preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED)
    name = get_str(transaction, "chain_name")
    configuration_file: Path = preset.dir / f"netdev/ingress/{name}.ingress"
    if not configuration_file.exists():
        raise InvalidPreconditionError(f"Chain {name} does not exists!")

    configuration_file.unlink()
    shutil.rmtree(configuration_file.parent / name)


def modify_mgmtd_chain(chain: str) -> Callable[[bytes], None]:
    return lambda message: modify_single_rule(chain, message)


def shall_use_subnet(ipn: ipaddress.IPv4Network) -> bool:
    if ipn.prefixlen < 4:
        raise InvalidParameterError("Mask must designate at least 4 bits (actually anything lower than 8 is insane)")
    if ipn.prefixlen != 32:
        return True
    return False


def validate_port_forward_params(command: str, *, public_interface: str, ip_public: str, port_public: str,
                                 ip_private: str, port_private: str, protocol: str) -> None:
    param_present = False
    if len(public_interface) or len(ip_public) or len(ip_private) or len(port_public):
        param_present = True
    if len(port_private) or len(protocol):
        param_present = True
    if command == "add" or param_present:
        if len(ip_private) == 0:
            raise InvalidParameterError(f"Cannot {command} port forward without private ip")
        if len(port_public) == 0:
            raise InvalidParameterError(f"Cannot {command} port forward without port_public")
        if len(ip_public) == 0 and len(public_interface) == 0:
            raise InvalidParameterError(f"Cannot {command} without either ip_public or public_interface")
        if len(port_private) and protocol == "both":
            raise InvalidParameterError("Port_private is allowed only if single protocol is being forwarded")


def modify_port_forward(message: bytes) -> None:
    transaction: Mapping[str, str] = json.loads(message)
    preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED)
    rule_name = get_str(transaction, "rule_name")
    command = get_str(transaction, "command")
    notes = get_optional_str(transaction, 'notes')
    # Rule specific data
    public_interface = get_optional_str(transaction, 'public_interface')
    ip_public = get_optional_str(transaction, 'ip_public')
    port_public = get_optional_str(transaction, 'port_public')
    ip_private = get_optional_str(transaction, 'ip_private')
    port_private = get_optional_str(transaction, 'port_private')
    protocol = get_optional_enum_str(transaction, 'protocol', ['tcp', 'udp', 'both'])

    # Validate things needed always
    validate_part_name(rule_name)
    validate_command(command)
    part = 'ip/nat/prerouting/mgmtd'
    part_dir = preset.dir / part
    if not part_dir.exists():
        raise InvalidPreconditionError(f"Part {part} does not exist!")
    # TODO name generation duplication with fill_leaf and others
    conf_file = part_dir / f"{rule_name}.conf"
    notes_file = part_dir / f"{rule_name}.notes"
    validate_add_or_modify(command, f"{part}/{rule_name}", conf_file)

    if command == "remove":
        perform_single_rule_remove(preset, notes_file, conf_file)
        return
    if command == "comment" or command == "uncomment":
        # TODO add implementation
        raise RuntimeError(f"Command {command} is not implemented yet")

    # We are adding new, or changing existing rule
    validate_port_forward_params(command, public_interface=public_interface,
                                 ip_public=ip_public, port_public=port_public,
                                 ip_private=ip_private, port_private=port_private,
                                 protocol=protocol)
    if len(ip_public) == 0 and len(public_interface) == 0 and len(notes) == 0:
        raise InvalidParameterError("Nothing to do")

    if len(protocol) < 1:
        protocol = "tcp"

    match = ""
    if len(public_interface):
        match += f"iifname {public_interface} "
    if len(ip_public):
        ip_addr_public = ipaddress.IPv4Address(ip_public)
        match += f"ip daddr {ip_addr_public} "
    if len(match):
        if protocol == "both":
            match += f"meta l4proto {{tcp, udp}} th dport {port_public} "
        else:
            match += f"{protocol} dport {port_public} "

    ip_addr_private = ipaddress.IPv4Address(ip_private)
    action = f"dnat to {ip_addr_private}"
    if len(port_private):
        action += f":{port_private}"

    with PresetChangeGuard(preset.dir):
        if len(match):
            conf_file.write_text(f"{match} {action}\n")
        if len(notes) > 0:
            extended_notes = f"{notes}\n"
        else:
            extended_notes = ""
        extended_notes += "Generated by net.filter.modify.port_forward\n"
        if (not notes_file.exists()) or len(notes) > 0:
            notes_file.write_text(extended_notes)
        modify_action(preset.dir, f"Executed {command} on rules {part}/{rule_name}")


def validate_masquerade_params(command: str, *, public_interface: str, private_interface: str,
                               ip_private: str, mask: str) -> None:
    if command == "add" or len(ip_private) or len(mask):
        if len(public_interface) == 0:
            raise InvalidParameterError(f"Cannot {command} masquerade without public_interface")
        if len(mask) and len(ip_private) == 0:
            raise InvalidParameterError(f"Cannot {command} masquerade with mask and without ip_private")


def validate_snat_params(command: str, *, public_interface: str, private_interface: str,
                         ip_public: str, ip_private: str, mask: str) -> None:
    if command == "add" or len(ip_private) or len(mask) or len(ip_public) or len(public_interface):
        if len(public_interface) == 0 or len(ip_public) == 0:
            raise InvalidParameterError(f"Cannot {command} snat without both public_interface and ip_public")
        if len(mask) and len(ip_private) == 0:
            raise InvalidParameterError(f"Cannot {command} snat with mask and without ip_private")


# TODO refactor NAT related modify functions and modify_single_rule function as
# they contain common logic...
def modify_masquerade_snat(message: bytes, *, use_snat: bool) -> None:
    transaction: Mapping[str, str] = json.loads(message)
    preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED)
    rule_name = get_str(transaction, "rule_name")
    command = get_str(transaction, "command")
    notes = get_optional_str(transaction, 'notes')
    # Rule specific data
    public_interface = get_optional_str(transaction, 'public_interface')
    private_interface = get_optional_str(transaction, 'private_interface')
    if use_snat:
        ip_public = get_optional_str(transaction, 'ip_public')
    ip_private = get_optional_str(transaction, 'ip_private')
    mask_private = get_optional_str(transaction, 'mask_private')

    # Validate things needed always
    validate_part_name(rule_name)
    validate_command(command)
    part = 'ip/nat/postrouting/mgmtd'
    part_dir = preset.dir / part
    if not part_dir.exists():
        raise InvalidPreconditionError(f"Part {part} does not exist!")
    # TODO name generation duplication with fill_leaf and others
    conf_file = part_dir / f"{rule_name}.conf"
    notes_file = part_dir / f"{rule_name}.notes"
    validate_add_or_modify(command, f"{part}/{rule_name}", conf_file)

    if command == "remove":
        perform_single_rule_remove(preset, notes_file, conf_file)
        return
    if command == "comment" or command == "uncomment":
        # TODO add implementation
        raise RuntimeError(f"Command {command} is not implemented yet")

    # We are adding new, or changing existing rule
    if use_snat:
        validate_snat_params(command, public_interface=public_interface,
                             private_interface=private_interface,
                             ip_public=ip_public, ip_private=ip_private, mask=mask_private)
    else:
        validate_masquerade_params(command, public_interface=public_interface,
                                   private_interface=private_interface,
                                   ip_private=ip_private, mask=mask_private)
    if len(public_interface) == 0 and len(notes) == 0:
        raise InvalidParameterError("Nothing to do")

    match = f"oifname {public_interface}"
    if use_snat:
        ip_addr_public = ipaddress.IPv4Address(ip_public)
        action = f"snat to {ip_addr_public}"
    else:
        action = "masquerade"
    if len(ip_private):
        ip_addr_private = ipaddress.IPv4Address(ip_private)
        use_subnet = False
        if len(mask_private) > 0:
            private_subnet = ipaddress.IPv4Network((ip_addr_private, mask_private))
            use_subnet = shall_use_subnet(private_subnet)
        if use_subnet:
            match += f" ip saddr {private_subnet}"
        else:
            match += f" ip saddr {ip_addr_private}"
    if len(private_interface):
        match += f" iifname {private_interface}"

    with PresetChangeGuard(preset.dir):
        if len(public_interface):
            conf_file.write_text(f"{match} {action}\n")
        if len(notes) > 0:
            extended_notes = f"{notes}\n"
        else:
            extended_notes = ""
        extended_notes += f"Generated by net.filter.modify.{'snat' if use_snat else 'masquerade'}\n"
        if (not notes_file.exists()) or len(notes) > 0:
            notes_file.write_text(extended_notes)
        modify_action(preset.dir, f"Executed {command} on rules {part}/{rule_name}")


def modify_snat(message: bytes) -> None:
    modify_masquerade_snat(message, use_snat=True)


def modify_masquerade(message: bytes) -> None:
    modify_masquerade_snat(message, use_snat=False)


def validate_n_on_n_params(command: str, ip_public: str, ip_private: str, public_interface: str, mask: str) -> None:
    if command == "add" or len(public_interface) or len(mask):
        if len(ip_private) == 0 or len(ip_public) == 0:
            raise InvalidParameterError(f"Cannot {command} N:N NAT without both ip_public and ip_private")
    if len(ip_private) > 0 or len(ip_public) > 0:
        if len(ip_private) == 0 or len(ip_public) == 0:
            raise InvalidParameterError(f"Cannot {command} N:N NAT without both ip_public and ip_private")


def modify_nat_n_on_n(message: bytes) -> None:
    transaction: Mapping[str, str] = json.loads(message)
    preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED)
    rule_name = get_str(transaction, "rule_name")
    command = get_str(transaction, "command")
    notes = get_optional_str(transaction, 'notes')
    # Rule specific data
    public_interface = get_optional_str(transaction, 'public_interface')
    ip_public = get_optional_str(transaction, 'ip_public')
    ip_private = get_optional_str(transaction, 'ip_private')
    mask = get_optional_str(transaction, 'mask')

    validate_part_name(rule_name)
    validate_command(command)

    part_pre = 'ip/nat/prerouting/mgmtd'
    part_post = 'ip/nat/postrouting/mgmtd'
    part_pre_dir = preset.dir / part_pre
    part_post_dir = preset.dir / part_post
    if not part_pre_dir.exists():
        raise InvalidPreconditionError(f"Part {part_pre} does not exist!")
    if not part_post_dir.exists():
        raise InvalidPreconditionError(f"Part {part_post} does not exist!")

    # TODO name generation duplication with fill_leaf and others
    conf_file_pre = part_pre_dir / f"{rule_name}.conf"
    conf_file_post = part_post_dir / f"{rule_name}.conf"
    notes_file_pre = part_pre_dir / f"{rule_name}.notes"
    notes_file_post = part_post_dir / f"{rule_name}.notes"
    validate_add_or_modify(command, f"{part_pre}/{rule_name}", conf_file_pre)
    validate_add_or_modify(command, f"{part_post}/{rule_name}", conf_file_post)

    if command == "remove":
        with PresetChangeGuard(preset.dir):
            perform_single_rule_remove(preset, notes_file_pre, conf_file_pre, partial_remove=True)
            perform_single_rule_remove(preset, notes_file_post, conf_file_post, partial_remove=True)
            modify_action(preset.dir, f"Removed rule {part_pre}/{rule_name} and {part_post}/{rule_name}")
            return
    if command == "comment" or command == "uncomment":
        # TODO add implementation
        raise RuntimeError(f"Command {command} is not implemented yet")

    # We are adding new, or changing existing rule
    validate_n_on_n_params(command, ip_public, ip_private, public_interface, mask)
    if len(ip_public) == 0 and len(notes) == 0:
        raise InvalidParameterError("Nothing to do")

    # For subnets until better support is present we use hack with bitmask operations
    # eg. to map 10.10.10.x to 192.168.35.x we do:
    # ip saddr 10.10.10.0/24 snat to ip saddr & 0.0.0.255 | 192.168.35.0

    ip_addr_public = ipaddress.IPv4Address(ip_public)
    ip_addr_private = ipaddress.IPv4Address(ip_private)
    use_subnet = False
    if len(mask) > 0:
        logger.debug(f"mask {mask}")
        public_subnet = ipaddress.IPv4Network((ip_addr_public, mask))
        logger.debug(f"public_subnet {public_subnet}")
        private_subnet = ipaddress.IPv4Network((ip_addr_private, mask))
        logger.debug(f"private_subnet {private_subnet}")
        use_subnet = shall_use_subnet(public_subnet)
    if use_subnet:
        pre_match = f"ip daddr {public_subnet}"
        pre_action = f"dnat to ip daddr & {private_subnet.hostmask} | {private_subnet.network_address}"
        post_match = f"ip saddr {private_subnet}"
        post_action = f"snat to ip saddr & {public_subnet.hostmask} | {public_subnet.network_address}"
    else:
        pre_match = f"ip daddr {ip_addr_public}"
        pre_action = f"dnat to {ip_addr_private}"
        post_match = f"ip saddr {ip_addr_private}"
        post_action = f"snat to {ip_addr_public}"
    if len(public_interface):
        pre_match += f" iifname {public_interface}"
        post_match += f" oifname {public_interface}"

    with PresetChangeGuard(preset.dir):
        if len(pre_match):
            conf_file_pre.write_text(f"{pre_match} {pre_action}\n")
            conf_file_post.write_text(f"{post_match} {post_action}\n")
        if len(notes) > 0:
            extended_notes = f"{notes}\n"
        else:
            extended_notes = ""
        extended_notes += "Generated by net.filter.modify.nat_n_to_n\n"
        if (not notes_file_pre.exists()) or len(notes) > 0:
            notes_file_pre.write_text(extended_notes)
        if (not notes_file_post.exists()) or len(notes) > 0:
            notes_file_post.write_text(extended_notes)
        modify_action(preset.dir, f"Executed {command} on rules {part_pre}/{rule_name} and {part_post}/{rule_name}")


def handle_enable(message: bytes, from_part: bytes, message_id: bytes) -> Any:
    transaction: Mapping[str, str] = json.loads(message)
    ask_for_affirmation = get_bool(transaction, "ask_for_affirmation")
    return affirmable_firewall_transaction.enable(ask_for_affirmation, topics.net.filter.enable, from_part, message_id)


def handle_disable(message: bytes, from_part: bytes, message_id: bytes) -> Any:
    transaction: Mapping[str, str] = json.loads(message)
    ask_for_affirmation = get_bool(transaction, "ask_for_affirmation")
    return affirmable_firewall_transaction.disable(ask_for_affirmation, topics.net.filter.disable, from_part, message_id)


def handle_commit(message: bytes) -> None:
    if message:
        logger.warning(f"Non empty message received by handle_commit(): {message!r}")
    affirmable_firewall_transaction.commit()


def handle_cleanup(message: bytes) -> Optional[str]:
    if message:
        logger.warning(f"Non empty message received by handle_cleanup(): {message!r}")
    if affirmable_firewall_transaction.cleanup():
        return (f"{RESPONSE_OK} Removed leftovers of unfished transaction. "
                "Verify config correctness or restore config from backup with 'set_config'")
    raise InvalidPreconditionError("Nothing to cleanup")


def handle_reload(message: bytes) -> None:
    if message:
        logger.warning(f"Non empty message received by handle_reload(): {message!r}")
    reload_action()


def main() -> None:
    messages = {}
    messages[topics.net.filter.commit] = guarded(sync(handle_commit))
    messages[topics.net.filter.cleanup] = guarded(sync(handle_cleanup))
    messages[topics.net.filter.reload] = guarded(sync(handle_reload))
    messages[topics.net.filter.preset.select] = guarded(preset_select)
    messages[topics.net.filter.preset.create] = guarded(sync(preset_create))
    messages[topics.net.filter.preset.delete] = guarded(sync(preset_delete))
    messages[topics.net.filter.preset.edit] = guarded(sync(preset_edit))
    messages[topics.net.filter.preset.save] = guarded(sync(preset_save))
    messages[topics.net.filter.preset.list] = guarded(sync(preset_list))
    messages[topics.net.filter.preset.print] = guarded(sync(preset_print))
    messages[topics.net.filter.modify.copy] = guarded(sync(modify_copy))
    messages[topics.net.filter.modify.erase] = guarded(sync(modify_erase))
    messages[topics.net.filter.modify.policy] = guarded(sync(modify_policy))
    messages[topics.net.filter.modify.common] = guarded(sync(modify_mgmtd_chain("inet/filter/common/mgmtd")))
    messages[topics.net.filter.modify.input] = guarded(sync(modify_mgmtd_chain("inet/filter/input/mgmtd")))
    messages[topics.net.filter.modify.output] = guarded(sync(modify_mgmtd_chain("inet/filter/output/mgmtd")))
    messages[topics.net.filter.modify.forward] = guarded(sync(modify_mgmtd_chain("inet/filter/forward/mgmtd")))
    messages[topics.net.filter.modify.ingress] = guarded(sync(modify_ingress))
    messages[topics.net.filter.modify.create_chain_ingress] = guarded(sync(modify_create_chain_ingress))
    messages[topics.net.filter.modify.remove_chain_ingress] = guarded(sync(modify_remove_chain_ingress))
    messages[topics.net.filter.modify.nat_pre] = guarded(sync(modify_mgmtd_chain("ip/nat/prerouting/mgmtd")))
    messages[topics.net.filter.modify.nat_post] = guarded(sync(modify_mgmtd_chain("ip/nat/postrouting/mgmtd")))
    messages[topics.net.filter.modify.nat_n_on_n] = guarded(sync(modify_nat_n_on_n))
    messages[topics.net.filter.modify.masquerade] = guarded(sync(modify_masquerade))
    messages[topics.net.filter.modify.snat] = guarded(sync(modify_snat))
    messages[topics.net.filter.modify.port_forward] = guarded(sync(modify_port_forward))
    messages[topics.net.filter.enable] = guarded(handle_enable)
    messages[topics.net.filter.disable] = guarded(handle_disable)
    messages[topics.net.filter.get_config] = guarded(sync(get_config))
    messages[topics.net.filter.show] = guarded(sync(show))
    messages[topics.net.filter.set_config] = guarded(set_config)

    _client.register_responders(messages)

    if _client.has_responding_handler(topics.net.filter.reload):
        logger.info('Init firewall')
        reload_action()
    else:
        logger.info('Loading rules not allowed by this daemon instance, skipping init')

    while True:
        try:
            _client.wait_and_receive()
        except _client.LostRequestList as lr:
            logger.warning(f"Received LostRequestList: {lr}")


if __name__ == "__main__":
    main()
