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
# Standard imports
import argparse
import sys
import json
import shutil

from enum import Enum
from pathlib import Path
from typing import Any, Container, Mapping, MutableMapping, Optional, Union, Sequence, List

# Third party imports
from pyroute2 import IPRoute  # type: ignore
from pyroute2 import IPDB
from pyroute2.netlink.exceptions import NetlinkError  # type: ignore

# Local imports
import mpa.communication.topics as topics
from .common import GLOBAL_ROUTES, MPA, NetlinkEvents, SCOPES, TYPES
from mpa.common.common import RESPONSE_OK, add_or_merge
from mpa.communication import client as com_client
from mpa.communication.affirmable_preset_actions import AffirmablePresetActionsBase, ROLLBACK_WARNING
from mpa.communication.client import Async
from mpa.communication.client import guarded
from mpa.communication.client import sync
from mpa.communication.common import InvalidPreconditionError, InvalidParameterError, InvalidPayloadError, RouteAlreadyExistsError
from mpa.communication.common import get_interface_name_from_ip_addres
from mpa.communication.daemon_transaction import DaemonTransaction
from mpa.communication.inter_process_lock import InterProcessLock
from mpa.common.logger import Logger
from mpa.communication.message_parser import get_bool, get_dict, get_enum_str, get_int, get_ip46_and_mask, get_str
from mpa.communication.message_parser import get_optional_ip46, get_optional_enum_str, get_optional_str
from mpa.communication.preset import PresetBase
from mpa.communication.preset import PresetChangeGuardBase
from mpa.communication.preset import PresetType
from mpa.communication.preset import VerificationError
from mpa.communication.process import run_command_unchecked
from mpa.network.management import get_nm_param_values, reduce_to_single_value_if_possible
from mpa.network.routing_common import LOCK_FILE
from mpa.network.routing_common import PRESETS, EDITS, CURRENT, PREVIOUS, ENABLED
from mpa.network.routing_common import PRESETS_BACKUP, EDITS_BACKUP, RESCUE, INITIALLY_CREATED_AS

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

_parser = argparse.ArgumentParser(prog='Routing daemon')
com_client.add_command_line_params(_parser)
_args = _parser.parse_args()
_client = com_client.Client(args=_args)

ipdb = IPDB()

last_carrier_interface_state: MutableMapping[str, int] = {}

_network_transaction = DaemonTransaction(f"Connectivity confirmation was not received. {ROLLBACK_WARNING}", _client)

LOCK = InterProcessLock(LOCK_FILE)
INVALID_FILE_BECAUSE_STATE_CHANGE_IS_NOT_AFFIRMABLE_YET = Path('/invalid')  # TODO: this is routing.py specific
# Value taken from https://gitlab.freedesktop.org/NetworkManager/NetworkManager/-/blob/main/src/libnmc-base/nm-client-utils.c#L307
EXTERNAL_CONNECTION_STATE = '(externally))'


def add_presets_action(parent_dir: Path, new_presets: Mapping[str, Any], excluded: Container[str] = list()) -> None:
    for name, value in new_presets.items():
        if name in excluded:
            continue
        new_preset_dir = parent_dir / name
        if new_preset_dir.exists():
            raise InvalidPayloadError(f"Preset '{name}' already exists so cannot be added")
        try:
            with PresetChangeGuard(new_preset_dir):
                for subkey, subvalue in value.items():
                    # TODO Do we need to check 'notes' here, if we do it also in fill_config_file_from_dict?
                    if subkey == "notes":
                        fill_dir_notes(new_preset_dir, subvalue)
                    elif subkey == "hidden":
                        pass
                    elif 'contents' in subvalue:
                        fill_config_file_from_dict(new_preset_dir, subvalue, subkey)
        except VerificationError:
            raise InvalidPayloadError(f"Preset '{name}' failed verification")


def get_config(message: bytes) -> Mapping[str, Any]:
    config: MutableMapping[str, Any] = dict()
    config['enabled'] = Preset.is_enabled()
    if CURRENT.exists():
        config['selected'] = CURRENT.resolve().stem
    saved: MutableMapping[str, Sequence[str]] = {}
    for entry in PRESETS.iterdir():
        saved.update(single_preset_print(entry, ''))
    config['saved'] = saved
    edited: MutableMapping[str, Sequence[str]] = {}
    for entry in EDITS.iterdir():
        edited.update(single_preset_print(entry, ''))
    config['edited'] = edited
    return {'static_routing': config}


class RouteStatus(Enum):
    ROUTE_CLEAR = 0  # This route can be added without any problems
    ROUTE_IN_CURRENT_ROUTES = 1  # This route is already loaded in system
    ROUTE_IN_CURRENT_PRESET = 2  # This route is already present in currently edited preset


class PresetChangeGuard(PresetChangeGuardBase):
    def is_valid(self) -> bool:
        return True


class Preset(PresetBase):
    def is_valid(self) -> bool:
        return True


Preset.set_class_params(saved_parent=PRESETS,
                        edited_parent=EDITS,
                        lock=LOCK,
                        enabled=ENABLED,
                        current=CURRENT,
                        previous=PREVIOUS)


class AffirmableRoutingActions(AffirmablePresetActionsBase):
    pass


AffirmableRoutingActions.set_class_params(preset_class=Preset,
                                          state_change_transaction_marker=INVALID_FILE_BECAUSE_STATE_CHANGE_IS_NOT_AFFIRMABLE_YET,
                                          rescue_preset_path=RESCUE,
                                          backup_saved_presets_path=PRESETS_BACKUP,
                                          backup_edited_presets_path=EDITS_BACKUP)


class InvalidConfig(Exception):
    def __init__(self, part_dir: Path, encapsulated: Exception):
        self.part_dir = part_dir
        self.encapsulated = encapsulated


def reload_action() -> str:
    flush_status = flush_routing_rules()
    if Preset.is_enabled():
        return load_rules_from_config()
    return flush_status


def generate_disabled_preset(target: Path) -> None:
    target.mkdir()


affirmable_routing_transaction = AffirmableRoutingActions("Routing",
                                                          _network_transaction,
                                                          reload_action,
                                                          generate_disabled_preset,
                                                          add_presets_action)


# TODO do we want to make it affirmable?
def set_config(message: bytes) -> Any:
    config = json.loads(message)
    ask_for_affirmation = False
    routing_config = get_dict(config, "static_routing")
    return affirmable_routing_transaction.set_config(ask_for_affirmation,
                                                     routing_config,
                                                     'invalid_topic_as_no_affirm_request_is_supported_yet', b'', b'')


# TODO do we want to make it affirmable?
def enable() -> str:
    if not Preset.is_enabled():
        Preset.enable()
        status: str = load_rules_from_config()
        return f"{RESPONSE_OK} \n Additional infromation: \n {status}"
    else:
        return f"{RESPONSE_OK} Static routing is already enabled"


# TODO do we want to make it affirmable?
def disable() -> str:
    if Preset.is_enabled():
        Preset.disable()
        flush_routing_rules()
        return f"{RESPONSE_OK} Static routing disabled"
    else:
        return f"{RESPONSE_OK} Static routing is already disabled"


def preset_select(message: bytes, from_part: bytes, message_id: bytes) -> Any:
    transaction: Mapping[str,  str] = json.loads(message)
    ask_for_affirmation = get_bool(transaction, "ask_for_affirmation")
    preset = Preset(get_optional_str(transaction, "name"), PresetType.SAVED)
    return affirmable_routing_transaction.select(ask_for_affirmation, preset,
                                                 topics.net.routes.preset.select,
                                                 from_part, message_id)


def preset_create(message: bytes) -> None:
    transaction: Mapping[str,  str] = json.loads(message)
    source = get_optional_str(transaction, "source")
    new_preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED, create=True)
    main_notes_file = new_preset.dir / ".notes"
    if len(source) > 0:
        source_dir = Preset(source, PresetType.SAVED).dir
        new_preset.dir.rmdir()
        shutil.copytree(source_dir, new_preset.dir, symlinks=True)
        main_notes_file.write_text(f"{INITIALLY_CREATED_AS}copy of {source_dir.stem}\n")
    else:
        main_notes_file.write_text(f"{INITIALLY_CREATED_AS}empty preset\n")


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


def preset_edit(message: bytes) -> None:
    transaction: Mapping[str,  str] = json.loads(message)
    preset = Preset(get_optional_str(transaction, "name"), PresetType.EDITED | PresetType.SAVED)
    preset.edit()


# TODO extract common code with fw_daemon
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
    name = transaction["name"]
    if not name or len(name) < 1:
        name = '*'
    retval = {}
    retval["saved"] = [entry.stem for entry in PRESETS.glob(name)]
    retval["being_edited"] = [entry.stem for entry in EDITS.glob(name)]
    retval["current"] = [entry.stem for entry in CURRENT.glob(name)]

    return retval


# This function is quite similar to fw_daemon subparts_print, TODO check if can
# be extracted or if preset contents in routing are different enough that it
# shall be changed or removed totally...
def subparts_print(part_dir: Path) -> Optional[Mapping[str, Any]]:
    try:
        retval: MutableMapping[str, Any] = {}
        for entry in part_dir.glob('*'):
            if entry.is_dir():
                entry_out = subparts_print(entry)
                if entry_out is not None:
                    add_or_merge(retval, {entry.stem: entry_out})
            if entry.is_file():
                if entry.name == '.ro':
                    pass
                elif entry.name == '.notes':
                    add_or_merge(retval, {'notes':  entry.read_text().strip()})
                elif entry.suffix == '.json':
                    add_or_merge(retval, {entry.stem: {'contents': json.loads(entry.read_text().strip())}})
        if len(retval) > 0:
            return retval
        return {}
    except InvalidConfig:
        raise
    except Exception as exc:
        logger.error(f"Failed reading config {part_dir}: {exc}")
        raise InvalidConfig(part_dir, exc)


# This function is shared between nm_daemon and fw_daemon TODO extract it
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
        raise RuntimeError(f"Invalid preset {preset_dir.stem}: \
                             in {exc.part_dir.relative_to(preset_dir)}: {str(exc.encapsulated)}")


def preset_print(message: bytes) -> Mapping[str, Sequence[str]]:
    transaction: Mapping[str,  str] = json.loads(message)
    name = '*' if transaction["name"] is None else transaction['name']
    editable_only = transaction["editable_only"]
    part = '' if transaction["part"] is None else transaction['part']
    if editable_only:
        preset = Preset(name, PresetType.EDITED)
        return single_preset_print(preset.dir, part)
    retval: MutableMapping[str, Sequence[str]] = {}
    for entry in PRESETS.glob(name):
        retval.update(single_preset_print(entry, part))
    for entry in EDITS.glob(name):
        retval.update(single_preset_print(entry, part))
    return retval


def fill_dir_notes(part_dir: Path, value: str) -> None:
    notes_file = part_dir / '.notes'
    notes_file.write_text(value + "\n")


# TODO check if commonality between nm_daemon and fw_deamon can be extracted
def fill_config_file_from_dict(preset_dir: Path, config: Mapping[str, Any], config_name: str) -> None:
    for key, value in config.items():
        if key == "contents":
            with open(f"{preset_dir}/{config_name}.json", "w") as file:
                file.write(json.dumps(config['contents']))
        elif key == "notes":
            fill_dir_notes(preset_dir, value)
        else:
            raise InvalidPayloadError(f"Unrecognized entry in config: {key}")


class RouteConfig:
    def __init__(self, transaction: Mapping[str, Any]):
        self.type = get_enum_str(transaction, "type", TYPES)
        self.network = get_ip46_and_mask(transaction, "network", "subnet")
        self.metric = get_int(transaction, "metric")
        self.bind = get_optional_str(transaction, "bind")
        self.dev = get_optional_str(transaction, "dev")
        self.via = get_optional_ip46(transaction, "via")
        self.scope = get_optional_enum_str(transaction, "scope", SCOPES)

        if len(self.dev) < 1 and self.via is None and self.type not in GLOBAL_ROUTES:
            raise InvalidParameterError(f"Missing 'dev' or 'via' value (at least one of them must be present for \
                                          route type {self.type})")

    def __eq__(self, other: Any) -> bool:
        if not isinstance(other, RouteConfig):
            return False
        for key in self.__dict__:
            if key != 'methods':
                if self.__dict__[key] != other.__dict__[key]:
                    return False
        return True

    def serializable(self) -> Mapping[str, Any]:
        retval = {
                "type": self.type,
                "network": f'{self.network.network_address}',
                "subnet": f'{self.network.prefixlen}',
                "metric": self.metric
                }
        if len(self.bind):
            retval["bind"] = self.bind
        if len(self.scope):
            retval["scope"] = self.scope
        if len(self.dev):
            retval["dev"] = self.dev
        if self.via is not None:
            retval["via"] = f'{self.via}'
        return retval


def load_rules_from_config(config_name: Optional[str] = None) -> str:
    flush_routing_rules()
    config_file: str = "*.json" if config_name is None else f"{config_name}.json"
    status: MutableMapping[str, Any] = {"errors": []}
    logger.debug(f"config file pattern: {config_file}")
    for entry in CURRENT.glob(config_file):
        config = load_json_file(entry)
        for preset_route in config['rules']:
            try:
                route_config = RouteConfig(preset_route['config'])
            except Exception as err:
                # Invalid file on disk --- it is our fault (we did not validate
                # some input earlier or we allowed user to play with disk
                # area which shall be restricted for him)
                # TODO what exactly shall we do here... ignore rule, stop loading whole preset?
                logger.info(f"Could not add rule {preset_route}. Error: {err}")
                status["errors"].append(f"Invalid rule deteced in config `{entry.stem}`")
                continue

            args = {
                "dst": str(route_config.network),
                "type": route_config.type,
                "proto": MPA,
                "priority": route_config.metric
            }
            # .scope is a string and if it is empty we should not add it to args
            if len(route_config.scope):
                args['scope'] = route_config.scope
            if route_config.dev != '':
                try:
                    with IPRoute() as ipr:
                        args["oif"] = ipr.link_lookup(ifname=route_config.dev)[0]
                except IndexError:
                    status["errors"].append(f"Device {route_config.dev!r} is not present on the machine")
                    continue
            if route_config.via is not None:
                args["gateway"] = f"{route_config.via}"
            try:
                with IPRoute() as ipr:
                    ipr.route("add", **args)
            except NetlinkError as err:
                logger.info(f"Could not add rule {args}. Error: {err}")
                status["errors"].append(f"Could not add rule {args}. Error: {err}")
    # TODO mypy raised error about incompatible type, so doing plain conversion
    # here. We use it for error reporting to user only currently, do we want it
    # formatted differently?
    return str(status)


# TODO what is the event type?
def parse_network_event(event: Any) -> None:
    interface_name: Optional[str] = None
    interface_status: Optional[bool] = None  # True if UP else False
    for attr in event['attrs']:
        if attr[0] == 'IFLA_IFNAME':
            interface_name = attr[1]
        elif attr[0] == 'IFLA_OPERSTATE':
            interface_status = True if attr[1] == 'UP' else False
    assert interface_name is not None
    assert interface_status is not None

    try:
        last_carrier_status = last_carrier_interface_state[interface_name]  # 1 = Connected, 0 = Disconnected
    except KeyError:
        last_carrier_status = 0  # assume that interface was down

    with open(f"/sys/class/net/{interface_name}/carrier", "r") as f:
        current_carrier_status = int(f.read().strip())

    if interface_status:
        # if the connection is externally managed, do not touch it
        # see https://cgit.freedesktop.org/NetworkManager/NetworkManager/commit/?id=ee4e679bc7479de42780ebd8e3a4d74afa2b2ebe
        if (current_carrier_status == 1 and last_carrier_status == 0):
            connection_state = reduce_to_single_value_if_possible(
                get_nm_param_values("GENERAL.STATE", interface_name, command="device show"))
            assert isinstance(connection_state, str)
            if not connection_state.strip().endswith(EXTERNAL_CONNECTION_STATE):
                run_command_unchecked(f'nmcli --wait 8 con up "{interface_name}"')
        load_rules_from_config()
    last_carrier_interface_state[interface_name] = current_carrier_status


# TODO are we interested in parameter types?
def on_interface_change(_ipdb: IPDB, netlink_message: Any, action: Any) -> None:
    if action == NetlinkEvents.RTM_NEWLINK.name:
        parse_network_event(netlink_message)


def load_rules(message: bytes) -> Mapping[str, str]:
    if message:
        logger.warning(f"Non empty message received by load_rules(): {message!r}")
    status: str = load_rules_from_config()
    return {"status": status}


def flush_routing_rules(protocol: int = MPA) -> str:
    with IPRoute() as ipr:
        status: str = str(ipr.flush_routes(proto=protocol))  # this is an empty list sometimes
    logger.info(f"Routes flush status: {status}")
    return status


def flush(message: bytes) -> Mapping[str, str]:
    return {"status": flush_routing_rules()}


def load_json_file(path: Path) -> MutableMapping[str, Any]:
    try:
        with open(path, "r") as file:
            retval = json.loads(file.read())
            assert isinstance(retval, MutableMapping)
            return retval
    except json.decoder.JSONDecodeError as exc:
        logger.exception(exc)
        # This shall not happen, so RuntimeError
        raise RuntimeError("Could not parse content of {config_path}/{config_name}.json, file is probably coruppted")


def read_config_file(config_path: Path, config_name: str) -> MutableMapping[str, Any]:
    try:
        return load_json_file(config_path / f"{config_name}.json")
    except IOError:
        raise InvalidParameterError(f"Config '{config_name}' is not readable (did you provide correct name?)")


def write_config_file(config_path: Path, config_name: str, data: Any) -> None:
    try:
        with open(f"{config_path}/{config_name}.json", "w") as file:
            file.write(json.dumps(data))
    except IOError:
        raise InvalidParameterError(f"Config '{config_name}' is not writable (did you provide correct name?)")


def remove_rule_from_config_file(rule_id: int, config_name: str, config_path: Path) -> None:
    current_config = read_config_file(config_path, config_name)

    removed = False
    for i in range(len(current_config['rules'])):
        if current_config['rules'][i]['id'] == rule_id:
            del current_config['rules'][i]
            removed = True
            break

    if not removed:
        raise InvalidParameterError("Can not find rule {rule_id} in config {config_name}")

    write_config_file(config_path, config_name, current_config)


def swap_rules(rule_id: int, rule_id2: int, config_name: str, config_path: Path) -> None:
    current_config = read_config_file(config_path, config_name)

    rule1_index = None
    rule2_index = None

    for i in range(len(current_config['rules'])):
        if current_config['rules'][i]['id'] == rule_id:
            rule1_index = i
        elif current_config['rules'][i]['id'] == rule_id2:
            rule2_index = i

    if rule1_index is None:
        raise InvalidParameterError(f"Cannot find rule {rule_id} in {config_name}")
    if rule2_index is None:
        raise InvalidParameterError(f"Cannot find rule {rule_id2} in {config_name}")

    current_config['rules'][rule1_index], current_config['rules'][rule2_index] = \
        current_config['rules'][rule2_index], current_config['rules'][rule1_index]
    current_config['rules'][rule1_index]['id'], current_config['rules'][rule2_index]['id'] = \
        current_config['rules'][rule2_index]['id'], current_config['rules'][rule1_index]['id']

    write_config_file(config_path, config_name, current_config)


def net_route_remove(message: bytes) -> None:
    """
    """
    transaction: Mapping[str, Any] = json.loads(message)
    name = get_optional_str(transaction, "name")
    rule_id = get_int(transaction, "id")
    config = get_str(transaction, "config")
    preset = Preset(name, PresetType.EDITED)
    remove_rule_from_config_file(rule_id, config, preset.dir)


def net_route_order(message: bytes) -> None:
    """
    """
    transaction: Mapping[str, Any] = json.loads(message)
    name = get_optional_str(transaction, "name")
    id1 = get_int(transaction, "id")
    id2 = get_int(transaction, "id2")
    config = get_str(transaction, "config")
    preset = Preset(name, PresetType.EDITED)
    swap_rules(id1, id2, config, preset.dir)


def handle_enable(message: bytes) -> Union[str, Async]:
    if message:
        logger.warning(f"Non empty message received by handle_enable(): {message!r}")
    return enable()


def handle_disable(message: bytes) -> str:
    if message:
        logger.warning(f"Non empty message received by handle_disable(): {message!r}")
    return disable()


def get_next_id(config: MutableMapping[str, Any]) -> int:
    ids: List[int] = []
    for rule in config['rules']:
        ids.append(rule['id'])
    try:
        next_id = max(ids) + 1
    except ValueError:
        next_id = 1
    return next_id


def add_net_route_to_config(config: RouteConfig, config_name: str,
                            path_to_edited_config: Path) -> None:
    try:
        current_config = read_config_file(path_to_edited_config, config_name)
        rule_id = get_next_id(current_config)
    except InvalidParameterError:
        logger.warning(f"{path_to_edited_config}/{config_name}.json do not exits, it will be created later")
        current_config = {"rules": []}
        rule_id = 1

    current_config['rules'].append({
            "config": config.serializable(), "notes": "", "id": rule_id
            })

    write_config_file(path_to_edited_config, config_name, current_config)


def check_if_route_allready_exists(route_config: RouteConfig, config_name: str,
                                   path_to_edited_config: Path) -> RouteStatus:
    if config_name == "global":
        dev = ""
    else:
        dev = f"dev {config_name}"
    output = run_command_unchecked(f"ip route show {route_config.network} {dev} metric {route_config.metric}")
    current_route = True if output.stdout.decode('ascii').count('\n') >= 1 else False

    try:
        current_config = read_config_file(path_to_edited_config, config_name)
    except InvalidParameterError:
        logger.warning(f"{path_to_edited_config}/{config_name}.json does not exist, it will be created later")
        current_config = {"rules": []}

    exists_in_preset = False
    for preset_route in current_config["rules"]:
        try:
            current_route_config = RouteConfig(preset_route["config"])
        except Exception:
            raise RuntimeError(f"Existing preset `{path_to_edited_config.stem}` has invalid contents")
        if current_route_config == route_config:
            exists_in_preset = True

    if exists_in_preset:
        return RouteStatus.ROUTE_IN_CURRENT_PRESET
    elif current_route:
        return RouteStatus.ROUTE_IN_CURRENT_ROUTES
    else:
        return RouteStatus.ROUTE_CLEAR


def net_route_add(message: bytes) -> str:
    """
    """
    transaction: MutableMapping[str,  str] = json.loads(message)
    name = get_optional_str(transaction, "name")
    route_config = RouteConfig(transaction)
    preset = Preset(name, PresetType.EDITED)

    if route_config.type in GLOBAL_ROUTES:
        config_file = "global"
    else:
        if len(route_config.bind) > 0:
            config_file = route_config.bind
        elif len(route_config.dev) > 0:
            config_file = route_config.dev
        elif route_config.via is not None:
            interface_name = get_interface_name_from_ip_addres(f"{route_config.via}")
            if interface_name is None:
                config_file = "global"
            else:
                config_file = interface_name
        else:
            # Impossible --- we verified that dev or via exist...
            raise RuntimeError("Could not find proper configuration for this rule")

    route_status = check_if_route_allready_exists(route_config, config_file, preset.dir)  # config_file contains interface name

    if route_status == RouteStatus.ROUTE_IN_CURRENT_PRESET:
        raise RouteAlreadyExistsError("Provided route already exists in selected preset. To see current preset content \
                                please use nm route_preset_print.")

    add_net_route_to_config(route_config, config_file, preset.dir)
    if route_status == RouteStatus.ROUTE_IN_CURRENT_ROUTES:
        return f"{RESPONSE_OK} Warrning! Provided route is currently available in system. Please notice that this rule may not \
                 be loaded when preset will be selected."
    else:
        return f"{RESPONSE_OK} Route added succesfully."


def main() -> None:
    messages = {}
    messages[topics.net.routing.get_config] = guarded(sync(get_config))
    messages[topics.net.routing.set_config] = guarded(sync(set_config))
    messages[topics.net.routing.flush] = guarded(sync(flush))
    messages[topics.net.routing.load_rules] = guarded(sync(load_rules))
    messages[topics.net.routes.preset.select] = guarded(preset_select)
    messages[topics.net.routes.preset.create] = guarded(sync(preset_create))
    messages[topics.net.routes.preset.delete] = guarded(sync(preset_delete))
    messages[topics.net.routes.preset.edit] = guarded(sync(preset_edit))
    messages[topics.net.routes.preset.save] = guarded(sync(preset_save))
    messages[topics.net.routes.preset.list] = guarded(sync(preset_list))
    messages[topics.net.routes.preset.print] = guarded(sync(preset_print))
    messages[topics.net.route.add] = guarded(sync(net_route_add))
    messages[topics.net.route.remove] = guarded(sync(net_route_remove))
    messages[topics.net.route.order] = guarded(sync(net_route_order))
    messages[topics.net.route.enable] = guarded(sync(handle_enable))
    messages[topics.net.route.disable] = guarded(sync(handle_disable))

    _client.register_responders(messages)

    if _client.has_responding_handler(topics.net.routing.load_rules):
        logger.info('Init static routing')
        ipdb.register_callback(on_interface_change)  # return value is required to unregister, but don't do that ever
        load_rules_from_config()  # load rules on daemon start
    else:
        logger.info('Loading rules not allowed by this daemon instance, skipping init')

    logger.info('Processing started')
    while True:
        try:
            _client.wait_and_receive()
        except _client.LostRequestList as lr:
            logger.warning(f"Received LostRequestList: {lr}")


if __name__ == "__main__":
    main()
