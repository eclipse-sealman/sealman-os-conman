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
import collections.abc as abc
from enum import Enum
from typing import Any, Callable, MutableMapping, Mapping

RESPONSE_OK = "OK"
RESPONSE_FAILURE = "FAILED:"


class FileExtension(Enum):
    """String enum for common file extensions."""
    JSON = ".json"
    TOML = ".toml"
    YAML = ".yaml"
    YML = ".yml"
    OVPN = ".ovpn"
    SWU = ".swu"


def empty_message_wrapper(func: Callable[..., Any]) -> Callable[..., Any]:
    def wrapper(message: bytes = b'') -> Any:
        return func(message)
    return wrapper


def add_or_merge(parent: MutableMapping[str, Any], to_add: Mapping[str, Any]) -> None:
    '''
    Adds new keys from to_add, tries to merge values for keys existing in boh parent and to_add.

    Merge is done for values which are dicts and sequences only. For sequneces
    simple extension is done.  For dicts all sub_keys in to_add needs to be new
    (i.e. there is no recursive merging)
    '''
    for key in to_add:
        if key not in parent:
            # Add
            parent[key] = to_add[key]
        else:
            # Merge (RuntimeError's here indicate wrong data which shall not be
            # possible to achive by user --- hence if they happen we need to
            # make some correction (e.g. better validation in set_config)
            old_value = parent[key]
            new_value = to_add[key]
            if isinstance(old_value, str):
                raise RuntimeError(f"Conflicting str {key}")
            if isinstance(old_value, abc.MutableMapping):
                if not isinstance(new_value, abc.Mapping):
                    raise RuntimeError(f"Non compatible types of {key}")
                for sub_key in new_value:
                    if sub_key in old_value:
                        raise RuntimeError(f"Conflicting {key}/{sub_key}")
                old_value.update(new_value)
            elif isinstance(old_value, abc.MutableSequence):
                if isinstance(new_value, abc.Sequence):
                    old_value.extend(new_value)
                else:
                    old_value.append(new_value)
            else:
                raise RuntimeError(f"Conflicting {key}")
