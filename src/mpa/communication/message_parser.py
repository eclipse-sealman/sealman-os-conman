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
import ipaddress
# from multimethod import multimethod  # TODO: uncomment when it will be fixed in upstream
import re
from subprocess import CalledProcessError
# from types import GenericAlias  # TODO: uncomment for MyIterable class
from typing import Any, Callable, Dict, List, Iterable, Mapping, Optional, Protocol, Type, TypeVar, Union

# Local imports
from mpa.communication.common import InvalidParameterError, InvalidPayloadError
from mpa.communication.process import run_command
from mpa.config.common import CONFIG_DIR_ROOT

T = TypeVar("T")
ReturnType_co = TypeVar("ReturnType_co", covariant=True)


class GetterFunction(Protocol[ReturnType_co]):
    def __call__(self, transaction: Mapping[str, Any], key: str) -> ReturnType_co:
        pass


def _get_type(raw_type: Any, subscripted_type: Type[T], name_in_error: str) -> GetterFunction[T]:
    def get(transaction: Mapping[str, Any], key: str) -> T:
        value = transaction[key]
        if not isinstance(value, raw_type):
            # Invalid format of message is for sure error in UI code, hence RuntimeError
            raise InvalidPayloadError(f"Entry must be a {name_in_error}: {key}")
        return value  # type: ignore
    return get


def mandatory_key(transaction: Mapping[str, Any], key: str) -> None:
    if key not in transaction:
        # UI shall send complete messages, hence RuntimeError
        raise InvalidPayloadError(f"Missing entry: {key}")


def make_mandatory(fun: GetterFunction[ReturnType_co]) -> GetterFunction[ReturnType_co]:
    def mandatory(transaction: Mapping[str, Any], key: str) -> ReturnType_co:
        mandatory_key(transaction, key)
        return fun(transaction, key)
    return mandatory


def make_optional(fun: GetterFunction[ReturnType_co]) -> GetterFunction[Optional[ReturnType_co]]:
    def optional(transaction: Mapping[str, Any], key: str) -> Optional[ReturnType_co]:
        if key not in transaction:
            return None
        if transaction[key] is None:
            return None
        return fun(transaction, key)
    return optional


def make_optional_with_default(fun: GetterFunction[T], default: T) -> GetterFunction[T]:
    def optional(transaction: Mapping[str, Any], key: str) -> T:
        if key not in transaction:
            return default
        if transaction[key] is None:
            return default
        return fun(transaction, key)
    return optional


_raw_get_str = _get_type(str, str, "string")


def _get_str(transaction: Mapping[str, Any], key: str) -> str:
    value = _raw_get_str(transaction, key)
    return value.strip()


def _get_file(transaction: Mapping[str, Any], key: str) -> str:
    return _raw_get_str(transaction, key)


get_optional_str = make_optional_with_default(_get_str, "")
_get_mandatory_str = make_mandatory(_get_str)
_get_mandatory_file = make_mandatory(_get_file)


def get_file(transaction: Mapping[str, Any], key: str) -> str:
    value = _get_mandatory_file(transaction, key)
    if len(value) < 1:
        raise InvalidParameterError(f"Entry file must not be empty: {key}")
    return value


def get_str(transaction: Mapping[str, Any], key: str) -> str:
    value = _get_mandatory_str(transaction, key)
    if len(value) < 1:
        # Is it failure of UI that value is not in allowed set (in which case it
        # should be RuntimeError) or we want to do this check only in daemon level
        # (in which case this is InvalidParameterError... Doing the latter for now
        raise InvalidParameterError(f"Entry string must not be empty: {key}")
    return value


def get_str_with_default(transaction: Mapping[str, Any], key: str, *, default: str) -> str:
    value = get_optional_str(transaction, key)
    if len(value) < 1:
        return default
    return value


# TODO: multimethod is the only one module with nicely supports overloading functions
# with multiple parameters, but according to this https://github.com/coady/multimethod/issues/82
# "strings are containers of strings" and that causes an issue on how to distinct
# an str object from Iterable on static analysis according to these issues
# https://github.com/python/mypy/issues/11001 and https://github.com/python/mypy/issues/5090
# it is a common problem which has to wait for a solution, currently we will stick to use
# of Iterable together with List instead of MyIterable
# class MyIterable(Iterable[T]):
#     @classmethod
#     def __subclasshook__(cls, subclass: type) -> bool:
#         return issubclass(subclass, Iterable) and not issubclass(subclass, str)

#     def __class_getitem__(cls, key: type) -> GenericAlias:
#         return GenericAlias(cls, key)


# TODO: we have discovered a bug in multimethod https://welotec.atlassian.net/browse/MPA-972
# For now we abandon the use of function overload treatment as it doesn't work on python correctly
# This bug is submitted to the upstream https://github.com/coady/multimethod/issues/84
# @multimethod
def validate_enum_list(key: str, value: str, allowed_values: Iterable[str]) -> None:
    if value in allowed_values:
        return
    # Is it failure of UI that value is not in allowed set (in which case it
    # should be RuntimeError) or we want to do this check only in daemon level
    # (in which case this is InvalidParameterError... Doing the latter for now
    raise InvalidParameterError(f"Unrecognized value '{value}' for {key}, expected one of {allowed_values}")


# @validate_enum_list.register
# def _(key: str, value: List[str], allowed_values: List[List[str]]) -> None:
def validate_enum_lists(key: str, value: List[str], allowed_values: List[List[str]]) -> None:
    # XXX: here sorted() is being used instead sort(), because
    # we do not want to modify the order given by user as it may
    # be done on purpose, this is only to verify existence of
    # value in allowed_values
    if sorted(value) in sorted([sorted(item) for item in allowed_values]):
        return
    # Is it failure of UI that value is not in allowed set (in which case it
    # should be RuntimeError) or we want to do this check only in daemon level
    # (in which case this is InvalidParameterError... Doing the latter for now
    raise InvalidParameterError(f"Unrecognized value '{value}' for {key}, expected one of {allowed_values}")


def get_optional_enum_str(transaction: Mapping[str, Any], key: str,
                          allowed_values: Iterable[str]) -> str:
    value = get_optional_str(transaction, key)
    if len(value) > 0:
        validate_enum_list(key, value, allowed_values)
    return value


def get_enum_str(transaction: Mapping[str, Any], key: str,
                 allowed_values: Iterable[str]) -> str:
    value = get_str(transaction, key)
    validate_enum_list(key, value, allowed_values)
    return value


def get_enum_str_list(transaction: Mapping[str, Any], key: str,
                      allowed_values: List[List[str]]) -> list[str]:
    value = get_list(transaction, key)
    # TODO: change when there will be a fix in multimethod code
    # validate_enum_list(key, value, allowed_values)
    validate_enum_lists(key, value, allowed_values)
    return value


def _get_bool(transaction: Mapping[str, Any], key: str) -> bool:
    value = transaction[key]
    if not isinstance(value, bool):
        # Invalid format of message is for sure error in UI code, hence RuntimeError
        raise RuntimeError(f"Entry must be a boolean: {key}")
    return value


get_optional_bool = make_optional(_get_type(bool, bool, "boolean"))
get_bool = make_mandatory(_get_type(bool, bool, "boolean"))
get_optional_int = make_optional(_get_type(int, int, "integer"))
get_int = make_mandatory(_get_type(int, int, "integer"))
get_optional_dict = make_optional(_get_type(Dict, Dict[str, Any], "subobject"))
get_dict = make_mandatory(_get_type(Dict, Dict[str, Any], "subobject"))
get_list = make_mandatory(_get_type(List, List[Any], "subobject"))


def _get_ip_with_optional_mask(construct_network_from_str: Callable[..., NetworkType]) -> GetterFunction[NetworkType]:
    def get_ip_and_mask(transaction: Mapping[str, Any], key: str) -> NetworkType:
        ip_addr = get_str(transaction, key)
        if '/' not in ip_addr:
            ip_addr += '/128' if ':' in ip_addr else '/32'
        try:
            return construct_network_from_str(ip_addr)
        except ValueError as exc:
            raise InvalidParameterError(f"Error in IP address `{key}`: {exc}")
    return get_ip_and_mask


# mypy raises error: A function returning TypeVar should receive at least one argument containing the same TypeVar
def _network_type_wrapper(ip_with_net: str) -> NetworkType:  # type: ignore
    # mypy raises 2 errors on with return
    #    error: Incompatible return value type
    #    (got "Union[IPv4Network, IPv6Network]", expected "IPv4Network")  [return-value]
    #    error: Incompatible return value type
    #    (got "Union[IPv4Network, IPv6Network]", expected "IPv6Network")  [return-value]
    return ipaddress.ip_network(ip_with_net)  # type: ignore  # TODO looks like bug in mypy?


get_ip4_with_optional_mask = _get_ip_with_optional_mask(ipaddress.IPv4Network)
get_ip6_with_optional_mask = _get_ip_with_optional_mask(ipaddress.IPv6Network)
get_ip46_with_optional_mask = _get_ip_with_optional_mask(_network_type_wrapper)
get_optional_ip4_with_optional_mask = make_optional(get_ip4_with_optional_mask)
get_optional_ip6_with_optional_mask = make_optional(get_ip6_with_optional_mask)
get_optional_ip46_with_optional_mask = make_optional(get_ip46_with_optional_mask)


def _get_ip(construct_ip_from_str: Callable[[str], T]) -> GetterFunction[T]:
    def get_ip(transaction: Mapping[str, Any], key: str) -> T:
        value = get_str(transaction, key)
        try:
            ip_addr = construct_ip_from_str(value)
        except ValueError as exc:
            raise InvalidParameterError(f"Error in IP address `{key}`: {exc}")
        return ip_addr
    return get_ip


# TODO mypy cannot properly deduce types returned by get_optional_ip46...
get_optional_ip46 = make_optional(_get_ip(ipaddress.ip_address))
get_optional_ip4 = make_optional(_get_ip(ipaddress.IPv4Address))
get_optional_ip6 = make_optional(_get_ip(ipaddress.IPv6Address))
get_ip46 = make_mandatory(_get_ip(ipaddress.ip_address))
get_ip4 = make_mandatory(_get_ip(ipaddress.IPv4Address))
get_ip6 = make_mandatory(_get_ip(ipaddress.IPv6Address))

IP4or6Address = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


def get_ip46_list(transaction: Mapping[str, Any], key: str) -> List[IP4or6Address]:
    list_of_potenial_ips = get_list(transaction, key)
    retval: List[IP4or6Address] = []
    for candidate_ip in list_of_potenial_ips:
        retval.append(ipaddress.ip_address(candidate_ip))
    return retval


class TwoKeyGetterFunction(Protocol[ReturnType_co]):
    def __call__(self, transaction: Mapping[str, Any], __key1: str, __key2: str) -> ReturnType_co:
        pass


def make_optional_two_key(fun: TwoKeyGetterFunction[ReturnType_co]) -> TwoKeyGetterFunction[Optional[ReturnType_co]]:
    def optional(transaction: Mapping[str, Any], key1: str, key2: str) -> Optional[ReturnType_co]:
        if key1 in transaction and key2 in transaction:
            return fun(transaction, key1, key2)
        if key1 in transaction:
            raise InvalidParameterError("Entry '{key2}' was missing but it was required because entry '{key1}' was provided")
        if key2 in transaction:
            raise InvalidParameterError("Entry '{key1}' was missing but it was required because entry '{key2}' was provided")
        return None
    return optional


IpType = TypeVar("IpType")
NetworkType = TypeVar("NetworkType", ipaddress.IPv4Network, ipaddress.IPv6Network)


def _get_ip_and_mask(ip_getter: GetterFunction[IpType],
                     construct_network_from_str: Callable[..., NetworkType]) -> TwoKeyGetterFunction[NetworkType]:
    def get_ip_and_mask(transaction: Mapping[str, Any], ip_key: str, mask_key: str) -> NetworkType:
        ip_addr = ip_getter(transaction, ip_key)
        mask = get_str(transaction, mask_key)
        try:
            return construct_network_from_str(f"{ip_addr}/{mask}")
        except ValueError:
            try:
                network_address = construct_network_from_str(f"{ip_addr}/{mask}", strict=False)
                proposed_correct_address = f"{network_address.network_address}/{mask}"
            except ValueError as exc:
                raise InvalidParameterError(f"Error in IP network provided in '{ip_key}' and '{mask_key}': {exc}")
            raise InvalidParameterError(f"Error in IP network provided in '{ip_key}' and '{mask_key}': address and subnet "
                                        f"together are not valid, (did you mean '{ip_key}' to be {proposed_correct_address}?)")
    return get_ip_and_mask


get_ip4_and_mask = _get_ip_and_mask(get_ip4, ipaddress.IPv4Network)
get_ip6_and_mask = _get_ip_and_mask(get_ip6, ipaddress.IPv6Network)
get_ip46_and_mask = _get_ip_and_mask(get_ip46, _network_type_wrapper)
get_optional_ip4_and_mask = make_optional_two_key(get_ip4_and_mask)
get_optional_ip6_and_mask = make_optional_two_key(get_ip6_and_mask)
get_optional_ip46_and_mask = make_optional_two_key(get_ip46_and_mask)


def _get_port(transaction: Mapping[str, Any], key: str) -> str:
    port = get_str(transaction, key)
    try:
        int_port = int(port)
        if int_port < 1 or int_port > 65535:
            raise InvalidParameterError(f"Value `{port}` for entry `{key}` is not positive integer below 65536")
    except ValueError:
        if re.fullmatch(r"\w+", port):
            try:
                run_command("grep", "-q", f"^{port}\\W", f"{CONFIG_DIR_ROOT / 'services'}")
            except CalledProcessError:
                raise InvalidParameterError(f"Value `{port}` for entry `{key}` is not known port name")
        else:
            raise InvalidParameterError(f"Value `{port}` for entry `{key}` contains "
                                        "invalid characters and cannot be a port name or value")
    return port


# Note that port is returned as string (as you can use either port number or name)
get_port = make_mandatory(_get_port)
get_optional_port = make_optional_with_default(_get_port, "")
