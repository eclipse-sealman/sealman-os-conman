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
import base64
import re
from typing import Any, Iterable, Mapping, MutableMapping, Tuple, Union
from os import PathLike


def is_marker_in_line(line: str) -> bool:
    markers = ["<ca>", "</ca>",
               "<cert>", "</cert>",
               "<key>", "</key>",
               "<tls-auth>", "</tls-auth>"]
    for marker in markers:
        if line.strip() == marker:
            return True
    return False


def get_marker(line: str) -> str:
    if is_marker_in_line(line):
        return line.strip().strip("<").strip(">")
    else:
        return "none"


def is_ending_marker(line: str) -> bool:
    marker = get_marker(line)
    if len(marker) > 0 and marker[0] == '/':
        return True
    return False


def parse_params(line: str) -> Tuple[str, str]:
    line = line.strip()
    first_space = line.find(" ")
    if first_space == -1:
        return line, "true"
    return line[:first_space], line[first_space+1:]


def encode(file_content: Iterable[str]) -> Mapping[str, str]:
    markers = {'ca', 'cert', 'key', 'tls-auth'}
    content = dict()
    key = "line"
    for line in file_content:
        if ";" in line and line[0] == ";":
            continue
        marker = get_marker(line)
        if is_ending_marker(line):
            key = "line"
            continue
        if marker != "none":
            key = marker
            content[marker] = ""
            continue
        if key == "line":
            if line.strip() == "":
                continue
            params = parse_params(line)
            content[params[0]] = params[1]
        else:
            content[key] += line

    for marker in markers:
        if marker in content:
            content[marker] = base64.b64encode(content[marker].encode('utf-8')).decode('utf-8')
    return content


def decode(content: MutableMapping[str, str]) -> MutableMapping[str, str]:
    markers = {'ca', 'cert', 'key', 'tls-auth'}
    for item in content:
        if item in markers:
            continue
    for item in content:
        if item in markers:
            content[item] = base64.b64decode(content[item]).decode('utf-8')
    return content


def encode_from_file(filename: Union[str, bytes, PathLike[Any]]) -> Mapping[str, str]:
    content: Mapping[str, str] = dict()
    try:
        with open(filename, "r") as file:
            configfile = file.readlines()
        content = encode(configfile)
    except IOError:
        print(f"File not accessible - vpn config file not found {filename!r}.")
    return content


def decode_to_file(content: MutableMapping[str, str], filename: Union[str, bytes, PathLike[Any]]) -> None:
    markers = {'ca', 'cert', 'key', 'tls-auth'}
    tmp = decode(content)
    if len(tmp) == 0:
        return
    try:
        with open(filename, "w") as file:
            for item in tmp:
                if item not in markers:
                    param = "" if content[item] == 'true' else " " + content[item]
                    line = item + param + "\n"
                    file.write(line)
            for item in tmp:
                if item in markers:
                    line = "\n<" + item + ">\n" + content[item] + "\n</" + item + ">\n"
                    line = re.sub(r'(\n\s*)+\n', '\n', line)
                    file.write(line)
    except IOError:
        print("Problem with file creation.")
    pass
