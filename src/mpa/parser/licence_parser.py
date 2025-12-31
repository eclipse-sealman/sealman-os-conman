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
import glob
import os.path
import pydoc

LICENCE_DIRECTORY = "/usr/share/common-licenses"
MANIFEST_FILE = "license.manifest"


def get_oss() -> str:
    with open(f"{LICENCE_DIRECTORY}/{MANIFEST_FILE}", "r") as manifest:
        manifest_data = manifest.read().split('\n')
    while ("" in manifest_data):
        manifest_data.remove("")

    listOfPackages = []
    globalLic = ""
    for x in range(0, len(manifest_data), 4):
        package = {"name": manifest_data[x].split(":")[1].strip(),
                   "version": manifest_data[x+1].split(":")[1].strip(),
                   "licence": manifest_data[x+3].split(":")[1].strip()}
        listOfPackages.append(package)

    for p in listOfPackages:
        lic = ""
        files = glob.glob(f'{LICENCE_DIRECTORY}/{p["name"]}/[!generic_]*')
        for licFile in files:
            copying_file = f"{LICENCE_DIRECTORY}/{p['name']}/{os.path.basename(licFile)}"
            if os.path.isfile(copying_file):
                with open(copying_file, "r") as copying:
                    try:
                        temp = copying.read().split('\n\n')
                        lic += temp[0]
                        if len(temp) > 1:
                            lic += temp[1]
                    except Exception:
                        pass

        pkgLic = f"{p['name']} \nVersion: {p['version']} \n {lic} \nLicences: {p['licence']} (see below) \n\n\n"
        globalLic += pkgLic

    genericLicence = glob.glob(f"{LICENCE_DIRECTORY}/generic*")
    for generic in genericLicence:
        with open(generic, "r") as generic_file:
            globalLic += generic_file.read()
    return globalLic


if __name__ == "__main__":
    pydoc.pager(get_oss())
