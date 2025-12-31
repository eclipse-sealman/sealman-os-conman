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
import copy
import json
import os
import re
import sys
from packaging.version import Version
from pathlib import Path
from typing import Any, Dict, Iterable, Mapping, MutableMapping, Optional, Union

# Third party imports
import toml

# Local imports
from mpa.common.common import RESPONSE_OK
from mpa.common.logger import Logger
from mpa.communication import client as com_client
from mpa.communication.common import (
    expect_empty_message,
    filter_dict,
    filter_out_dict_in_place,
    get_single_string,
    InvalidPayloadError,
    merge_dictionaries,
)
from mpa.communication.inter_process_lock import InterProcessLock
from mpa.communication.message_parser import get_enum_str, get_file, get_str, get_str_with_default, get_dict
from mpa.communication.process import run_command, run_command_unchecked
from mpa.config.common import (
    AZURE_CONFIG_VALIDATED_PATH,
    CONFIG_DIR_ROOT,
    CONFIG_FORMAT_VERSION_TO_ASSUME_FOR_UNVERSIONED_CONFIG
)
from mpa.config.configfiles import ConfigFiles
from mpa.device.common import (
    CONFIG_KEY_DEVICE_ID_CERT,
    CONFIG_KEY_DEVICE_ID_PK,
    CONFIG_KEY_EDGE_CA_CERT,
    CONFIG_KEY_EDGE_CA_PK,
    CONFIG_KEY_TRUST_BUNDLE_CERT,
)

logger = Logger(f"{sys.argv[0] if __name__ == '__main__' else __name__}")

VAR_LIB_IOTEDGE = Path('/var/lib/iotedge')


class Azure:
    class DPS:
        X509_CERT_DIR = CONFIG_DIR_ROOT / "eg/certs/iotedge_dps_x509"
        X509_CERT_DIR.mkdir(parents=True, exist_ok=True)
        device_id_cert_path = X509_CERT_DIR / "device-id.pem"
        device_id_pk_path = X509_CERT_DIR / "device-id.key.pem"
        X509_CONFIG_KEY_TO_FILE_PATH: MutableMapping[str, Path] = {
            CONFIG_KEY_DEVICE_ID_CERT: device_id_cert_path,
            CONFIG_KEY_DEVICE_ID_PK: device_id_pk_path,
        }

        placeholder: MutableMapping[str, Any] = {
            'source': 'dps',
            'global_endpoint': 'https://global.azure-devices-provisioning.net',
            'id_scope': '<scope_id>',
            'attestation': '<attestation>',
        }

        tpm_placeholder: MutableMapping[str, Any] = {
            **placeholder,
            'attestation': {
                'method': 'tpm',
                'registration_id': '<registration_id>'
            }
        }

        x509_placeholder: MutableMapping[str, Any] = {
            **placeholder,
            'attestation': {
                'method': 'x509',
                'identity_cert': device_id_cert_path.as_uri(),
                'identity_pk': device_id_pk_path.as_uri()
            }
        }

    # We added incompatible changes between 0.1 and 1.0 in this file
    # Everything below 2.0 shall be compatible with code here
    FIRST_INCOMPATIBLE_CONFIG_VERSION = "2.0"

    AZURE_LOCK = InterProcessLock(Path(CONFIG_DIR_ROOT / "mgmtd/lock.azure"), stale_lock_seconds=600)
    NON_MODIFIABLE_IOTEDGE_CONFIG_ELEMENTS: MutableMapping[str, Any] = {
            CONFIG_KEY_TRUST_BUNDLE_CERT: None,
            "edge_ca": {CONFIG_KEY_EDGE_CA_CERT: None, CONFIG_KEY_EDGE_CA_PK: None},
            "connect": {"management_uri": None, "workload_uri": None},
            "listen": {"management_uri": None, "workload_uri": None},
            "moby_runtime": None
            }

    def __init__(self, *, cert_dir: Path = CONFIG_DIR_ROOT / 'eg/certs/iotedge') -> None:
        config_files = ConfigFiles()
        config_files.set_first_incompatible_config_format_version(self.FIRST_INCOMPATIBLE_CONFIG_VERSION)
        self.AZURE_CONFIG_FILE = config_files.add("azure_config", "aziot/config.toml")
        # the presence of this file matters for the function get_edge_modules() in mpa_code/docker/mgmtd-compose
        self.AZURE_CONFIG_FILE_VALIDATED = config_files.add(AZURE_CONFIG_VALIDATED_PATH.name,
                                                            AZURE_CONFIG_VALIDATED_PATH,
                                                            config_dir_root=Path("/"),
                                                            is_expected=False)
        self.IOTEDGE_INTERNAL_CERT_DIR_1 = config_files.add("iotedge_internal_certs_dir", 'hsm/certs',
                                                            config_dir_root=VAR_LIB_IOTEDGE, is_expected=False)
        self.IOTEDGE_INTERNAL_CERT_DIR_2 = config_files.add("iotedge_internal_cert_keys_dir", 'hsm/cert_keys',
                                                            config_dir_root=VAR_LIB_IOTEDGE, is_expected=False)
        self.IOTEDGE_CUSTOM_CERT_DIR = cert_dir
        cert_dir.mkdir(parents=True, exist_ok=True)
        config_files.verify()

        custom_edge_ca_cert_path = self.IOTEDGE_CUSTOM_CERT_DIR / "edge-ca.pem"
        custom_edge_ca_key_path = self.IOTEDGE_CUSTOM_CERT_DIR / "edge-ca.key.pem"
        custom_trust_bundle_cert_path = self.IOTEDGE_CUSTOM_CERT_DIR / "trust-bundle.pem"

        self.TRUST_BUNDLE_URI = custom_trust_bundle_cert_path.as_uri()

        self.TRUST_BUNDLE_CONFIG_KEY_TO_FILE_PATH: MutableMapping[str, Path] = {
            CONFIG_KEY_TRUST_BUNDLE_CERT: custom_trust_bundle_cert_path
        }

        self.EDGE_CA_CONFIG_KEY_TO_FILE_PATH: MutableMapping[str, Path] = {
                CONFIG_KEY_EDGE_CA_CERT: custom_edge_ca_cert_path,
                CONFIG_KEY_EDGE_CA_PK: custom_edge_ca_key_path,
        }

        self.EDGE_CERTIFICATES_PLACEHOLDER: MutableMapping[str, Any] = {}
        for key, file_path in self.EDGE_CA_CONFIG_KEY_TO_FILE_PATH.items():
            self.EDGE_CERTIFICATES_PLACEHOLDER[key] = file_path.as_uri()

        self.connectionstring_placeholder: MutableMapping[str, Any] = {
            'source': 'manual',
            'connection_string': '<device_connection_string>'
            }

    # TODO single underscore because we use it in UT for now --- find a better way
    def _load_azure_config(self) -> MutableMapping["str", Any]:
        with open(self.AZURE_CONFIG_FILE, 'r') as file:
            toml_dump = toml.load(file)
        assert isinstance(toml_dump, MutableMapping)
        return toml_dump

    def __save_azure_config(self, toml_config: Mapping[str, Any]) -> None:
        with open(self.AZURE_CONFIG_FILE, "w") as file:
            toml.dump(toml_config, file)
        self.__apply_config_if_possible()

    def __set_toml_dump_subtree(self, subtree_name: str, new_entries: Union[str, Mapping[str, Any]],
                                toml_dump: MutableMapping[str, Any]) -> None:
        if subtree_name in toml_dump:
            toml_dump.pop(subtree_name)
        toml_dump.update({subtree_name: new_entries})

    def __set_hostname(self, hostname: str, toml_dump: MutableMapping["str", Any]) -> None:
        run_command(f"pkexec hostnamectl set-hostname {hostname}")

        hosts = Path("/etc/hosts")
        content = hosts.read_text()
        new_hostname_string = f"127.0.1.1 {hostname}"
        if "127.0.1.1" in content:
            new_content = re.sub(r"127\.0\.1\.1\s+(\w+)", new_hostname_string, content, count=1)
        else:
            new_content = content + "\n" + new_hostname_string

        hosts.write_text(new_content)
        self.__set_toml_dump_subtree('hostname', hostname, toml_dump)

    def __set_provisioning_mode(self, mode: str, toml_dump: MutableMapping["str", Any]) -> None:
        self.__set_toml_dump_subtree('auto_reprovisioning_mode', mode, toml_dump)

    def __set_provisioning(self, provisioning_entries: Mapping[str, Any], toml_dump: MutableMapping[str, Any]) -> None:
        self.__set_toml_dump_subtree('provisioning', provisioning_entries, toml_dump)

    def __apply_config_if_possible(self) -> None:
        if self.AZURE_CONFIG_FILE_VALIDATED.exists():
            run_command("pkexec iotedge config apply")
        else:
            if run_command_unchecked("pkexec iotedge config apply").returncode == 0:
                self.AZURE_CONFIG_FILE_VALIDATED.touch()

    def set_hostname(self, message: bytes) -> str:
        config = json.loads(message)
        with self.AZURE_LOCK.transaction("setting Azure hostname"):
            hostname = get_str(config, 'hostname')
            toml_dump = self._load_azure_config()
            self.__set_hostname(hostname, toml_dump)
            self.__save_azure_config(toml_dump)
            return (f"{RESPONSE_OK} Hostname successfully changed to {hostname}. "
                    "Please logout and login again to see the new hostname.")

    def set_connection_string(self, message: bytes) -> None:
        with self.AZURE_LOCK.transaction("setting connection string"):
            toml_dump = self._load_azure_config()
            self.connectionstring_placeholder['connection_string'] = get_single_string(message, 'device_connection_string')
            self.__set_provisioning(self.connectionstring_placeholder, toml_dump)
            self.__save_azure_config(toml_dump)

    def set_tpm(self, message: bytes) -> None:
        with self.AZURE_LOCK.transaction("setting TPM Azure parameters"):
            toml_dump = self._load_azure_config()
            config: Mapping[str, Any] = json.loads(message)
            self.DPS.tpm_placeholder['attestation']['registration_id'] = get_str(config, 'registration_id')
            self.DPS.tpm_placeholder['id_scope'] = get_str(config, 'scope_id')
            self.__set_provisioning(self.DPS.tpm_placeholder, toml_dump)
            self.__save_azure_config(toml_dump)

    def set_x509(self, message: bytes) -> None:
        if not self.DPS.X509_CERT_DIR.exists():
            os.makedirs(self.DPS.X509_CERT_DIR)
        with self.AZURE_LOCK.transaction("setting X.509 Azure parameters"):
            toml_dump = self._load_azure_config()
            config = json.loads(message)
            self.DPS.x509_placeholder['id_scope'] = get_str(config, 'scope_id')
            config.pop('scope_id')
            self.__set_cert_x509_content(config)
            self.__set_provisioning(self.DPS.x509_placeholder, toml_dump)
            self.__save_azure_config(toml_dump)

    def __clean_directories(self, *directories: Path) -> None:
        for directory in directories:
            if directory.exists():
                for path in directory.iterdir():
                    run_command(f"pkexec rm -f {path.absolute()}")

    def __chown(self, owner: str, group: str, *files: Path) -> None:
        for file in files:
            run_command(f"pkexec /bin/chown {owner}:{group} {file}")

    def __chmod(self, mod: int, *files: Path) -> None:
        for file in files:
            run_command(f"pkexec /bin/chmod {mod} {file}")

    def __set_cert_content(
        self,
        certificates_path: Mapping[str, Path],
        certificates_content: Mapping[str, str],
        directories_to_clean: Iterable[Path],
    ) -> None:
        file_to_content: MutableMapping[Path, str] = {}
        for key, file_path in certificates_path.items():
            file_to_content[file_path] = get_file(certificates_content, key)
        self.__clean_directories(*directories_to_clean)
        for path, content in file_to_content.items():
            path.write_text(content)
        for key, file_path in certificates_path.items():
            # IoT Edge requires aziotcs to be the owner of the certificates and
            # aziotks to be the owner of private keys
            # https://learn.microsoft.com/en-us/azure/iot-edge/how-to-manage-device-certificates?view=iotedge-1.4&tabs=ubuntu#permission-requirements
            if key.endswith("cert"):
                self.__chown("aziotcs", "mgmtd", file_path)
                self.__chmod(644, file_path)
            elif key.endswith("pk"):
                self.__chown("aziotks", "mgmtd", file_path)
                self.__chmod(640, file_path)
            else:
                raise NotImplementedError

    def __set_cert_x509_content(self, certificates_content: Mapping[str, str]) -> None:
        self.__set_cert_content(self.DPS.X509_CONFIG_KEY_TO_FILE_PATH, certificates_content, [self.DPS.X509_CERT_DIR])

    def __set_cert_edge_ca_content(self, certificates_content: Mapping[str, str]) -> None:
        self.__set_cert_content(
            {**self.EDGE_CA_CONFIG_KEY_TO_FILE_PATH, **self.TRUST_BUNDLE_CONFIG_KEY_TO_FILE_PATH},
            certificates_content,
            [self.IOTEDGE_INTERNAL_CERT_DIR_1, self.IOTEDGE_INTERNAL_CERT_DIR_2, self.IOTEDGE_CUSTOM_CERT_DIR],
        )

    def set_cert(self, message: bytes) -> None:
        data = json.loads(message)

        # TODO move iotedge start to __exit__()
        with self.AZURE_LOCK.transaction("adding iotedge certificates"):
            try:
                run_command("pkexec aziotctl system stop")
                toml_dump = self._load_azure_config()
                if 'edge_ca' in toml_dump:
                    toml_dump['edge_ca'].update(self.EDGE_CERTIFICATES_PLACEHOLDER)
                else:
                    toml_dump['edge_ca'] = self.EDGE_CERTIFICATES_PLACEHOLDER
                toml_dump[CONFIG_KEY_TRUST_BUNDLE_CERT] = self.TRUST_BUNDLE_URI
                self.__set_cert_edge_ca_content(data)
                #  We touch actual config at last, so in case of any exception earlier
                #  we will not change it
                self.__save_azure_config(toml_dump)
            finally:
                run_command("pkexec aziotctl system restart")

    def remove_cert(self, message: bytes) -> None:
        expect_empty_message(message, "azure_remove_cert()")
        # TODO move iotedge start to __exit__()
        with self.AZURE_LOCK.transaction("removing iotedge certificates"):
            toml_dump = self._load_azure_config()
            if all(key not in toml_dump for key in ("edge_ca", CONFIG_KEY_TRUST_BUNDLE_CERT)):
                logger.info("certificates key not present in config")
                return
            run_command("pkexec aziotctl system stop")
            try:
                self.__clean_directories(
                    self.IOTEDGE_INTERNAL_CERT_DIR_1,
                    self.IOTEDGE_INTERNAL_CERT_DIR_2,
                    self.IOTEDGE_CUSTOM_CERT_DIR,
                )
                toml_dump = self._load_azure_config()
                # TODO do we want to pop whole 'certificates' key, or only subkeys from CERTIFICATES_PLACEHOLDER ?
                if "edge_ca" in toml_dump:
                    for key in self.EDGE_CERTIFICATES_PLACEHOLDER:
                        toml_dump["edge_ca"].pop(key)
                if CONFIG_KEY_TRUST_BUNDLE_CERT in toml_dump:
                    toml_dump.pop(CONFIG_KEY_TRUST_BUNDLE_CERT)
                self.__save_azure_config(toml_dump)
            finally:
                run_command("pkexec aziotctl system restart")

    def __set_config_version_0_1(self, azure_config: Dict[str, Any]) -> MutableMapping[str, Any]:
        toml_dump = self._load_azure_config()
        toml_dump.pop('hostname')
        toml_dump.update({'hostname': get_str(azure_config, 'hostname')})

        source = get_enum_str(azure_config, 'source', ['manual', 'dps'])
        if source == 'manual':
            self.connectionstring_placeholder['connection_string'] = get_str(azure_config, 'device_connection_string')
            self.__set_provisioning(self.connectionstring_placeholder, toml_dump)
        else:
            self.DPS.tpm_placeholder['attestation']['registration_id'] = get_str(azure_config, 'registration_id')
            self.DPS.tpm_placeholder['id_scope'] = get_str(azure_config, 'scope_id')
            self.__set_provisioning(self.DPS.tpm_placeholder, toml_dump)
        return toml_dump

    def __set_config_version_1_0(self, azure_config: Dict[str, Any]) -> MutableMapping[str, Any]:
        incoming_toml = azure_config['config']
        filter_out_dict_in_place(incoming_toml, self.NON_MODIFIABLE_IOTEDGE_CONFIG_ELEMENTS)
        new_toml = filter_dict(self._load_azure_config(), self.NON_MODIFIABLE_IOTEDGE_CONFIG_ELEMENTS)
        merge_dictionaries(new_toml, incoming_toml)
        return new_toml

    def set_config(self, message: bytes) -> None:
        config = json.loads(message)
        incoming_azure_config = get_dict(config, 'azure')
        # Initially (before config format versioning was introduced, and we assume
        # that this "unversioned" format is 0.1) we kept few specific fields in
        # azure config and certificate data in subtree certificates
        # Config format versions between 0.1 and 1.0 are nice way for testing
        # Config format version 1.0 uses whole config.toml but filters out few
        # special keys to prevent users from easily breaking the config.
        config_format_version = config.pop('config_format_version', CONFIG_FORMAT_VERSION_TO_ASSUME_FOR_UNVERSIONED_CONFIG)
        with self.AZURE_LOCK.transaction("setting whole Azure config"):
            if get_str_with_default(incoming_azure_config, "validated", default="0") == "1":
                self.AZURE_CONFIG_FILE_VALIDATED.touch()
            else:
                self.AZURE_CONFIG_FILE_VALIDATED.unlink(missing_ok=True)
            if Version(config_format_version) < Version(self.FIRST_INCOMPATIBLE_CONFIG_VERSION):
                new_toml_config = self.__set_config_version_1_0(incoming_azure_config)
                if 'certificates_content' in incoming_azure_config:
                    self.__set_cert_edge_ca_content(get_dict(incoming_azure_config, 'certificates_content'))
                    if 'edge_ca' in new_toml_config:
                        new_toml_config['edge_ca'].update(self.EDGE_CERTIFICATES_PLACEHOLDER)
                    else:
                        new_toml_config['edge_ca'] = self.EDGE_CERTIFICATES_PLACEHOLDER
                    new_toml_config[CONFIG_KEY_TRUST_BUNDLE_CERT] = self.TRUST_BUNDLE_URI
            elif Version(config_format_version) == Version(CONFIG_FORMAT_VERSION_TO_ASSUME_FOR_UNVERSIONED_CONFIG):
                new_toml_config = self.__set_config_version_0_1(incoming_azure_config)
            else:
                raise InvalidPayloadError("Incompatible config version {config_format_version}")
            self.__set_hostname(get_str(new_toml_config, 'hostname'), new_toml_config)
            self.__set_provisioning_mode(get_str_with_default(incoming_azure_config,
                                                              "auto_reprovisioning_mode",
                                                              default="Dynamic"),
                                         new_toml_config)
            self.__save_azure_config(new_toml_config)

    def read_config(self, export_private_keys: bool) -> MutableMapping[str, Any]:
        config: MutableMapping[str, Any] = {}
        config = self._load_azure_config()
        expect_edge_cert = False
        if "edge_ca" in config and CONFIG_KEY_EDGE_CA_CERT in config["edge_ca"]:
            expect_edge_cert = True
        expect_trust_bundle_cert = False
        if CONFIG_KEY_TRUST_BUNDLE_CERT in config:
            expect_trust_bundle_cert = True
        filter_out_dict_in_place(config, self.NON_MODIFIABLE_IOTEDGE_CONFIG_ELEMENTS)
        output = {'azure': {"config": config, "validated": "0"}}
        if self.AZURE_CONFIG_FILE_VALIDATED.exists():
            output['azure']['validated'] = "1"

        if expect_edge_cert:
            certificates_content = {}
            # We are going to throw on missing cert, in such case user will need to
            # run remove certificates with remove_cert or set new certificates
            # before being able to successfuly get_config
            for key, file_path in self.EDGE_CA_CONFIG_KEY_TO_FILE_PATH.items():
                certificates_content[key] = file_path.read_text()
            # config without private key will be obviously not settable by design
            if not export_private_keys:
                certificates_content.pop(CONFIG_KEY_EDGE_CA_PK)
            output['azure']['certificates_content'] = certificates_content
        if expect_trust_bundle_cert:
            trust_bundle_cert = self.TRUST_BUNDLE_CONFIG_KEY_TO_FILE_PATH[CONFIG_KEY_TRUST_BUNDLE_CERT]
            content = {
                CONFIG_KEY_TRUST_BUNDLE_CERT: trust_bundle_cert.read_text()
            }
            if expect_edge_cert:
                assert isinstance(output["azure"]["certificates_content"], dict)
                output["azure"]["certificates_content"].update(content)
            else:
                output["azure"]["certificates_content"] = content
        return output

    # TODO why do we disable coverage here?
    def get_config(self, *, with_privates: bool) -> com_client.SyncHandlerCallable:    # pragma: no cover
        def handler(message: bytes) -> Mapping[str, Any]:
            expect_empty_message(message, "azure_get_config()")
            return self.read_config(with_privates)
        return handler

    def get_configfile(self, message: bytes) -> Dict[str, Any]:
        expect_empty_message(message, "Azure.get_configfile()")
        with self.AZURE_LOCK.transaction("getting whole Azure config"):
            toml_dump = self._load_azure_config()
            output = {'azure_configfile': toml_dump}
        return output

    def __set_config_entries(self, message: bytes, *, remove_entries_not_present_in_incoming_config: bool) -> Optional[str]:
        removed_something = False
        decoded_message = json.loads(message)
        if isinstance(decoded_message["azure_configfile"], str):
            incoming_toml = toml.loads(get_str(decoded_message, "azure_configfile"))
        elif isinstance(decoded_message["azure_configfile"], dict):
            incoming_toml = get_dict(decoded_message, "azure_configfile")
        else:
            raise InvalidPayloadError("Expected to get str or dict")

        old_toml = self._load_azure_config()
        if filter_out_dict_in_place(incoming_toml, self.NON_MODIFIABLE_IOTEDGE_CONFIG_ELEMENTS):
            removed_something = True
        shall_set_hostname = False
        if remove_entries_not_present_in_incoming_config:
            if 'hostname' in incoming_toml:
                removed_something = True
            # TODO add hostname in default config so it is always present in
            # old_toml or change the way we set hostname in azure 1.2 completly
            # (e.g. ban hostname in config totally)
            if 'hostname' in old_toml:
                incoming_toml['hostname'] = old_toml['hostname']
            else:
                incoming_toml.pop('hostname')
            new_toml = filter_dict(old_toml, self.NON_MODIFIABLE_IOTEDGE_CONFIG_ELEMENTS)
            merge_dictionaries(new_toml, incoming_toml)
        else:
            new_toml = copy.copy(old_toml)  # shallow copy to just check hostname later
            merge_dictionaries(new_toml, incoming_toml, overwrite_existing_keys=True)
            if 'hostname' in incoming_toml:
                if 'hostname' not in old_toml:
                    shall_set_hostname = True
                elif incoming_toml['hostname'] != old_toml['hostname']:
                    shall_set_hostname = True

        with self.AZURE_LOCK.transaction("setting whole Azure config file"):
            if shall_set_hostname:
                self.__set_hostname(get_str(incoming_toml, 'hostname'), new_toml)
            self.__save_azure_config(new_toml)
        if removed_something:
            return (f"{RESPONSE_OK} New config applied, but some entries were ignored "
                    "(for example we do not allow setting of hostname or certificates this way)")
        return None

    def clean_keys(self, message: bytes) -> str:
        """Delete empty aziot key files and restart IoT Edge services."""
        expect_empty_message(message, "Azure.clean_keys()")
        run_command("pkexec /usr/sbin/eg_aziot_clean_keys")
        logger.info("Deleted empty aziot keys (if any)")
        run_command("pkexec aziotctl system restart")
        logger.info("Azure IoT system restarted.")
        return f"{RESPONSE_OK} Removed empty key files (if any) and restarted IoT Edge."

    def set_configfile(self, message: bytes) -> Optional[str]:
        self.AZURE_CONFIG_FILE_VALIDATED.touch()
        return self.__set_config_entries(message, remove_entries_not_present_in_incoming_config=True)

    def set_option(self, message: bytes) -> Optional[str]:
        return self.__set_config_entries(message, remove_entries_not_present_in_incoming_config=False)
