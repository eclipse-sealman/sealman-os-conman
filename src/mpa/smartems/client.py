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
import os
import copy
import json
from pathlib import Path
from typing import Any, Protocol

import requests
import toml
from requests.auth import HTTPBasicAuth
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_delay,
    wait_exponential,
)

from .common import DeviceContext, FirmwareDownloadError, FirmwareNoSpaceError, SmartEmsError
from .config import SmartEmsConfig
from .messenger import Messenger
from mpa.communication.message_parser import get_optional_str
from mpa.device.common import PROXY_CONFIG_FILE


class SmartEmsClient(Protocol):
    def send_transaction(self, transaction: dict[str, Any]) -> Any: ...

    def download(self, url: str) -> Path: ...


class DefaultSmartEmsClient:
    def __init__(
        self,
        context: DeviceContext,
        config: SmartEmsConfig,
        download_directory: Path,
        messenger: Messenger,
        debug_mode: bool = False,
    ) -> None:
        self._session = requests.Session()
        self._context = context
        self._config = config
        self._download_directory = download_directory
        self._messenger = messenger
        self._debug_mode = debug_mode

    def _request(self, method: str, url: str, **kwargs: Any) -> requests.Response:
        kwargs.setdefault("timeout", 31)
        kwargs.setdefault("verify", self._config.get_cert_status(self._debug_mode))
        kwargs.setdefault("auth", HTTPBasicAuth(self._config.username, self._config.password))
        kwargs.setdefault("proxies", self._get_proxies())

        head_response = self._session.request("HEAD", url, allow_redirects=True, **kwargs)
        if head_response.status_code == 404:
            raise SmartEmsError(f"System was unable to connect to: {url}")

        response = self._session.request(method, head_response.url, **kwargs)
        if 200 <= response.status_code < 300:
            return response
        if response.status_code == 400:
            try:
                status_400_response = response.json()
            except json.JSONDecodeError as exc:
                raise SmartEmsError(exc)
            errors = self.__extract_http_errors_from_response(status_400_response)
            raise SmartEmsError(f"Smart EMS was unable to process the request, following errors were discovered: {errors}")
        elif response.status_code == 401:
            raise SmartEmsError("Unauthorized, please check your credentials.")
        elif response.status_code == 404:
            raise SmartEmsError("Endpoint not found, please check URL.")
        else:
            raise SmartEmsError(f"Smart EMS returns {response.status_code}")

    def _get(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("GET", url, **kwargs)

    def _head(self, url: str, **kwargs: Any) -> requests.Response:
        return self._request("HEAD", url, **kwargs)

    def send_transaction(self, transaction: dict[str, Any]) -> Any:
        if not self._config.url:
            self._messenger.send("smart_ems.rt", "Smart EMS URL is not configured")
            return {}

        transaction.pop("save_count", None)
        response = self._request("POST", self._config.get_url(), json={**self._context.to_dict(), **transaction})
        data = response.json()
        if len(data) == 1 and "error" in data:
            return data

        serial_number = data.pop("serialNumber", None)
        if serial_number is None or serial_number != self._context.serial_number:
            raise SmartEmsError("Serial number mismatch")

        return data

    @staticmethod
    def _get_proxies() -> dict[str, str]:
        if not PROXY_CONFIG_FILE.exists():
            return {}

        config = toml.loads(PROXY_CONFIG_FILE.read_text())

        return {
            "http": get_optional_str(config, "http_proxy"),
            "https": get_optional_str(config, "https_proxy"),
        }

    def download(self, url: str, **kwargs: Any) -> Path:
        try:
            content_length = self._get_content_length(url, **kwargs)
            self._check_available_space(content_length)
            path = self._download_directory / f"{url.split('/')[-1]}"
            self._download(url=url, local_path=path, content_length=content_length, **kwargs)
            return path

        except FirmwareNoSpaceError:
            raise

        except FirmwareDownloadError:
            raise

        except Exception as exc:
            raise FirmwareDownloadError(f"Unable to download firmware: {exc}") from exc

    def _get_content_length(self, url: str, **kwargs: Any) -> int:
        try:
            response = self._head(url, **kwargs)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise FirmwareDownloadError(f"Unable to determine firmware size: {exc}") from exc

        value = response.headers.get("Content-Length")
        if value is None:
            raise FirmwareDownloadError("Firmware response does not contain Content-Length")

        try:
            return int(value)
        except ValueError as exc:
            raise FirmwareDownloadError(f"Invalid firmware Content-Length: {value!r}") from exc

    def _check_available_space(self, content_length: int) -> None:
        stats = os.statvfs(self._download_directory)
        free_bytes = stats.f_frsize * stats.f_bfree
        if content_length > free_bytes:
            raise FirmwareNoSpaceError(
                f"Not enough space to download firmware. Required: {content_length} bytes, available: {free_bytes} bytes."
            )

    @retry(
        stop=stop_after_delay(1800),
        wait=wait_exponential(min=2, max=60),
        retry=retry_if_exception_type(requests.ConnectionError),
        reraise=True,
    )
    def _download(self, url: str, local_path: Path, content_length: int, chunk_size: int = 8192, **kwargs: Any) -> None:
        # TODO what if the file aleady exists and is the size of content length?
        # should we remove it and download it again or return immediately if the size matches?
        filesize = local_path.stat().st_size if local_path.exists() else 0
        try:
            response = self._get(url, stream=True, headers={"Range": f"bytes={filesize}-"}, **kwargs)
            response.raise_for_status()
            mode = "ab" if filesize else "wb"
            with local_path.open(mode) as file:
                for chunk in response.iter_content(chunk_size=chunk_size):
                    if chunk:
                        filesize += file.write(chunk)
                        if filesize % 100000 == 0:
                            msg = f"Download progress: {filesize / content_length:>7.2%}"
                            self._messenger.send("smart_ems.rt", msg)

            if filesize != content_length:
                raise FirmwareDownloadError(
                    f"Downloaded firmware size does not match expected size. Expected {content_length}, got {filesize}."
                )

        except requests.ConnectionError:
            # Let tenacity retry this.
            raise

        except requests.RequestException as exc:
            raise FirmwareDownloadError(f"Firmware download failed: {exc}") from exc

    def __extract_http_errors_from_response(self, status_400_response: dict[str, Any]) -> dict[str, Any]:
        try:
            errors_children = status_400_response["errors"]["children"]
        except KeyError:
            errors_children = {}
        errors: dict[str, Any] = {}
        for child, child_value in errors_children.items():
            if "errors" in child_value:
                child_errors = copy.copy(child_value["errors"])
                errors.update({child: child_errors})
        return errors
