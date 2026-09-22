#!/user/bin/env python3
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

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from mpa.smartems.config import SmartEmsConfig


@pytest.fixture
def basic_config() -> SmartEmsConfig:
    return SmartEmsConfig(username="user", password="pass", url="http://example.com")


class TestGetBaseUrl:
    def test_http_url_converted_to_https(self) -> None:
        assert SmartEmsConfig.get_base_url("http://example.com") == "https://example.com"

    def test_https_url_unchanged(self) -> None:
        assert SmartEmsConfig.get_base_url("https://example.com") == "https://example.com"

    def test_preserves_only_scheme_and_netloc(self) -> None:
        result = SmartEmsConfig.get_base_url("http://example.com/path?a=1#frag")
        assert result == "https://example.com"


class TestEndpoint:
    def test_endpoint_default(self, basic_config: SmartEmsConfig) -> None:
        assert basic_config.endpoint == "/api/edgegateway/configuration"

    def test_endpoint_vcc(self) -> None:
        config = SmartEmsConfig(username="u", password="p", url="http://x", edgegatewayvcc=True)
        assert config.endpoint == "/api/edgegatewayvcc/configuration"


class TestGetUrl:
    def test_get_url_default(self, basic_config: SmartEmsConfig) -> None:
        assert basic_config.get_url() == "https://example.com/api/edgegateway/configuration"

    def test_get_url_vcc(self) -> None:
        config = SmartEmsConfig(username="u", password="p", url="http://example.com", edgegatewayvcc=True)
        assert config.get_url() == "https://example.com/api/edgegatewayvcc/configuration"


class TestCertificateContent:
    def test_get_certificate_content_when_exists(self, tmp_path: Path) -> None:
        cert_file = tmp_path / "custom.pem"
        cert_file.write_text("  CERT_CONTENT  \n")
        with patch("mpa.smartems.config.SMARTEMS_CERT", cert_file):
            assert SmartEmsConfig.get_certificate_content() == "CERT_CONTENT"

    def test_get_certificate_content_when_missing(self, tmp_path: Path) -> None:
        cert_file = tmp_path / "missing.pem"
        with patch("mpa.smartems.config.SMARTEMS_CERT", cert_file):
            assert SmartEmsConfig.get_certificate_content() == ""

    def test_save_certificate_content_writes_file(self, tmp_path: Path) -> None:
        cert_file = tmp_path / "custom.pem"
        with patch("mpa.smartems.config.SMARTEMS_CERT", cert_file):
            SmartEmsConfig.save_certificate_content("CONTENT")
            assert cert_file.read_text() == "CONTENT"

    def test_save_certificate_content_empty_does_not_write(self, tmp_path: Path) -> None:
        cert_file = tmp_path / "custom.pem"
        with patch("mpa.smartems.config.SMARTEMS_CERT", cert_file):
            SmartEmsConfig.save_certificate_content("")
            assert not cert_file.exists()

    def test_remove_certificate(self, tmp_path: Path) -> None:
        cert_file = tmp_path / "custom.pem"
        cert_file.write_text("data")
        with patch("mpa.smartems.config.SMARTEMS_CERT", cert_file):
            SmartEmsConfig.remove_certificate()
            assert not cert_file.exists()


class TestGetCertStatus:
    def test_debug_mode_returns_false(self, basic_config: SmartEmsConfig) -> None:
        assert basic_config.get_cert_status(debug_mode=True) is False

    def test_skip_ssl_verification_returns_false(self) -> None:
        config = SmartEmsConfig(username="u", password="p", url="http://x", skip_ssl_verification=True)
        assert config.get_cert_status() is False

    def test_cert_exists_returns_path(self, basic_config: SmartEmsConfig, tmp_path: Path) -> None:
        cert_file = tmp_path / "custom.pem"
        cert_file.write_text("data")
        with (patch("mpa.smartems.config.SMARTEMS_CERT", cert_file)):
            assert basic_config.get_cert_status() == str(cert_file)

    def test_no_debug_no_cert_returns_true(self, basic_config: SmartEmsConfig, tmp_path: Path) -> None:
        cert_file = tmp_path / "missing.pem"
        with (patch("mpa.smartems.config.SMARTEMS_CERT", cert_file)):
            assert basic_config.get_cert_status() is True


class TestGetPollingInterval:
    def test_returns_interval_value(self, basic_config: SmartEmsConfig, tmp_path: Path) -> None:
        timer_file = tmp_path / "smartems.timer"
        timer_file.write_text("[Timer]\nOnUnitActiveSec=42s\n")
        with patch("mpa.smartems.config.SMARTEMS_TIMER", timer_file):
            assert basic_config.get_polling_interval() == 42

    def test_returns_zero_if_not_found(self, basic_config: SmartEmsConfig, tmp_path: Path) -> None:
        timer_file = tmp_path / "smartems.timer"
        timer_file.write_text("[Timer]\nOnBootSec=180s\n")
        with patch("mpa.smartems.config.SMARTEMS_TIMER", timer_file):
            assert basic_config.get_polling_interval() == 0


class TestUpdateTimer:
    def test_raises_for_too_low_interval(self, basic_config: SmartEmsConfig) -> None:
        with pytest.raises(ValueError, match="too low"):
            basic_config.update_timer(5)

    def test_zero_interval_allowed(self, basic_config: SmartEmsConfig) -> None:
        with patch("mpa.smartems.config.update_timer") as mock_update_timer:
            basic_config.update_timer(0)
            mock_update_timer.assert_called_once()
            _, kwargs = mock_update_timer.call_args
            assert kwargs["interval"] == 0
            assert "#OnUnitActiveSec" in kwargs["timer_template"]

    def test_valid_interval_calls_update_timer(self, basic_config: SmartEmsConfig) -> None:
        with patch("mpa.smartems.config.update_timer") as mock_update_timer:
            basic_config.update_timer(30)
            mock_update_timer.assert_called_once()
            _, kwargs = mock_update_timer.call_args
            assert kwargs["interval"] == 30
            assert "OnUnitActiveSec={interval}s" in kwargs["timer_template"]


class TestUpdate:
    def test_update_copies_fields(self, basic_config: SmartEmsConfig) -> None:
        other = SmartEmsConfig(
            username="new_user",
            password="new_pass",
            url="http://new-url.com",
            edgegatewayvcc=True,
            skip_ssl_verification=True,
        )
        basic_config.update(other)
        assert basic_config.username == "new_user"
        assert basic_config.password == "new_pass"
        assert basic_config.url == "http://new-url.com"
        assert basic_config.edgegatewayvcc is True
        assert basic_config.skip_ssl_verification is True


class TestFromDictToDict:
    def test_from_dict_with_all_fields(self) -> None:
        data = {
            "username": "u",
            "password": "p",
            "url": "http://x",
            "edgegatewayvcc": True,
            "skip_ssl_verification": True,
        }
        config = SmartEmsConfig.from_dict(data)
        assert config.username == "u"
        assert config.password == "p"
        assert config.url == "http://x"
        assert config.edgegatewayvcc is True
        assert config.skip_ssl_verification is True

    def test_from_dict_with_defaults(self) -> None:
        config = SmartEmsConfig.from_dict({})
        assert config.username == ""
        assert config.password == ""
        assert config.url == ""
        assert config.edgegatewayvcc is False
        assert config.skip_ssl_verification is False

    def test_to_dict_roundtrip(self, basic_config: SmartEmsConfig) -> None:
        data = basic_config.to_dict()
        restored = SmartEmsConfig.from_dict(data)
        assert restored.to_dict() == data


class TestFileOperations:
    def test_to_file_writes_json(self, basic_config: SmartEmsConfig, tmp_path: Path) -> None:
        file_path = tmp_path / "config.cfg"
        basic_config.to_file(file_path)
        assert json.loads(file_path.read_text()) == basic_config.to_dict()

    def test_from_file_reads_json(self, tmp_path: Path) -> None:
        file_path = tmp_path / "config.cfg"
        data = {
            "username": "u",
            "password": "p",
            "url": "http://x",
            "edgegatewayvcc": False,
            "skip_ssl_verification": False,
        }
        file_path.write_text(json.dumps(data))
        config = SmartEmsConfig.from_file(file_path)
        assert config.to_dict() == data

    def test_save_and_load(self, tmp_path: Path, basic_config: SmartEmsConfig) -> None:
        config_file = tmp_path / "config.cfg"
        with patch("mpa.smartems.config.SMARTEMS_CONFIG", config_file):
            basic_config.save()
            loaded = SmartEmsConfig.load()
            assert loaded.to_dict() == basic_config.to_dict()
