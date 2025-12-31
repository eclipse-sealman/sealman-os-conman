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
import pytest
import shutil
import nginx
from pathlib import Path

from mpa.webgui import mgmtd_webgui

NGINX_TEST_CONF = Path(__file__).parent / "data/example_nginx_configuration.conf"
NGINX_TEST_CONF_TEMPLATE = Path("/tmp/nginx.conf")


@pytest.fixture(scope="class")
def setup_and_cleanup():
    shutil.copyfile(NGINX_TEST_CONF, NGINX_TEST_CONF_TEMPLATE)
    yield
    NGINX_TEST_CONF_TEMPLATE.unlink(missing_ok=True)


@pytest.fixture(scope="class")
def ngnix_config():
    return nginx.loadf(NGINX_TEST_CONF_TEMPLATE)


@pytest.mark.usefixtures("setup_and_cleanup", "ngnix_config")
class TestMgmtdWebgui:
    @pytest.mark.parametrize(
        "port",
        [
            "80",
            "ssl",
            "48366"
        ],
    )
    def test_finding_existing_server(self, port, ngnix_config):
        nginx_server = mgmtd_webgui.find_server_config_by_listen(ngnix_config, port)
        assert nginx_server is not None

    @pytest.mark.parametrize(
        "port",
        [
            "8",
            "0",
            "http",
            "48",
            "83",
            "36",
            "66",
            "4",
            "3",
            "6"
            "483",
            "366",
            "836",
            "8366"
        ],
    )
    def test_finding_non_existing_server(self, port, ngnix_config):
        nginx_server = mgmtd_webgui.find_server_config_by_listen(ngnix_config, port)
        assert nginx_server is None

    @pytest.mark.parametrize(
        "port",
        [
            "80",
            "ssl"
        ],
    )
    def test_removing_server(self, port):
        #  In this case we can not use fixture to load config
        #  When test is running with paramter the same conf object is
        #  passed everytime and after first run ngnix config is already modified
        conf = nginx.loadf(NGINX_TEST_CONF_TEMPLATE)
        server_to_remove = mgmtd_webgui.find_server_config_by_listen(conf, port)
        assert len(conf.filter("Server")) == 2
        mgmtd_webgui.remove_server_from_config(conf, server_to_remove)
        assert len(conf.filter("Server")) == 1

    @pytest.mark.parametrize(
        "port, expected",
        [
            ("48366", "48366"),
            ("ssl", "48366")
        ],
    )
    def test_reading_port_from_ssl_config(self, port, expected, ngnix_config):
        server_to_remove = mgmtd_webgui.find_server_config_by_listen(ngnix_config, port)
        port = mgmtd_webgui.get_listen_port(server_to_remove)
        assert port == expected

    def test_add_new_server(self, ngnix_config):
        test_port = '50304'
        location = nginx.Location('/', nginx.Key('return', '301 https://$host:8001$request_uri'))
        mgmtd_webgui.add_new_server(ngnix_config, [nginx.Key('listen', test_port), location])
        assert len(ngnix_config.filter("Server")) == 3
        new_server_found = mgmtd_webgui.find_server_config_by_listen(ngnix_config, test_port)
        assert new_server_found

    def test_get_redirect_status(self, ngnix_config):
        assert mgmtd_webgui.http_redirect_status(ngnix_config)
        server_to_remove = mgmtd_webgui.find_server_config_by_listen(ngnix_config, "80")
        mgmtd_webgui.remove_server_from_config(ngnix_config, server_to_remove)
        assert not mgmtd_webgui.http_redirect_status(ngnix_config)
