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
class azure:
    get_config_with_privates = "azure.get_config_with_privates"
    get_config = "azure.get_config"
    set_config = "azure.set_config"
    get_config_file = "azure.get_config_file"
    set_config_file = "azure.set_config_file"
    set_partial_config_file = "azure.set_partial_config_file"
    set_tpm = "azure.set_tpm"
    set_x509 = "azure.set_x509"
    set_cert = "azure.set_cert"
    set_hostname = "azure.set_hostname"
    remove_cert = "azure.remove_cert"
    set_connection_string = "azure.set_connection_string"
    clean_keys = "azure.clean_keys"


class dev:
    get_config = "dev.get_config"
    get_config_with_privates = "dev.get_config_with_privates"
    set_config = "dev.set_config"
    manage_user = "dev.manage_user"
    get_serial_number = "dev.get_serial_number"
    perform_factory_reset = "dev.perform_factory_reset"
    install_localcert = "dev.install_localcert"
    docker_volumes_access = "dev.docker_volumes_access"
    swupdate = "dev.swupdate"
    reboot = "dev.reboot"

    class tpm:
        get_config = "dev.tpm.get_config"

    class motd:
        set = "dev.motd.set"
        set_config = "dev.motd.set_config"
        get_config = "dev.motd.get_config"

    class issue:
        set = "dev.issue.set"
        set_config = "dev.issue.set_config"
        get_config = "dev.issue.get_config"

    class proxy:
        add = "dev.proxy.add"
        delete = "dev.proxy.delete"
        set_config = "dev.proxy.set_config"
        get_config = "dev.proxy.get_config"

    class overcommit_memory:
        get = "dev.overcommit_memory.get"
        set = "dev.overcommit_memory.set"

    class serial:
        set_config = "dev.serial.set_config"
        get_config = "dev.serial.get_config"

    class logrotate:
        set_config = "dev.logrotate.set_config"
        get_config = "dev.logrotate.get_config"

    class logintimeout:
        set_config = "dev.logintimeout.set_config"
        get_config = "dev.logintimeout.get_config"

    class datetime:
        get_config = "datetime.get_config"
        set_config = "datetime.set_config"
        set_timezone = "datetime.set_timezone"
        show = "datetime.show"
        set_ntp_server = "datetime.set_ntp_server"
        manage_ntp_service = "datetime.manage_ntp_service"

    class ssh:
        set_config = "dev.ssh.set_config"
        get_config = "dev.ssh.get_config"
        list_keys = "dev.ssh.list_keys"
        add_key = "dev.ssh.add_key"
        remove_key = "dev.ssh.remove_key"

    class local_console:
        set_config = "dev.local_console.set_config"
        get_config = "dev.local_console.get_config"

        class login:
            set_config = "dev.local_console.login.set_config"
            get_config = "dev.local_console.login.get_config"

        class syskeys:
            set_config = "dev.local_console.syskeys.set_config"
            get_config = "dev.local_console.syskeys.get_config"

    class user:
        class password_hash:
            set_config = "dev.user.password_hash.set_config"
            get_config = "dev.user.password_hash.get_config"


class smart_ems:
    set_config = "smart_ems.set_config"
    get_config = "smart_ems.get_config"
    check_smart_ems = "smart_ems.check_smart_ems"
    manage_cert = "smart_ems.manage_cert"


class docker:
    set_config = "docker.set_config"
    restart = "docker.restart"

    class dns:
        add = "docker.dns.add"
        delete = "docker.dns.delete"
        get_config = "docker.dns.get_config"
        set_config = "docker.dns.set_config"

    class params:
        set = "docker.params.set"
        get_config = "docker.params.get_config"
        set_config = "docker.params.set_config"

    class compose:
        get_config = "docker.compose.get_config"
        set_config = "docker.compose.set_config"
        status = "docker.compose.status"
        add = "docker.compose.add"
        get = "docker.compose.get"
        delete = "docker.compose.delete"
        recreate = "docker.compose.recreate"
        auth_add = "docker.compose.auth_add"
        auth_remove = "docker.compose.auth_remove"

        class proxy:
            add = "docker.compose.proxy.add"
            delete = "docker.compose.proxy.delete"


class net:
    set_config = "net.set_config"
    set_ignore_default_route = "net.set_ignore_default_route"
    get_config = "net.get_config"
    status = "net.status"

    class dns:
        get_config = "net.dns.get_config"
        set_config = "net.dns.set_config"
        show = "net.dns.get_config"
        add = "net.dns.add"
        delete = "net.dns.delete"

    class promiscous_mode:
        set_config = "net.promiscous_mode.set_config"

    class dhcp_server:
        list = "net.dhcp_server.list"
        get_config = "net.dhcp_server.get_config"
        set_config = "net.dhcp_server.set_config"
        set_inerface_state = "net.dhcp_server.set_interface_state"

    class cellular:
        set_config = "net.cellular.set_config"
        change_state = "net.cellular.change_state"
        check = "net.cellular.check"

    class wifi:
        class client:
            scan = "net.wifi.client.scan"
            set_config = "net.wifi.client.set_config"
            change_state = "net.wifi.client.change_state"

    class ovpn:
        add_tunnel = "net.ovpn.add_tunnel"
        remove_tunnel = "net.ovpn.remove_tunnel"
        get_config = "net.ovpn.get_config"
        set_config = "net.ovpn.set_config"
        set_autostart = "net.ovpn.set_autostart"
        set_tunnel_state = "net.ovpn.set_tunnel_state"
        list_tunnels = "net.ovpn.list_tunnels"
        tunnels_status = "net.ovpn.tunnels_status"

    class filter:
        commit = "net.filter.commit"
        cleanup = "net.filter.cleanup"
        reload = "net.filter.reload"
        enable = "net.filter.enable"
        disable = "net.filter.disable"
        get_config = "net.filter.get_config"
        show = "net.filter.show"
        set_config = "net.filter.set_config"

        class preset:
            select = "net.filter.preset.select"
            create = "net.filter.preset.create"
            delete = "net.filter.preset.delete"
            edit = "net.filter.preset.edit"
            save = "net.filter.preset.save"
            list = "net.filter.preset.list"
            print = "net.filter.preset.print"

        class modify:
            copy = "net.filter.modify.copy"
            erase = "net.filter.modify.erase"
            policy = "net.filter.modify.policy"
            common = "net.filter.modify.common"
            input = "net.filter.modify.input"
            output = "net.filter.modify.output"
            forward = "net.filter.modify.forward"
            nat_pre = "net.filter.modify.nat_pre"
            nat_post = "net.filter.modify.nat_post"
            nat_n_on_n = "net.filter.modify.nat_n_on_n"
            masquerade = "net.filter.modify.masquerade"
            snat = "net.filter.modify.snat"
            port_forward = "net.filter.modify.port_forward"
            ingress = "net.filter.modify.ingress"
            create_chain_ingress = "net.filter.modify.create_chain_ingress"
            remove_chain_ingress = "net.filter.modify.remove_chain_ingress"

    class routing:
        get_config = "net.routing.get_config"
        set_config = "net.routing.set_config"
        flush = "net.routing.flush"
        load_rules = "net.routing.load_rules"

    class route:
        add = "net.route.add"
        remove = "net.route.remove"
        order = "net.route.order"
        enable = "net.route.enable"
        disable = "net.route.disable"

    class routes:
        class preset:
            select = "net.routes.preset.select"
            create = "net.routes.preset.create"
            delete = "net.routes.preset.delete"
            edit = "net.routes.preset.edit"
            save = "net.routes.preset.save"
            list = "net.routes.preset.list"
            print = "net.routes.preset.print"

    class vlan:
        add = "net.vlan.add"
        remove = "net.vlan.remove"
        get_config = "net.vlan.get_config"
        set_config = "net.vlan.set_config"
        edit = "net.vlan.edit"

    class ids:
        change_state = "net.ids.change_state"


class logstreamer:
    download_logs = "logstreamer.download_logs"


class webgui:
    status = "webgui.status"
    manage_service = "webgui.manage_service"
    change_port = "webgui.change_port"
    set_config = "webgui.set_config"
    get_config = "webgui.get_config"
    manage_redirect = "webgui.manage_redirect"
