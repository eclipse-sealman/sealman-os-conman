/*
 * Copyright (c) 2025 Contributors to the Eclipse Foundation.
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License, Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include "config/command_line.h"
#include "manager.h"
#include "proxy.h"
#include "remover.h"
#include "shared_state.h"
#include "utils/watchdog.h"

int main(int argc, char* argv[])
{
	auto& s = SharedState::instance();
	s.cfgdata = config::parse_command_line(argc, argv);
	std::thread managerThread(utils::watchdog<manager>);
	std::thread proxyThread(utils::watchdog<proxy>);
	std::thread removerThread(utils::watchdog<remover>);
	managerThread.join();
	proxyThread.join();
	removerThread.join();
	return 0;
}
