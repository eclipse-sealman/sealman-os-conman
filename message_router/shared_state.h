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
#ifndef SHARED_STATE_H
#define SHARED_STATE_H

#include <set>
#include <condition_variable>
#include <zmq.hpp>
#include "client_list.h"
#include "config/data.h"
#include "utils/locks.h"

struct SharedState
{
	static SharedState& instance()
	{
		static SharedState s;
		return s;
	}

	ClientsState clients;
	std::set<std::string, std::less<>> subscriptions; // list known subscriptions (sinks and/or handlers exist)

		// to_proxy_socket_address is filled when proxy thread starts, together
		// with subscriptionsLocker and proxy_ready it delays processing of
		// other threads until proxy thread starts. Note however, that if proxy
		// thread crashes other threads are still alive. to_proxy_socket is a
		// push/pull one, so until proxy thread gets back up any pushes should
		// be blocking, but we need TODO test it :) There is also another edge
		// case scenario --- all threads having to_proxy socked opend dying at
		// the same time --- TODO check if it is possible to lose messages in
		// such scenario
	std::string to_proxy_socket_address;

		// clientsLocker is used to protect SharedState::clients
	utils::RecursiveSharedUniqueLock clientsLocker;

		// subscriptionsLocker has two uses:
		// * lock associated with condition variable proxy_ready used for proxy
		//   and other threads startup synchrozation regarding to_proxy_socket
		// * changes in SharedState::subscriptions
	utils::RecursiveSharedUniqueLock subscriptionsLocker;

		// used to (re)start remover when first client attaches
	std::condition_variable_any active_clients;

		// used to delay startup of other threads until proxy thread is ready
	std::condition_variable_any proxy_ready;

	zmq::context_t context;
	config::Data cfgdata;
};

#endif //SHARED_STATE_H
