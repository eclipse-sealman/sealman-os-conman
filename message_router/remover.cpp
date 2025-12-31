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
#include "remover.h"
#include "shared_state.h"
#include "socket_closer.h"
#include <thread>

using namespace std::literals;

void remover()
{
	static int _run_call_count = 0;
	++_run_call_count;
	auto& s = SharedState::instance();
	auto sleep_for = 1ms;

	zmq::socket_t sock_to_proxy;
	auto to_proxy_closer = SocketCloser(s, sock_to_proxy);
	{
		auto lock = s.subscriptionsLocker.lock_unique();
		while (s.to_proxy_socket_address.empty())
		{
			s.proxy_ready.wait(lock._lock);
		}
		to_proxy_closer.open(zmq::socket_type::push, [&s](zmq::socket_t& sock) {
				sock.connect(s.to_proxy_socket_address);});
	}

	while (true)
	{
		std::this_thread::sleep_for(sleep_for);
		{
			auto lock = s.clientsLocker.lock_unique();
			while (s.clients.empty())
			{
				s.active_clients.wait(lock._lock);
			}
			auto cutoff_time = std::chrono::steady_clock::now() - 10s;
			auto optit = s.clients.oldest();
			while (optit && (*optit)->props.last_seen <= cutoff_time)
			{
				s.clients.remove(*optit);
				optit = s.clients.oldest();
			}
			{
				auto dead_handlers = s.clients.get_dead_handlers();
				// TODO code duplication between here and manager
				for (auto& element : dead_handlers)
				{
					auto& query = element.first.first;
					auto& response = element.first.second;

					zmq::message_t part1(query.size() + 1);
					part1.data<char>()[0] = '!';
					memcpy(part1.data<char>() + 1, query.data(), query.size());
					sock_to_proxy.send(part1, zmq::send_flags::sndmore);

					zmq::message_t part2(response.data(), response.size());
					sock_to_proxy.send(part2, zmq::send_flags::none);
				}
			}
			if (optit)
			{
				sleep_for = std::chrono::duration_cast<decltype(sleep_for)>(
						(*optit)->props.last_seen - cutoff_time) + 1ms;
			}
			else
			{
				sleep_for = 10s;
			}
		}
	}
}

