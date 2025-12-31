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
#ifndef SOCKET_CLOSER_H
#define SOCKET_CLOSER_H
#include "shared_state.h"

class SocketCloser : boost::noncopyable
{
public:
	SocketCloser(SharedState& s, zmq::socket_t& socket) :
		_s(s),
		_socket(socket)
	{
	}
		template <typename OpenAction_T>
	SocketCloser(SharedState& s, zmq::socket_t& socket, zmq::socket_type type, OpenAction_T&& open_action):
		SocketCloser(s, socket)
	{
		open(type, std::forward<OpenAction_T>(open_action));
	}
	~SocketCloser()
	{
		_socket.close();
	}
		template <typename OpenAction_T>
	void open(zmq::socket_type type, OpenAction_T&& open_action)
	{
		_socket = zmq::socket_t(_s.context, type);
		open_action(_socket);
	}
private:
	SharedState& _s;
	zmq::socket_t& _socket;
};

struct BindAndApplyGroup
{
	SharedState& _s;
	const config::Data::UriAndPath& _uri_and_path;
	BindAndApplyGroup(SharedState& s, const config::Data::UriAndPath& uri_and_path) :
		_s(s),
		_uri_and_path(uri_and_path)
	{
	}
	void operator()(zmq::socket_t& socket) const
	{
		socket.bind(*_uri_and_path.first);
		_s.cfgdata.apply_group(_uri_and_path);
	};
};

#endif //SOCKET_CLOSER_H
