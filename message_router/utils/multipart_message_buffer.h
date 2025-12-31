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
#ifndef MULTIPART_MESSAGE_BUFFER
#define MULTIPART_MESSAGE_BUFFER

#include <vector>
#include <zmq.hpp>
#include "message_buffer.h"

namespace utils
{

	template <size_t size_T, unsigned int alignment_T = 1>
class MultipartMessageBuffer
{
public:
	typedef MessageBuffer<size_T, alignment_T> MessagePart;

		template <typename T>
	void init(const T& first_part, unsigned int size = 1)
	{
		parts.resize(size);
		parts.front().copy_string(first_part);
	};

		template <typename... Targs_T>
	void init_multipart(const Targs_T&... values)
	{
		parts.resize(sizeof...(values));
		init_multipart_impl<0>(values...);
	};

	void send(zmq::socket_t& socket)
	{
		if (parts.empty()) [[ unlikely ]]
		{
			throw std::length_error("Multipart message without any parts cannot be sent");
		}
		auto send_part = [&](const MessagePart& mp, zmq::send_flags fl)
		{
			socket.send(zmq::const_buffer(mp.sv().data(), mp.sv().size()), fl);
		};
		const auto end = --parts.end();
		for (auto it = parts.begin();  it != end; ++it)
		{
			send_part(*it, zmq::send_flags::sndmore);
		}
		send_part(*end, zmq::send_flags::none);
	}

	std::vector<MessagePart> parts;

		template <unsigned int pos_T, typename T>
	void init_multipart_impl(const T& value)
	{
		parts[pos_T].init_from(value);
	}

		template <unsigned int pos_T, typename T, typename...Targs_T>
	void init_multipart_impl(const T& value, const Targs_T&... values)
	{
		parts[pos_T].init_from(value);
		init_multipart_impl<pos_T+1>(values...);
	}

};

} //namespace utils

#endif //MULTIPART_MESSAGE_BUFFER
