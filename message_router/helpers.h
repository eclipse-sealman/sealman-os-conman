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
#ifndef HELPERS_H
#define HELPERS_H

#include <zmq.hpp>

#if 1 // TODO move things in this #if to better place...

inline zmq::send_flags send_flags(bool more)
{
	return more ? zmq::send_flags::sndmore : zmq::send_flags::none;
}

inline std::string_view to_string_view(const zmq::message_t& m, size_t pos, size_t count)
{
	const auto size = m.size();
	if (pos + count > size)
	{
		throw std::out_of_range("Requested string_view larger than message_t size");
	}
	return std::string_view(static_cast<const char*>(m.data()) + pos, count);
}


inline std::string_view to_string_view(const zmq::message_t& m, size_t pos = 0)
{
	const auto size = m.size();
	if (pos > size)
	{
		throw std::out_of_range("Requested string_view larger than message_t size");
	}
	return std::string_view(static_cast<const char*>(m.data()) + pos, size - pos);
}

	template<typename T>
bool is_aligned(void *p)
{
	//TODO shall we benchmark it aginst manual calculation???
	auto size = sizeof(T);
	return std::align(alignof(T), size, p, size);
}


	template <typename T, typename Container_T>
T get_raw_copy_aligned(const Container_T& container, size_t pos = 0)
{
	static_assert(std::is_trivially_copyable<T>::value);
	auto data = static_cast<char*>(const_cast<void*>(container.data())) + pos;
	const bool fits = (container.size() >= sizeof(T) + pos);
	if (fits && is_aligned<T>(data))
	{
		return *reinterpret_cast<T*>(data);
	}
	T value;
	if (fits)
	{
		std::memcpy(&value, data, sizeof(T));
	}
	return value;
}

	template <typename T, typename Container_T>
void put_raw_copy(const T& value, const Container_T& container, size_t pos = 0)
{
	static_assert(std::is_trivially_copyable<T>::value);
	auto data = static_cast<char*>(const_cast<void*>(container.data())) + pos;
	const bool fits = (container.size() >= sizeof(T) + pos);
	if (!fits)
	{
		throw std::runtime_error("Buffer overrun attempted");
	}
	if (is_aligned<T>(data))
	{
		T& target = *reinterpret_cast<T*>(data);
		target = value;
	}
	else
	{
		std::memcpy(data, &value, sizeof(T));
	}
}

#endif //1

#endif //HELPERS_H
