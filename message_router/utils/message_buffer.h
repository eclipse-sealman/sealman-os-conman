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
#ifndef UTILS_MESSAGE_BUFFER_H
#define UTILS_MESSAGE_BUFFER_H
#include <boost/noncopyable.hpp>
#include <boost/container/small_vector.hpp>
#include <string_view>

namespace utils
{

	template <size_t size_T, unsigned int alignment_T = 1>
class MessageBuffer
{
private:
	typedef boost::container::inplace_alignment<alignment_T> AlignmentType;
	typedef typename boost::container::small_vector_options<AlignmentType>::type Options;


	static constexpr size_t    minimum_raw_capacity = size_T;

public:
	typedef boost::container::small_vector<char, minimum_raw_capacity, void, Options> Vector;
private:
	Vector _data;

public:
	MessageBuffer() = default;
	MessageBuffer(std::string_view sv)
	{
		copy_string(sv);
	}
	Vector& sv()
	{
		return _data;
	}
	const Vector& sv() const
	{
		return _data;
	}
		template <typename String_T>
	void copy_string(const String_T& source)
	{
		_data.resize(0);
		append_string(source);
	}

	void init_from(const std::string_view& value)
	{
		copy_string(value);
	}

	void init_from(const unsigned long long& value)
	{
		_data.resize(sizeof(value));
		unsigned long long& data = *reinterpret_cast<unsigned long long*>(_data.data());
		data = value;
	}

		template <typename String_T>
	void append_string(const String_T& source)
	{
		static_assert(std::is_same<typename String_T::value_type, typename Vector::value_type>::value);
		const auto old_size = _data.size();
		const auto source_size = source.size();
		if (source_size)
		{
			_data.resize(old_size + source_size);
			std::copy(source.begin(), source.end(), _data.begin() + old_size);
		}
	}
};

	template <size_t size_T, unsigned int alignment_T>
std::string_view to_string_view(const MessageBuffer<size_T, alignment_T>& mb)
{
	return std::string_view(mb.sv().data(), mb.sv().size());
}

} // namespace utils

#endif // UTILS_MESSAGE_BUFFER_H
