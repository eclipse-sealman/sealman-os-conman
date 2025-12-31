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
#include "config/data.h"
#include <unistd.h>
#include <sys/stat.h>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/optional/optional_io.hpp>

namespace config
{

using namespace std::literals;

namespace //anonymous
{

void throw_system_error(int error, const std::string& what)
{
	throw std::system_error(std::error_code(error, std::system_category()), what);
}

} // anonymous namespace

void Data::apply_group(const UriAndPath& socket)
{
	const auto& file = socket.second;
	if ((!gid) || file.empty())
	{
		return;
	}
	if (chown(file.c_str(), -1, *gid) == -1)
	{
		throw_system_error(errno,
				"While attempting to change group of socket: "s.append(file) +
				" to " + boost::trim_copy(boost::lexical_cast<std::string>(gid)) +
				" (" + boost::trim_copy(boost::lexical_cast<std::string>(group)) +
				") error from system was received");
	}
	if (chmod(file.c_str(), 0775) == -1) // TODO 0775 --- rwx on ug, rx on o
	{
		throw_system_error(errno,
				"While attempting to change permissions of socket: "s.append(file) +
				" error from system was received");
	}
}

namespace //anonymous
{

void print_socket(const std::pair<boost::optional<std::string>, std::string>& socket,
		std::ostream& out, bool& anyFile)
{
	out << *socket.first;
	if (!socket.second.empty())
	{
		anyFile = true;
		out << " (on file: " << socket.second << ")";
	}
	out << "\n";
}

} // anonymous namespace

std::ostream& operator<<(std::ostream& out, const Data& data)
{
	bool anyFile = false;
	out << "req: "; print_socket(data.req, out, anyFile);
	out << "push: "; print_socket(data.push, out, anyFile);
	out << "sub: "; print_socket(data.sub, out, anyFile);
	if (anyFile)
	{
		if (data.group)
		{
			out << "Files would be in group: " << *data.group << "\n";
		}
		else
		{
			out << "Files would be in default group." << "\n";
		}
	}
	return out;
}

} // namespace config
