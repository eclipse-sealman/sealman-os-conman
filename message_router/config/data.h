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
#ifndef CONFIG_DATA_H
#define CONFIG_DATA_H
#include <sys/types.h>
#include <filesystem>
#include <boost/optional.hpp>

namespace config
{

static_assert(std::is_integral<::gid_t>::value, "We are POSIX specific, "
		"gid_t shall be integral type declared in sys/types.h");

struct Data
{
	using UriAndPath = std::pair<boost::optional<std::string>, std::filesystem::path>;
	boost::optional<std::string> group;
	boost::optional<::gid_t> gid;
	UriAndPath req;
	UriAndPath sub;
	UriAndPath push;

	void apply_group(const UriAndPath& file);

	friend std::ostream& operator<<(std::ostream& out, const Data& data);
};

} // namespace config

#endif // CONFIG_DATA_H
