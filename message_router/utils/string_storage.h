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
#ifndef UTILS_STRING_STORAGE_H
#define UTILS_STRING_STORAGE_H
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <string_view>
#include <cassert>

#include <iostream>

#include <boost/serialization/strong_typedef.hpp>

namespace utils
{

BOOST_STRONG_TYPEDEF(std::string_view, StoredStringView);


	// shared_ptr has own locking inside and it seems that using it would not
	// really make our life esier, so we use this simple storage instead
class StringStorage
{
public:
	// TODO shall we use strong typedef to differentiate stored string views from other views?
	StoredStringView push(const std::string_view& value)
	{
		auto it = counts.find(value);
		if (it != counts.end())
		{
			it->second++;
			return StoredStringView(it->first);
		}
		auto [storage_it, is_added_to_storage] = storage.emplace(value);
		assert(is_added_to_storage);
		auto [counts_it, is_added_to_counts] = counts.emplace(*storage_it, 0);
		assert(is_added_to_counts);
		assert(counts_it->second == 0);
		counts_it->second++;
		return StoredStringView(counts_it->first);
	}
	void pop(const std::string_view& value)
	{
		auto it = counts.find(value);
		assert(it != counts.end());
		assert(it->second > 0);
		it->second--;
		if (it->second == 0)
		{
			// Workaround for lack of heterogenous keys in unordered containers in C++ until C++20
			// TODO invistigate if we have support for heterogenous keys in compiler used in yocto
			auto removed = storage.erase(std::string(value));
			assert(removed);
			counts.erase(it);
		}
	}

private:
	// how many users of value we have and holder for string
	std::unordered_map<std::string_view, unsigned int> counts;
	// actual storage
	std::unordered_set<std::string> storage;
};

} //namespace utils

#endif //UTILS_STRING_STORAGE_H
