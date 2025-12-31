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
#ifndef UTILS_WATCHDOG_H
#define UTILS_WATCHDOG_H

#include <exception>
#include <string>
#include <chrono>
#include <iostream>
#include <thread>

namespace utils
{

using namespace std::literals;

	/** Simple watchdog.
	 *
	 * Can be used to e.g. restart thread (or subfunction in thread
	 * automatically). Of course shall be used only in enviromment in which
	 * such restart will usually work and is sensible (e.g. we have some
	 * external state which allows to continue processing with much smaller
	 * interruption than restart of whole program (e.g. automatic systemd
	 * restart).
	 */
	// TODO make params configurable
	template<void (function_T)()>
void watchdog()
{
	unsigned crashes = 0;
	unsigned crash_sequence = 0;
	std::exception_ptr exc;
	std::string what;
	bool shall_run = true;
	while (shall_run)
	{
		auto start = std::chrono::steady_clock::now();
		try
		{
			function_T();
			shall_run=false;
		}
		catch (std::exception& e)
		{
			what = "Caught std::exception with what: "s + e.what();
			exc = std::current_exception();
		}
		catch (...)
		{
			what = "Unknown exception caught";
			exc = std::current_exception();
		}
		if (shall_run)
		{
			constexpr auto runtime_ending_crash_sequence = 60s;
			constexpr unsigned max_crashes = 100;
			constexpr unsigned max_crashes_in_sequence = 5;
			auto stop = std::chrono::steady_clock::now();
			auto runtime = stop - start;
			++crashes;
			if (runtime > runtime_ending_crash_sequence)
			{
				crash_sequence = 0;
			}
			else
			{
				++crash_sequence;
			}
			if (crashes > max_crashes ||                                // to many crashes in general
					crash_sequence > max_crashes_in_sequence || // to long quick crash sequence
					(crashes == 1 && crash_sequence))           // immediate crash at startup
			{
				std::cerr << std::this_thread::get_id() << ": Rethrowing\n";
				std::rethrow_exception(exc);
			}
			std::cerr << std::this_thread::get_id() <<
				":Restarting function after failure. " << what << "\n";
		}
	}
}

} //namespace utils

#endif //UTILS_WATCHDOG_H
