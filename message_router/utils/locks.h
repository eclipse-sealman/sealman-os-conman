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
#ifndef UTILS_LOCKS_H
#define UTILS_LOCKS_H
#include <mutex>
#include <stdexcept>
#include <shared_mutex>
#include <unordered_map>

namespace utils
{

class SharedUniqueLock
{
public:
	using Mutex = std::shared_timed_mutex;
	using SharedLock = std::shared_lock<Mutex>;
	using UniqueLock = std::unique_lock<Mutex>;

	SharedLock lock_shared()
	{
		return SharedLock(_mutex);
	}
		template <typename TimePointOrDuration_T>
	SharedLock lock_shared(const TimePointOrDuration_T& timeout)
	{
		return SharedLock(_mutex, timeout);
	}

	UniqueLock lock_unique()
	{
		return UniqueLock();
	}
		template <typename TimePointOrDuration_T>
	UniqueLock lock_unique(const TimePointOrDuration_T& timeout)
	{
		return UniqueLock(_mutex, timeout);
	}
private:
	Mutex _mutex;
};

class RecursiveSharedUniqueLock
{
public:
	using Mutex = std::shared_timed_mutex;
	static constexpr bool disallow_recursive_unique_locks = true;
private:
	enum class State
	{
		unlocked = 0, // = 0 to ensure that default initialization will get to unlocked
		shared,
		unique
	};
	typedef std::unordered_map<Mutex*, State> StateMap;

	static bool switch_state(StateMap& state_map, Mutex* mutex, const State new_state)
	{
		auto& current_state = state_map[mutex];
		if (current_state == State::unlocked || new_state == State::unlocked)
		{
			current_state = new_state;
			return true;
		}
		if (new_state == State::unique)
		{
			if (disallow_recursive_unique_locks && current_state == State::unique)
			{
				throw std::runtime_error("Attempted recusrive unique lock");
			}
			if (current_state == State::shared)
			{
				throw std::runtime_error("Attempted recusrive upgrade from shared to unique");
			}
		}
		return false;
	}

		template <State state_T, typename Lock_T>
	struct Lock
	{
		Lock(StateMap& state_map, Mutex& mutex) :
			_mutex(mutex),
			_state_map(state_map)
		{
			lock();
		}
			template <typename TimePointOrDuration_T>
		Lock(StateMap& state_map, Mutex& mutex, const TimePointOrDuration_T& timeout) :
			_state_map(state_map)
		{
			if (switch_state(_state_map, &mutex, state_T))
			{
				_lock = Lock_T(mutex, timeout);
				if (!_lock.owns_lock())
				{
					switch_state(_state_map, &mutex, State::unlocked);
				}
			}

		}

		void lock()
		{
			if (switch_state(_state_map, &_mutex, state_T))
			{
				_lock = Lock_T(_mutex);
			}
		}

		void unlock()
		{
			if (_lock.owns_lock())
			{
				switch_state(_state_map, _lock.mutex(), State::unlocked);
				_lock.unlock();
			}
		}

		~Lock()
		{
			unlock();
		}
		Lock_T _lock;
		Mutex& _mutex;
		StateMap& _state_map;
	};
public:
	using SharedLock = Lock<State::shared, std::shared_lock<Mutex>>;
	using UniqueLock = Lock<State::unique, std::unique_lock<Mutex>>;

	SharedLock lock_shared()
	{
		return SharedLock(_state_map, _mutex);
	}
		template <typename TimePointOrDuration_T>
	SharedLock lock_shared(const TimePointOrDuration_T& timeout)
	{
		return SharedLock(_state_map, _mutex, timeout);
	}

	UniqueLock lock_unique()
	{
		return UniqueLock(_state_map, _mutex);
	}
		template <typename TimePointOrDuration_T>
	UniqueLock lock_unique(const TimePointOrDuration_T& timeout)
	{
		return UniqueLock(_state_map, _mutex, timeout);
	}
private:
	Mutex _mutex;
	static thread_local StateMap _state_map;
};

} //namespace utils
#endif // UTILS_LOCKS_H
