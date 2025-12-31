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
#include "manager.h"
#include <random>
#include <thread>
#include "utils/multipart_message_buffer.h"
#include "socket_closer.h"

using namespace std::literals;

namespace // anonymous
{

} //anonymous namespace


class Manager
{
private:
	static constexpr unsigned int inline_topic_size = 40u;
	static constexpr auto max_response_part_size = std::max(inline_topic_size, id_size);
	typedef utils::MultipartMessageBuffer<max_response_part_size, std::alignment_of<IdType>::value> MultipartMessage;

	bool is_more_expected() const
	{
		return _request.empty() || _request.back().more();
	}

	zmq::message_t& receive_unguarded()
	{
		assert(_request.empty() || _request.back().more());
		_request.push_back({});
		if (!_sock_rep.recv(_request.back())) [[ unlikely ]]
		{
			throw std::runtime_error("recv failed on req socket");
		}
		return _request.back();
	}

	zmq::message_t& receive()
	{
		if (is_more_expected()) [[ likely ]]
		{
			return receive_unguarded();
		}
		throw std::runtime_error("Programming error: nothing to receive where we expected otherwise");
	}

		template <typename T>
	zmq::message_t* receive(const T& expected_part_description)
	{
		if (is_more_expected()) [[ likely ]]
		{
			return &receive_unguarded();
		}
		_response.init_multipart("INVALID"sv, "Missing "sv);
		_response.parts.back().append_string(expected_part_description); // TODO silently crop
		return nullptr;
	}

		template <typename T>
	zmq::message_t* receive_id(const T& expected_part_description)
	{
		if (receive(expected_part_description))
		{
			if (_request.back().size() != sizeof(IdType))
			{
				_response.init_multipart("INVALID"sv, "Wrong size of "sv);
				_response.parts.back().append_string(expected_part_description);
				return nullptr;
			}
			return &_request.back();
		}
		return nullptr;
	}

	void init_reset_response()
	{
		_response.init("RESET"sv);
	};

		// TODO think about putting this logic into ID class
		/** Resolves random id collision.
		 *
		 *  We have two ways of getting ID --- allowing client to suggest one or generating
		 *  random one. The latter option is used be default or if client suggestion is
		 *  already taken. In rare cases a randomly generated ID can still collide with
		 *  another already existing ID. This function attempts at finding unused one in
		 *  such case. Most of the code here is run if and only if we detected collision
		 *  which is extremly rare, so we don't really care about perfomance --- we instead
		 *  want to minimize risk of not being able to find unique ID.
		 *
		 *  For ID we generate random integer leaving MSByte with zeros --- if we ever get
		 *  collsion we use this byte to find first unused ID ending whith bits same as the
		 *  random number, so to actually be unable to find unique id we need 256th
		 *  collisions on ***same*** random number. This is practically impossible, because
		 *  we also reject suggestions from clients for IDs with MSByte set to anything else
		 *  than 0, so this space is accessible only for collisions.
		 *
		 *  Alternative approach would be to call random function again each time we get
		 *  conflict --- this approach was rejecetd because it does not allow to make clear
		 *  distincion between normal and conflict resolving ids.
		 *
		 *  Below is additonal information supporting data for collision probability which
		 *  might be helpful in case we want to switch to different size of ID. Currently we
		 *  use 64 bit IDs (mostly to allow nice human readable strings for values suggested
		 *  by clients) which will unlikely get into any collision resolving until we reach
		 *  milions of clients active at the same time, not to mention possibility to get
		 *  fatal collision count. In case of 32 bit IDs this solution is probalitiscally
		 *  non-breakable, although for 32 bit IDs first non-fatal collision resolving will
		 *  happen around 1000 clients so if we want to switch to 32 bit IDs we shall
		 *  measure efficiency of code resloving collisions and/or lower number of bits used
		 *  for collision resolving.
		 *
		 *  Fatal collision probability can be calculated using formula:
		 *
		 *      /     /                                                        \  \
		 *      |     | /                                        \ fatal_count |  |
		 *      |     | |            active_ids                  |             |  |
		 *      |     | | -------------------------------------- |             |  |
		 *      |     | |                   /          1       \ |             |  |
		 *      |   - | | /               \ | 1 - ------------ | |             |  |
		 *  1 - |     | | |   random_bits | \     fatal_count  / |             |  |
		 *      |     | \ \ 2             /                      /             |  |
		 *      |     | ------------------------------------------------------ |  |
		 *      |     \                  fatal_count!                          /  |
		 *      \ e                                                               /
		 *
		 *  adapted from Flajolet's and Sedgwick's solution of generalized birthday problem
		 *  provided in book Analytic Combinatorics (https://ac.cs.princeton.edu/home/AC.pdf,
		 *  page in PDF 130, printed page 116, Note II.8).
		 *
		 *  Bits reseved to resolve collisions           | 0 | 1 | 2 |   8 |
		 *  ---------------------------------------------+---+---+---+-----+
		 *  How many times same random part needes to    |   |   |   |     |
		 *  to be generated to exceed space reserved     | 2 | 3 | 5 | 257 |
		 *  for resolving collisions (fatal_count above) |   |   |   |     |
		 *
		 *  Fatal collision    |                   Random bits/bits reserved to resolve collisions                  |
		 *  probability        |  24/0  | 32/0   | 31/1 |    30/2 | 24/8    | 56/0     | 64/0     | 62/2   | 56/8   |
		 *  -------------------+--------+--------+------+---------+---------+----------+----------+--------+--------+
		 *               1e3   |   2.9% | 0.011% |      |         |         | 6.9e-10% | 2.7e-12% |        |        |
		 *               5e3   |  52%   | 0.29%  |      |         |         | 1.7e-8%  | 6.8e-11% |        |        |
		 *               1e5   |  100%  | 68%    | 3.5% | 6.3e-7% |         | 6.9e-6%  | 2.7e-8%  |        |        |
		 *   Number of   1e6   |        | 100%   |      |         |         | 6.9e-4%  | 2.7e-6%  | 2e-10% |        |
		 *   active ids  3e8   |        |        |      |         | 0%      | 46%      |  0.24%   |        |        |
		 *   (active_ids 1.5e9 |        |        |      |         | 2.2e-5% | 99.99%   |  5.9%    |        |        |
		 *    above)     1.6e9 |        |        |      |         | 97%     | 99.99%   |  6.7%    |        |        |
		 *               5e9   |        |        |      |         | 100%    | 100%     | 49%      |        |        |
		 *               1e18  |        |        |      |         | 100%    | 100%     | 49%      |        | 1e-11% |
		 *
		 */
		template <typename IdType_T, typename CheckerFunctionType_T>
	void try_finding_unique_id(IdType_T& id, CheckerFunctionType_T exists)
	{
		if ((_s.clients.*exists)(id))
		{
			for (unsigned int i = 0; i < 256; ++i)
			{
				id += _maximum_allowed_normal_id;
				if ((_s.clients.*exists)(id))
				{
					continue;
				}
				return;
			}
			throw std::runtime_error("Unable to find unique ID --- we must be very unlucky...");
		}
	}

		template <typename IdType_T, typename T>
	IdType_T get_old_id(const T& expected_part_description)
	{
		IdType_T old_id{0};
		if (_request.back().more())
		{
			if (receive_id(expected_part_description))
			{
				old_id  = IdType_T(get_raw_copy_aligned<IdType>(_request.back()));
				if (old_id > _maximum_allowed_normal_id)
				{
					old_id = 0;
				}
			}
		}
		return old_id;
	}

	void add_new_id()
	{
		PublicIdType new_public_id{0};
		PublicIdType old_public_id = get_old_id<PublicIdType>("OldPublicId"sv);
		PrivateIdType new_private_id{0};
		PrivateIdType old_private_id = get_old_id<PrivateIdType>("OldPrivateId"sv);

		bool shall_notify_active_clients = false;
		{
			auto lock = _s.clientsLocker.lock_unique();
			if (_s.clients.empty())
			{
				shall_notify_active_clients = true;
			}
			const auto wanted_private_id = old_private_id ? old_private_id : PrivateIdType{random()};
			const auto wanted_public_id = old_public_id ? old_public_id : PublicIdType{random()};
			if (_s.clients.make_friend(wanted_private_id, wanted_public_id))
			{
				new_private_id = wanted_private_id;
				new_public_id = wanted_public_id;
			}
			else
			{
				// We failed at making a friend (i.e. there was collision, most probaly because client
				// requested an old id which is already taken).  In such case we ensure private id is
				// randomized (i.e. do it if it was not done before) but we randomize public id only if it
				// is taken already.
				new_public_id = _s.clients.get_private_id(wanted_public_id) ? random() : old_public_id;
				new_private_id = old_private_id ? random() : wanted_private_id;
				try_finding_unique_id(new_public_id, &ClientsState::get_private_id);
				try_finding_unique_id(new_private_id, &ClientsState::get_public_id);
				if (!_s.clients.insert_friend(new_private_id, new_public_id)) [[ unlikely ]]
				{
					throw std::runtime_error("Id which we meant to be unique already exists...");
				}
			}
		}
		if (shall_notify_active_clients)
		{
			_s.active_clients.notify_all();
		}
		_response.init_multipart("ID"sv, new_private_id, new_public_id);
	}

	struct ReplyLostRequest
	{
			template <typename Lock_T, typename Iterator_T>
		void operator()(Manager& m, Lock_T& /*lock*/, Iterator_T& client_it) const
		{
			const Client& client = *client_it;
			if (client.props.lost_requests.empty())
			{
				m._response.init("OK"sv);
				return;
			}
			decltype(client.props.lost_requests) lost_requests;
			lost_requests.swap(client.props.lost_requests);
			m._response.init("LOST"sv, 3 * lost_requests.size() + 1);
			int i = 0;
			for (const auto& [topic, lost_request] : lost_requests)
			{
				{
					++i;
					m._response.parts[i].copy_string(topic);
				}
				++i;
				auto& sv = m._response.parts[i].sv();
				sv.resize(sizeof(SequenceType));
				SequenceType& data = *reinterpret_cast<SequenceType*>(sv.data());
				data = lost_request.sequence;
				{
					++i;
					m._response.parts[i].copy_string(lost_request.response_topic);
				}
			}
		}
	};

	struct DeleteClient
	{
			template <typename Lock_T, typename Iterator_T>
		void operator()(Manager& m, Lock_T& /*lock*/, Iterator_T& client_it) const
		{
			m._s.clients.remove(client_it);
		}
	};

	struct RegisterHandler
	{
			template <typename Lock_T, typename Iterator_T>
		void operator()(Manager& m, Lock_T& lock, Iterator_T& client_it) const
		{
			auto client_locker = ClientLocker(*client_it);
			lock.unlock();
			const auto firstQueryPosition = m._request.size();
			do
			{
				if (!m.receive("query topic"sv)) return;
				if (!m.receive("response topic"sv)) return;
			}
			while (m._request.back().more());
			std::vector<zmq::message_t> to_proxy;
			const auto size = m._request.size();
			m._response.parts.resize(1);
			auto& sv = m._response.parts[0].sv();
			unsigned int pairs_count = (size - firstQueryPosition) / 2;
			sv.resize(pairs_count);
			unsigned int j = firstQueryPosition;
			lock.lock();
			for (unsigned int i = 0; i < pairs_count; ++i)
			{
				auto query_topic = to_string_view(m._request[j]);
				++j;
				auto response_topic = to_string_view(m._request[j]);
				++j;
				auto status = m._s.clients.add_handler(query_topic, response_topic, *client_it);
				switch (status)
				{
				case ClientsState::AddHandlerSatatus::unique_new:
				case ClientsState::AddHandlerSatatus::unique_readded:
				case ClientsState::AddHandlerSatatus::unique_changed:
					sv[i] = 'U';
					break;
				case ClientsState::AddHandlerSatatus::accessory_new:
				case ClientsState::AddHandlerSatatus::accessory_readded:
				case ClientsState::AddHandlerSatatus::accessory_changed:
					sv[i] = 'A';
					break;
				case ClientsState::AddHandlerSatatus::duplicate_new:
				case ClientsState::AddHandlerSatatus::duplicate_readded:
				case ClientsState::AddHandlerSatatus::duplicate_changed:
					sv[i] = 'D';
					break;
				}
				switch (status)
				{
				case ClientsState::AddHandlerSatatus::unique_readded:
				case ClientsState::AddHandlerSatatus::accessory_readded:
				case ClientsState::AddHandlerSatatus::duplicate_readded:
					continue;
				case ClientsState::AddHandlerSatatus::unique_new:
				case ClientsState::AddHandlerSatatus::accessory_new:
				case ClientsState::AddHandlerSatatus::duplicate_new:
				case ClientsState::AddHandlerSatatus::unique_changed:
				case ClientsState::AddHandlerSatatus::accessory_changed:
				case ClientsState::AddHandlerSatatus::duplicate_changed:
					break;
				}
				{
					auto dead_handlers = m._s.clients.get_dead_handlers();
					for (auto& element : dead_handlers)
					{
						auto& query = element.first.first;
						auto& response = element.first.second;
						to_proxy.emplace_back(query.size() +1);
						to_proxy.back().data<char>()[0] = '!';
						memcpy(to_proxy.back().data<char>() + 1,
								query.data(), query.size());
						to_proxy.emplace_back(response.data(), response.size());
					}
				}
				to_proxy.emplace_back(query_topic.size() +1);
				to_proxy.back().data<char>()[0] = '@';
				memcpy(to_proxy.back().data<char>() + 1,
						query_topic.data(), query_topic.size());
				to_proxy.emplace_back(response_topic.data(), response_topic.size());
			}
			lock.unlock();
			bool send_more = true;
			for (auto& part : to_proxy)
			{
				m._sock_to_proxy.send(part, send_flags(send_more));
				send_more = !send_more;
			}
		}
	};

		// The idea is to allow compiler to make it obvious for
		// optimizer that all of those calls shall be inlined...
		// TODO Is there cleaner/easier way of doing it (mpl/hana/...?)
		template <typename FirstFunctor_T, typename... Functors_T>
	struct Execute
	{
			template <typename... Args_T>
		void operator()(Args_T&... args) const
		{
			Execute<FirstFunctor_T>{}(args...);
			Execute<Functors_T...>{}(args...);
		}
	};
		template <typename Functor_T>
	struct Execute<Functor_T>
	{
			template <typename... Args_T>
		void operator()(Args_T&... args) const
		{
			Functor_T{}(args...);
		}
	};

		template <typename... Functors_T>
	void check_private_id()
	{
		if (!receive("private Id"sv)) return;
		if (_request.back().size() != sizeof(IdType))
		{
			return init_reset_response();
		}
		// we need unique lock because
		// a) ping reorders elements
		// b) functors usually change shared state too
		auto lock = _s.clientsLocker.lock_unique();
		auto opt_client = _s.clients.ping(PrivateIdType(get_raw_copy_aligned<IdType>(_request.back())));
		if (!opt_client)
		{
			return init_reset_response();
		}
		Execute<Functors_T...>{}(*this, lock, *opt_client);
	}

	void check_if_topic_exists()
	{
		std::string response;
		do
		{
			if (!receive("topic regex"sv))
			{
				return;
			}
			response.push_back('N');
			auto regex_sv = to_string_view(_request.back());
			auto regex = std::regex(regex_sv.begin(), regex_sv.end());
			{
				auto lock = _s.subscriptionsLocker.lock_shared();
				if (std::find_if(_s.subscriptions.begin(), _s.subscriptions.end(),
							[&regex](const auto& s)
							{
								return std::regex_match(s, regex);
							}
							) != _s.subscriptions.end())
				{
					response.back() = 'S';
				}
			}
			// Our handlers removal is timeout based but zmq
			// listners removal is event based (hence faster), so we
			// do not check for handler if there are no listeners
			if (response.back() == 'S')
			{
				auto lock = _s.clientsLocker.lock_shared();
				if (_s.clients.handlers_match_request_topic(regex))
				{
					response.back() = 'H';
				}
			}
		}
		while (_request.back().more());
		_response.init(response);
	}

public:
	Manager() :
		_s(SharedState::instance())
	{
	}
	void run_manager()
	{
		++_run_call_count;

		auto rep_closer = SocketCloser(_s, _sock_rep, zmq::socket_type::rep,
				BindAndApplyGroup(_s, _s.cfgdata.req));

		auto to_proxy_closer = SocketCloser(_s, _sock_to_proxy);
		{
			auto lock = _s.subscriptionsLocker.lock_unique();
			while (_s.to_proxy_socket_address.empty())
			{
				_s.proxy_ready.wait(lock._lock);
			}
			to_proxy_closer.open(zmq::socket_type::push, [this](zmq::socket_t& sock) {
					sock.connect(_s.to_proxy_socket_address);});
		}


		while (true)
		{
			_request.clear();
			const auto subject = to_string_view(receive_unguarded());
			bool valid = true;
			bool excessive_parts = false;
			if (subject == "PING")
			{
				check_private_id<ReplyLostRequest>();
			}
			else if (subject == "HELLO")
			{
				add_new_id();
			}
			else if (subject == "GOODBYE")
			{
				check_private_id<ReplyLostRequest, DeleteClient>();
			}
			else if (subject == "HANDLE")
			{
				check_private_id<RegisterHandler>();
			}
			else if (subject == "EXISTS")
			{
				check_if_topic_exists();
			}
			else
			{
				valid = false;
				_response.init_multipart("INVALID"sv, "Unrecognized request: "sv);
				_response.parts[1].append_string(subject);
			}
			while (_request.back().more())
			{
				excessive_parts = true;
				_request.clear();
				receive_unguarded();
			}
			if (valid && excessive_parts)
			{
				_response.init_multipart("INVALID"sv, "To many parts"sv);
			}
			_response.send(_sock_rep);
		}
	}
private:

	static const IdType _maximum_allowed_normal_id = std::numeric_limits<IdType>::max() >> 8;

	unsigned long long random() const
	{
		static std::mt19937_64 generator{std::random_device()()};
		static std::uniform_int_distribution<IdType> dist(1, _maximum_allowed_normal_id);
		return dist(generator);
	}


	zmq::socket_t _sock_rep;
	zmq::socket_t _sock_to_proxy;
	SharedState& _s;
	int _run_call_count = 0;
	std::vector<zmq::message_t> _request;
	MultipartMessage _response;
};

void manager()
{
	static Manager the_manager;
	the_manager.run_manager();
}
