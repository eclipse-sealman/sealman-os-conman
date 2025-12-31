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
#ifndef CLIENT_LIST_H
#define CLIENT_LIST_H

#include <set>
#include <chrono>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/hashed_index.hpp>
#include <boost/multi_index/sequenced_index.hpp>
#include <boost/multi_index/member.hpp>
#include <regex>
#include <tuple>
#include "utils/string_storage.h"
#include "helpers.h"

typedef unsigned int  SequenceType;
typedef unsigned long long IdType;
BOOST_STRONG_TYPEDEF(IdType, PublicIdType);
BOOST_STRONG_TYPEDEF(IdType, PrivateIdType);
constexpr unsigned int id_size = sizeof(IdType);

enum class Familiarity
{
	acquaintance,
	alien
};

struct ClientProps
{
	struct LostRequest
	{
		LostRequest() = default;
		LostRequest(SequenceType seq) :
			public_id(0),
			sequence(seq)
		{
		}
		LostRequest(PublicIdType id, SequenceType seq, const std::string_view& response) :
			public_id(id), sequence(seq), response_topic(response)
		{
		}
		IdType public_id;
		SequenceType sequence;
		std::string response_topic;
	};
	struct ExpectedResponse
	{
		ExpectedResponse() = default;
		ExpectedResponse(SequenceType seq):
			sequence(seq)
		{
		}
		ExpectedResponse(utils::StoredStringView query, utils::StoredStringView response, SequenceType seq):
			query_topic(query),
			response_topic(response),
			sequence(seq)
		{
		}

		friend bool operator<(const ExpectedResponse& l, const ExpectedResponse r)
		{
			return l.sequence < r.sequence;
			//return std::tie(l.sequence, l.query_topic, l.response_topic) <
				//std::tie(r.sequence, r.query_topic, r.response_topic);
		}

		std::string_view query_topic;
		std::string_view response_topic;
		SequenceType sequence;

	};

	std::chrono::time_point<std::chrono::steady_clock> last_seen = std::chrono::steady_clock::now();

		// list of query/response pairs handled by this client
		// used for tracking registered responce topics
		// used for filling of expected_outgoing_responses
		// presence here keeps string in query/response storage
		// TODO actually keeps StoredStringView only but not enforced by
		// type system yet... verified manually
	std::unordered_map<std::string_view, std::string_view> served_topics;

		// temporary storage of requests from this client for which
		// responses will be rather not received, key is query topic
		// TODO initialy made as multimap, but seems that set/vector would be better probably
		// TODO we keep real strings hear as strings in storage can be
		// already removed when client receives data from here, shall we
		// change approach?
	std::unordered_multimap<std::string, LostRequest> lost_requests;

		// which handlers (private id) we expect to send how many responses to this client
		// TODO this is leftover from intermediate solution, currently intended as way
		// of early cleanup of expected outgoing responses and optionally to inform
		// handlers that they don't need to respond as client disconnected, but do we
		// really need it?
	std::unordered_map<IdType, unsigned int> expected_incoming_responses;

		// to which clients (public id) this handler shall send which responses
		// needed to fill lost_requests in case of handler removal
	std::unordered_map<IdType, std::set<ExpectedResponse>> expected_outgoing_responses;

		// statistics of this client
		// Global
	size_t published = 0;
	size_t requests = 0;
	size_t lost = 0;
	size_t responses = 0;

		// For stale responses detection (i.e. since last ping)
	unsigned int expected_outgoing_responses_count = 0;
	unsigned int last_lagging_count = 0;
	unsigned int new_expected_outgoing_responses_count = 0;
	unsigned int new_outgoing_responses_sent_count = 0;

		// used to extend lifetime of client even in case of missing
		// ping will probably ever kick in only in case of high overoald
	unsigned int lock_count = 0;

	Familiarity familiarity = Familiarity::acquaintance;

		[[ nodiscard ]]
	bool touch()
	{
		// Only if unanswered count grows
		if ((new_expected_outgoing_responses_count > new_outgoing_responses_sent_count) &&
			// and we are sure that there are some unaswered requests from before last ping
			(expected_outgoing_responses_count > new_expected_outgoing_responses_count))
		{
			auto lagging = expected_outgoing_responses_count - new_expected_outgoing_responses_count;

			// let's not be picky, and ignore small numbers of forgotten messages,
			// the goal is to avoid enormous memory consumption, not to detect each
			// unaswered message. TODO magic number chosen arbitralily
			if ((lagging > 100) &&
					// Only if our lag grown since last ping
					(lagging > last_lagging_count))
			{
				auto new_lagging = lagging - last_lagging_count;
				// Only if lagging messages are more than 10% of totals
				// received burst of messages and performed more than one ping
				// before responding to them he will enter here easily
				// Another way to enter here is to slowly leak slowly (i.e.
				// forget about one request from time to time completly)
				if ((10 * lagging > expected_outgoing_responses_count))
				{
					// One of 2 options.
					// either total lagging grew above recently received
					// messages, this deals mostly with slow leaks,
					if ((lagging > new_expected_outgoing_responses_count) ||
						// or more than 50% of recent burst was
						// unprocessed before sending new ping
						(2 * new_lagging > new_expected_outgoing_responses_count))
					return false;
				}
			}
			last_lagging_count = lagging;
		}
		new_expected_outgoing_responses_count = 0;
		new_outgoing_responses_sent_count = 0;
		last_seen = std::chrono::steady_clock::now();
		return true;
	}
};

struct Client
{
	// Client is meant to be kept in boost multi_index, hence data which can
	// affect indices is kept directly in it, and data which cannot affect
	// any of the indices is kept inside mutable props member
	IdType private_id;
	IdType public_id;
	mutable ClientProps props;

	void remove_expected_incoming_response(PrivateIdType priv_id) const
	{
		auto it = props.expected_incoming_responses.find(priv_id);
		assert(it != props.expected_incoming_responses.end());
		assert(it->second);
		it->second--;
		if (!it->second)
		{
			props.expected_incoming_responses.erase(it);
		}
	}

	void remove_all_expected_incoming_responses(PrivateIdType priv_id) const
	{
		auto removed = props.expected_incoming_responses.erase(priv_id);
		assert(removed);
	}

	void add_expected_incoming_response(PrivateIdType priv_id) const
	{
		props.expected_incoming_responses[priv_id]++;
		assert(props.expected_incoming_responses[priv_id]);
	}

	void add_unhandlable_request(std::string_view topic, SequenceType sequence) const
	{
		props.lost_requests.emplace(std::piecewise_construct,
				std::forward_as_tuple(topic),
				std::forward_as_tuple(sequence));
	}

	void add_lost_response(PublicIdType pub_id, ClientProps::ExpectedResponse& expected) const
	{
		props.lost_requests.emplace(std::piecewise_construct,
				std::forward_as_tuple(expected.query_topic),
				std::forward_as_tuple(pub_id, expected.sequence, expected.response_topic));
	}

	unsigned int clean_dead_client_requests(PublicIdType requestor) const
	{
		auto it = props.expected_outgoing_responses.find(requestor);
		assert(it != props.expected_outgoing_responses.end());
		unsigned int count = it->second.size();
		assert(count);
		props.expected_outgoing_responses.erase(it);
		return count;
	}

	bool add_request(PublicIdType requestor, std::string_view topic, SequenceType sequence) const
	{
		auto it = props.served_topics.find(topic);
		if (it == props.served_topics.end())
		{
			return false;
		}
		auto& responses = props.expected_outgoing_responses[requestor];
		// TODO we manually ensure that served_topics contains only StoredStringView, this should be automated in type system
		auto [expected_it, added] = responses.emplace(utils::StoredStringView(it->first), utils::StoredStringView(it->second), sequence);
		if (!added)
		{
			// seems that client reused sequence...
			return false;
		}
		++props.expected_outgoing_responses_count;
		++props.new_expected_outgoing_responses_count;
		return true;
	}

	bool new_response(std::string_view topic, PublicIdType requestor, SequenceType sequence) const
	{
		auto responses_it = props.expected_outgoing_responses.find(requestor);
		if (responses_it == props.expected_outgoing_responses.end())
		{
			return false;
		}
		auto& responses = responses_it->second;
		auto expected_it = responses.find(ClientProps::ExpectedResponse(sequence));
		if (expected_it == responses.end())
		{
			return false;
		}
		if (expected_it->response_topic != topic)
		{
			// naugthy handler, used different topic than promised, let's ignore it
		}
		responses.erase(expected_it);
		if (responses.empty())
		{
			props.expected_outgoing_responses.erase(responses_it);
		}
		--props.expected_outgoing_responses_count;
		++props.new_outgoing_responses_sent_count;
		return true;
	}

	void set_familiarity(Familiarity familiarity) const
	{
		props.familiarity = familiarity;
	}

	Client(PrivateIdType priv_id, PublicIdType pub_id) :
		private_id(priv_id),
		public_id(pub_id)
	{
	}

};

class ClientLocker
{
public:
	ClientLocker(const Client& client) :
		_client(client)
	{
		_client.props.lock_count++;
	}
	~ClientLocker()
	{
		_client.props.lock_count--;
	}
private:
	const Client& _client;
};

class ClientsState
{
public:
	typedef std::pair<std::string_view, std::string_view> QueryResponse;
	typedef boost::hash<QueryResponse> Hash;
	typedef std::unordered_map<QueryResponse, unsigned int, Hash> HandlersCount;
private:
	struct Sequence {};
	struct PrivId {};
	struct PubId {};
	typedef boost::multi_index::multi_index_container<Client,
		boost::multi_index::indexed_by<
			boost::multi_index::sequenced<
				boost::multi_index::tag<Sequence>
			>,
			boost::multi_index::hashed_unique<
				boost::multi_index::tag<PrivId>,
				boost::multi_index::member<Client, IdType, &Client::private_id>
				>,
			boost::multi_index::hashed_unique<
				boost::multi_index::tag<PubId>,
				boost::multi_index::member<Client, IdType, &Client::public_id>
				>
			>
		> Container;
	typedef Container::index_iterator<PrivId>::type priv_id_iterator;

	Container _data;

		// map from topics to handlers (private id) --- used to update that are
		// requests to which handler shall respond
		// this uses strings from storage, but is not used to manage their lifetime
	std::unordered_map<std::string_view, std::unordered_set<IdType>> handlers;
		// map from query/response to count of handlers --- used to manage topic handlers announcements
		// visible to clients in pub socket
		// presence here keeps string in query/response storage
	HandlersCount handlers_count;
		// temporary storage for query/response pairs we know shall be
		// annouced as lacking handlers
		// presence here keeps string in query/response storage
	HandlersCount dead_handlers;
	utils::StringStorage query_topics_storage;
	utils::StringStorage response_topics_storage;

	bool remove_impl(const Client& cli)
	{
		if (cli.props.lock_count)
		{
			ping(PrivateIdType(cli.private_id));
			return false;
		}
		auto& pub_ind = _data.get<PubId>();
		// Tell all clients waiting on our responses that they will not get them
		for (auto& [receiver_id, expected_set] : cli.props.expected_outgoing_responses)
		{
			auto receiver_it = pub_ind.find(receiver_id);
			assert(receiver_it != pub_ind.end());
			assert(expected_set.empty() == false);
			receiver_it->remove_all_expected_incoming_responses(PrivateIdType(cli.private_id));
			while (expected_set.empty() == false)
			{
				auto node = expected_set.extract(expected_set.begin());
				receiver_it->add_lost_response(PublicIdType(cli.public_id), node.value());
			}
		}
		// Tell all handlers that they shall not bother with responses to us
		// TODO this may be useful if we would switch to storing iterators instead of ids in props
		// for now it is just to keep our bookkeeping asserts clean
		auto& priv_ind = _data.get<PrivId>();
		for (auto& [handler_priv_id, count] : cli.props.expected_incoming_responses)
		{
			auto handler_it = priv_ind.find(handler_priv_id);
			assert(handler_it != priv_ind.end());
			assert(count);
			auto count2 = handler_it->clean_dead_client_requests(PublicIdType(cli.public_id));
			assert(count == count2);
		}
		// Go over our handlers and deregister them
		for (auto& [query_sv, response_sv] : cli.props.served_topics)
		{
			// First from handlers -> private_id map
			auto handlers_it = handlers.find(query_sv);
			assert(handlers_it != handlers.end());
			auto set_it =  handlers_it->second.find(cli.private_id);
			assert(set_it != handlers_it->second.end());
			handlers_it->second.erase(set_it);
			if (handlers_it->second.empty())
			{
				handlers.erase(handlers_it);
			}

			// Then
			auto handlers_count_it = handlers_count.find(std::make_pair(query_sv, response_sv));
			assert(handlers_count_it != handlers_count.end());
			assert(handlers_count_it->second);
			handlers_count_it->second--;
			if (handlers_count_it->second == 0)
			{
				dead_handlers.insert(handlers_count.extract(handlers_count_it));
			}
			query_topics_storage.pop(query_sv);
			response_topics_storage.pop(response_sv);
		}
		return true;
	}

public:
	class DeadHandlers : public HandlersCount, boost::noncopyable
	{
	public:
		DeadHandlers(HandlersCount&& dead_handlers, ClientsState& owner) :
			HandlersCount{dead_handlers},
			_owner{owner}
		{
		}

		DeadHandlers(DeadHandlers&&) = default;

		~DeadHandlers()
		{
			for (auto& element : *this)
			{
				_owner.query_topics_storage.pop(element.first.first);
				_owner.response_topics_storage.pop(element.first.second);
			}
		}
	private:
		ClientsState& _owner;
	};

	DeadHandlers get_dead_handlers()
	{
		HandlersCount temp(std::move(dead_handlers));
		dead_handlers.clear();
		return DeadHandlers(std::move(temp), *this);
	}
		/** Moves client to front of active clients list.
		 *
		 *  If client exists updates last_seen in client to current time
		 *  and returns iterator to client, otherwise returns empty
		 *  optional.
		 *
		 */
	std::optional<priv_id_iterator> ping(PrivateIdType priv_id)
	{
		auto& ind = _data.get<PrivId>();
		auto it = ind.find(priv_id);
		if (it == ind.end())
		{
			//return nullptr;
			return {};
		}
		if (!it->props.touch())
		{
			remove(it);
			return {};
		}
		_data.relocate(_data.end(), _data.project<0>(it));
		if (it->props.familiarity == Familiarity::alien)
		{
			return {};
		}
		return it;
	}

	PublicIdType get_public_id(PrivateIdType priv_id) const
	{
		auto& ind = _data.get<PrivId>();
		auto it = ind.find(priv_id);
		if (it == ind.end())
		{
			return PublicIdType(0);
		}
		return PublicIdType(it->public_id);
	}

	PrivateIdType get_private_id(PublicIdType pub) const
	{
		auto& ind = _data.get<PubId>();
		auto it = ind.find(pub);
		if (it == ind.end())
		{
			return PrivateIdType(0);
		}
		return PrivateIdType(it->private_id);
	}

		/** Returns client with oldest last_seen value.
		 */
	std::optional<Container::iterator> oldest()
	{
		if (_data.empty())
		{
			return {};
		}
		return _data.begin();
	}

		/* unique --- there is no other identical pair of query and response
		 * duplicate --- some other handler serves same response to a query
		 * accessory --- there is/are other handler(s) for same query but with differnt response topic
		 * new --- this is new query topic for client
		 * changed --- client changed response topic to earlier registered query topic
		 * readded --- client registed same pair of query/response as it did earlier
		 */
	enum class AddHandlerSatatus
	{
		unique_new,
		unique_changed,
		unique_readded,
		accessory_new,
		accessory_changed,
		accessory_readded,
		duplicate_new,
		duplicate_changed,
		duplicate_readded,
	};

		// TODO shall we switch to iterator instead of PublicId in interface of this function?
	bool add_request(PublicIdType requestor, std::string_view topic, SequenceType sequence)
	{
		auto& pub_ind = _data.get<PubId>();
		auto client_it = pub_ind.find(requestor);
		if (client_it == pub_ind.end())
		{
			return false;
		}
		auto handlers_it = handlers.find(topic);
		if (handlers_it == handlers.end())
		{
			client_it->add_unhandlable_request(topic, sequence);
			return false;
		}
		bool added = false;
		auto& priv_ind = _data.get<PrivId>();
		for (auto& handler_id : handlers_it->second)
		{
			auto hand_it = priv_ind.find(handler_id);
			assert(hand_it != priv_ind.end());
			if (hand_it == priv_ind.end())
			{
				continue;
			}
			if (hand_it->add_request(requestor, topic, sequence))
			{
				client_it->add_expected_incoming_response(PrivateIdType(handler_id));
				added = true;
			}
			else
			{
				// Either programming error on our side or client reused sequence
				client_it->add_unhandlable_request(topic, sequence);
				return false;
			}
		}
		if (added) [[ likely ]]
		{
			return true;
		}
		client_it->add_unhandlable_request(topic, sequence);
		return false;

	}

	bool new_response(PrivateIdType handler_id, std::string_view topic, PublicIdType requestor,
			SequenceType sequence)
	{
		auto& priv_ind = _data.get<PrivId>();
		auto handler_it = priv_ind.find(handler_id);
		if (handler_it == priv_ind.end())
		{
			return false;
		}
		if (handler_it->new_response(topic, requestor, sequence))
		{
			auto& pub_ind = _data.get<PubId>();
			auto client_it = pub_ind.find(requestor);
			if (client_it != pub_ind.end())
			{
				client_it->remove_expected_incoming_response(PrivateIdType(handler_id));
			}
			return true;
		}
		return false;
	}
		template <typename Query_T, typename Response_T>
	AddHandlerSatatus add_handler(const Query_T& query_topic, const Response_T& response_topic,
			const Client& client)
	{
		auto query_sv = query_topics_storage.push(query_topic);
		auto respose_sv = response_topics_storage.push(response_topic);
		auto [hc_it, is_new_hc] = handlers_count.emplace(std::make_pair(query_sv, respose_sv), 1);
		if (is_new_hc)
		{
			query_topics_storage.push(query_sv);
			response_topics_storage.push(respose_sv);
		}
		else
		{
			hc_it->second++;
		}
		auto [resp_it, is_new_c] = client.props.served_topics.emplace(query_sv, respose_sv);
		auto& h_set = handlers[query_sv];
		const bool is_new_query_globally = h_set.empty();
		auto [hand_it, is_new_h] = handlers[query_sv].emplace(client.private_id);
		//auto [hand_it, is_new_h] = handlers.emplace(query_sv, { client.private_id });
		// is_new_c | is_new_query_globally
		//  true    |  true    -> really fresh start for query topic
		//  true    |  false   -> this is new topic for client, but some other client handles it already
		//                        we need to check if that other client uses different response topic
		//  false   |  false   -> client tries to reregister query --- maybe it changes response topic
		//                        anyway, we need to check for conflicts as in above case
		//  false   |  true    -> shall not happen, we made some error during additions/removals earlier
		//
		if (is_new_c && is_new_query_globally)
		{
			return AddHandlerSatatus::unique_new;
		}

		bool readded_same = false;
		std::string old_response;
		if (!is_new_c)
		{
			// self reregistration, potentially changed response topic...
			if (resp_it->second != respose_sv)
			{
				old_response = resp_it->second;
#if 1 // TODO code duplication between here and remover in this #if 1 block...
				auto old_hc_it = handlers_count.find(std::make_pair(query_sv, old_response));
				assert(old_hc_it != handlers_count.end());
				old_hc_it->second--;
				if (old_hc_it->second == 0)
				{
					dead_handlers.insert(handlers_count.extract(old_hc_it));
				}
#endif //1
				mark_messages_as_lost(query_sv, old_response, client);
				response_topics_storage.pop(old_response);
				resp_it->second = respose_sv;
			}
			else
			{
				response_topics_storage.pop(respose_sv);
				assert(is_new_hc == false);
				hc_it->second--;
				readded_same = true;
			}
		}
		assert(is_new_h == is_new_c);
		if (is_new_h != is_new_c)
		{
			throw std::runtime_error("Failed synchronization between clients and handlers");
		}
		assert(is_new_query_globally ? is_new_c : true);
		if (is_new_query_globally && is_new_c == false)
		{
			throw std::runtime_error("Failed synchronization between clients and handlers");
		}

		//Check if we are duplicate or accessory or unique
		bool accessory = false;
		for (auto& handler_id : h_set)
		{
			if (handler_id == client.private_id)
			{
				continue;
			}
			auto other_response = get_response_topic(PrivateIdType(handler_id), query_sv);
			assert(other_response);
			if (!other_response)
			{
				throw std::runtime_error("Failed synchronization between clients and handlers");
			}
			if (respose_sv == *other_response)
			{
				if (is_new_c)     return AddHandlerSatatus::duplicate_new;
				if (readded_same) return AddHandlerSatatus::duplicate_readded;
				else              return AddHandlerSatatus::duplicate_changed;
			}
			accessory = true;
		}
		if (accessory)
		{
			if (is_new_c)     return AddHandlerSatatus::accessory_new;
			if (readded_same) return AddHandlerSatatus::accessory_readded;
			else              return AddHandlerSatatus::accessory_changed;
		}
		//if (is_new_c) was handled way above
		if (readded_same) return AddHandlerSatatus::unique_readded;
		else              return AddHandlerSatatus::unique_changed;
	}

	void mark_messages_as_lost(std::string_view query_sv, std::string_view response_sv, const Client& handler)
	{
		auto& ind = _data.get<PubId>();
		auto client_it = ind.end();
		ClientProps& handler_props = handler.props;
		auto responses_end = handler_props.expected_outgoing_responses.end();
		for (auto responses_it = handler_props.expected_outgoing_responses.begin();
				responses_it != responses_end;)
		{
			auto& client_id = responses_it->first;
			std::set<ClientProps::ExpectedResponse>& responses = responses_it->second;
			assert(responses.empty() == false);
			bool client_it_unset = true;
			auto expected_end = responses.end();
			for (auto expected_it = responses.begin(); expected_it != expected_end;)
			{
				if (expected_it->query_topic == query_sv &&
						expected_it->response_topic == response_sv)
				{
					if (client_it_unset)
					{
						client_it = ind.find(client_id);
						assert(client_it != ind.end());
					}
					client_it->remove_expected_incoming_response(
							PrivateIdType(handler.private_id));
					auto it_copy = expected_it;
					++expected_it;
					auto node = responses.extract(it_copy);
					client_it->add_lost_response(PublicIdType(handler.public_id), node.value());
				}
				else
				{
					++expected_it;
				}
			}
			if (responses_it->second.empty())
			{
				responses_it = handler.props.expected_outgoing_responses.erase(responses_it);
			}
			else
			{
				++responses_it;
			}
		}
	}

		/* Ensures client exists and marks if it said Hello to us.
		 *
		 * Returns true if new client was created, false otherwise.
		 *
		 * If new client was created we also set if it said hello
		 * (Familiarity::acquaintance) or not (Familiarity::alien)
		 *
		 * Note that if client already existed it is not updated anyhow.
		 */
	bool insert_friend(PrivateIdType priv_id, PublicIdType pub_id)
	{
		auto [client_it, is_new] = _data.emplace_back(priv_id, pub_id);
		if (is_new)
		{
			client_it->set_familiarity(Familiarity::acquaintance);
		}
		return is_new;
	}

	bool try_insert_alien(PrivateIdType priv_id, PublicIdType pub_id)
	{
		auto [client_it, is_new] = _data.emplace_back(priv_id, pub_id);
		if (is_new)
		{
			client_it->set_familiarity(Familiarity::alien);
		}
		else if (client_it->private_id != priv_id || client_it->public_id != pub_id)
		{
			return false;
		}
		return true;
	}

	bool make_friend(PrivateIdType priv_id, PublicIdType pub_id)
	{

		auto [client_it, is_new] = _data.emplace_back(priv_id, pub_id);
		if (is_new == false)
		{
			if (client_it->private_id != priv_id || client_it->public_id != pub_id)
			{
				// Oops, we tried to make a fried from client
				// with different id's than we expected
				return false;
			}
		}
		client_it->set_familiarity(Familiarity::acquaintance);
		return true;
	}

	void remove(const Client& cli)
	{
		if (remove_impl(cli))
		{
			_data.get<PrivId>().erase(cli.private_id);
		}
	}

	void remove(priv_id_iterator& cli)
	{
		if (remove_impl(*cli))
		{
			_data.get<PrivId>().erase(cli);
		}
	}

	void remove(Container::iterator& cli)
	{
		if (remove_impl(*cli))
		{
			_data.erase(cli);
		}
	}

	bool empty() const
	{
		return _data.empty();
	}

	bool handlers_match_request_topic(const std::regex& regex) const
	{
		const auto end = handlers_count.end();
		if (std::find_if(handlers_count.begin(), end,
					[&regex](const auto& qrp_and_count)
					{
						if (std::regex_match(qrp_and_count.first.first.begin(), qrp_and_count.first.first.end(), regex))
						{
							return qrp_and_count.second > 0;
						}
						return false;
					}) != end)
		{
			return true;
		}
		return false;
	}

	auto size() const
	{
		return _data.size();
	}

		template <typename T>
	const std::optional<std::string_view> get_response_topic(PrivateIdType handler_id, const T& query_topic) const
	{
		auto& ind = _data.get<PrivId>();
		auto cli_it = ind.find(handler_id);
		if (cli_it == ind.end())
		{
			return {};
		}
		auto& served = cli_it->props.served_topics;
		auto served_it = served.find(query_topic);
		if (served_it == served.end())
		{
			return {};
		}
		return served_it->second;
	}
};

#endif //CLIENT_LIST_H
