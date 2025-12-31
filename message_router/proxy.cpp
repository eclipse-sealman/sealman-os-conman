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
#include "proxy.h"
#include <thread>
#include <utility>
#include "socket_closer.h"

using namespace std::literals;


class Proxy
{
private:

	bool sock_pull_in_progress() const
	{
		return _sock_pull_message.empty() == false && _sock_pull_message.back().more();
	}

	void send_out_internal(zmq::socket_t& socket)
	{
		if (sock_pull_in_progress())
		{
			return;
		}
		for (auto& multipart : _internal_queue)
		{
			for (auto& part : multipart)
			{
				socket.send(part, send_flags(part.more()));
			}
		}
		_internal_queue.clear();
	}

	zmq::message_t publish_receive(zmq::socket_t& socket)
	{
		zmq::message_t received;
		const auto received_count = socket.recv(received);
		if (!received_count)
		{
			throw std::runtime_error("Nothing received in pull but we expected to get some");
		}
		return received;
	}

	void publish()
	{
		static IdType counter{0};
		bool more = false;
		bool valid_private_id_size_detected = false;
		bool valid_public_id_size_detected = false;
		bool ids_verified = false;
		do
		{
			_sock_pull_message.emplace_back(publish_receive(_sock_pull));
			auto& part=_sock_pull_message.back();
			more = part.more();
			switch (_sock_pull_message.size())
			{
			case 1:
				break;
			case 2:
				if (part.size() == sizeof(IdType)) [[likely]]
				{
					valid_private_id_size_detected = true;
					_current_message_private_id = get_raw_copy_aligned<IdType>(part);
					put_raw_copy(++counter, part);
					{
						auto lock = _s.clientsLocker.lock_shared();
						_current_message_public_id = _s.clients.get_public_id(_current_message_private_id);
					}
				}
				// else
				// {
					// Invalid size of private id field shall cause clients to ignore message
					// (unless they want to work around a buggy client) --- so we leave it as is
				// }
				break;
			case 3:
				if (part.size() == sizeof(IdType)) [[likely]]
				{
					valid_public_id_size_detected = true;
					const PublicIdType public_id_field_copy{get_raw_copy_aligned<IdType>(part)};
					if (_current_message_public_id && _current_message_public_id == public_id_field_copy) [[ likely ]]
					{
						// Typical case --- client provided known matching pair of ids
						ids_verified = true;
					}
					else if (_current_message_public_id == PublicIdType(0))
					{
						// Atypical case --- probably forwarder restart happened...
						bool shall_notify_active_clients = false;
						{
							auto lock = _s.clientsLocker.lock_unique();
							bool clients_were_empty = _s.clients.empty();
							if (_s.clients.try_insert_alien(_current_message_private_id, public_id_field_copy))
							{
								ids_verified = true;
								_current_message_public_id = public_id_field_copy;
								shall_notify_active_clients = clients_were_empty;
							}
							// else
							// {
								// There exists already another client with this public
								// id, most probably client is buggy, (alternatively we
								// faced very unlikely scenario:
								// 1. There is client A with pub_id FOO, priv_id privA
								// 2. Forwarder is restarted
								// 3. New client B connects to forwarder requesting pub_id FOO and receives priv_id privB
								// 4. Old client A tries to get its old pub_id FOO and // priv_id privA
								// Anyway we don't need to do anything here because
								// ids_verified is initialized to false
							// }
						}
						if (shall_notify_active_clients)
						{
							_s.active_clients.notify_all();
						}
					}
					if (ids_verified == false) [[ unlikely ]]
					{
						// Naughty client tried to use invalid public id
						// We need to clear the public ID from message unfortunately
						// and we need to set _current_message_public_id to untrusted so we can
						// copy it into sequence field later
						_current_message_public_id = public_id_field_copy;
						std::memset(part.data(), 0, part.size());
					}
				}
				// else
				// {
					// Invalid size of public id field means that we cannot trust in what we
					// calculated from private id, we consiously do nothing here though (i.e. leave
					// this invalid public id in message --- clients know the right size)
				// }
				break;
			case 4:
				if (ids_verified == false)
				{
					// Message contained valid size but invalid value public/private id pair --- we replaced public id
					// with 0 and removed private id, but in case we have a buggy (but still
					// providing some usable information in those 2 fields) client we copy both
					// values to the message id part, so other clients can work around
					// the buggy one without changes in forwarder.
					char which_id_present_bit_field = 0;
					char present_id_sum = 0;
					if (valid_private_id_size_detected)
					{
						++present_id_sum;
						which_id_present_bit_field += 1;
					}
					if (valid_public_id_size_detected)
					{
						++present_id_sum;
						which_id_present_bit_field += 2;
					}

					const size_t size_of_marker_byte_and_bit_field_byte = 2;
					zmq::message_t temp(size_of_marker_byte_and_bit_field_byte + present_id_sum * sizeof(IdType) + part.size());
					char* data = reinterpret_cast<char*>(temp.data());
					data[0] = '$';
					data[1] = which_id_present_bit_field;
					const auto private_id_start = data + 2;
					const auto public_id_start = private_id_start + (valid_private_id_size_detected ? sizeof(IdType) : 0);
					const auto sequence_start = public_id_start + (valid_public_id_size_detected ? sizeof(IdType) : 0);
					if (valid_private_id_size_detected)
					{
						std::memcpy(private_id_start, &_current_message_private_id, sizeof(IdType));
					}
					if (valid_public_id_size_detected)
					{
						memcpy(public_id_start, &_current_message_public_id, sizeof(IdType));
					}
					memcpy(sequence_start, part.data(), part.size());
					part.swap(temp);
				}
				else
				// TODO for now we use lock unique here, but we may think about
				// changing locking strategy, so we use unique lock of clientsLocker
				// only for operations on indices (i.e. addition/removal of client)
				// and use lighter per client props locks (e.g. spin locks with yield
				// or semaphores) to guard containers inside client props
				{
					char& first_char = *reinterpret_cast<char*>(part.data());
					auto lock = _s.clientsLocker.lock_unique();
					if (first_char == 'M')
					{
						if (part.size() != sizeof(SequenceType))
						{
							first_char = '^';
						}
					}
					else if (first_char == 'Q')
					{
						if (part.size() != sizeof(SequenceType))
						{
							first_char = '?';
						}
						else if (!_s.clients.add_request(_current_message_public_id,
								to_string_view(_sock_pull_message.front()),
								get_raw_copy_aligned<SequenceType>(part)))
						{
							first_char = 'q';
						}
					}
					else if (first_char == 'R')
					{
						if (part.size() != sizeof(IdType) + sizeof(SequenceType) + 1)
						{
							first_char = '#';
						}
						else if (!_s.clients.new_response(_current_message_private_id,
								to_string_view(_sock_pull_message.front()),
								PublicIdType(get_raw_copy_aligned<IdType>(
										part, 1)),
								get_raw_copy_aligned<SequenceType>(
									part, 1 + sizeof(IdType))))
						{
							first_char = 'r';
						}
					}
					else
					{
						zmq::message_t temp(1 + part.size());
						char* data = reinterpret_cast<char*>(temp.data());
						data[0] = '&';
						++data;
						std::memcpy(data, part.data(), part.size());
						part.swap(temp);
					}
				}
				_sock_xpub.send(_sock_pull_message[0], zmq::send_flags::sndmore);
				_sock_xpub.send(_sock_pull_message[1], zmq::send_flags::sndmore);
				_sock_xpub.send(_sock_pull_message[2], zmq::send_flags::sndmore);
				[[ fallthrough ]];
			default:
				_sock_xpub.send(part, send_flags(more));
				break;
			}
		} while (more && zmq::poll(item_pull(), 1, 0));
		if (!more)
		{
			if (_sock_pull_message.size() == 1)
			{
				_sock_xpub.send(_sock_pull_message[0], zmq::send_flags::none);
			}
			if (_sock_pull_message.size() == 2)
			{
				_sock_xpub.send(_sock_pull_message[0], zmq::send_flags::sndmore);
				_sock_xpub.send(_sock_pull_message[1], zmq::send_flags::none);
			}
			_sock_pull_message.clear();
		}
		send_out_internal(_sock_xpub);
	}

	void publish_internal(zmq::socket_t& sock_from, zmq::socket_t& sock_to)
	{
		static std::vector<zmq::message_t> temp_storage;
		static int internal_resurections = 0;
		if (_run_call_count > internal_resurections)
		{
			if (temp_storage.empty() == false)
			{
				// seems that we crashed but watchdog restarted us
				if (temp_storage.back().more() == false)
				{
					// message is full, we can send it
					_internal_queue.emplace_back(std::move(temp_storage));
					temp_storage.clear();
				}
			}
			internal_resurections = _run_call_count;
		}
		auto received = publish_receive(sock_from);
		const bool more=received.more();
		temp_storage.emplace_back(std::move(received));
		if (more)
		{
			return;
		}
		_internal_queue.emplace_back(std::move(temp_storage));
		temp_storage.clear();
		send_out_internal(sock_to);
	}

	void manage_subscription(zmq::socket_t& socket)
	{
		zmq::message_t received;
		const auto received_count = socket.recv(received);
		if (!received_count)
		{
			throw std::runtime_error("Nothing received xpub but we expected to get some");
		}
		if (received.size() < 1)
		{
			throw std::runtime_error("Empty subscription message");
		}
		auto sv = to_string_view(received);
		if (sv[0] != 0 && sv[0] != 1)
		{
			throw std::runtime_error("Invalid first byte of subscription message");
		}
		const bool subscription = sv[0];
		sv = sv.substr(1);
		bool subscriptions_updated = false;
		{
			auto lock = _s.subscriptionsLocker.lock_unique();
			if (subscription)
			{
				const auto [it, is_new] = _s.subscriptions.emplace(sv);
				subscriptions_updated = is_new;
			}
			else
			{
				auto it = _s.subscriptions.find(sv);
				if (it != _s.subscriptions.end())
				{
					subscriptions_updated = true;
					_s.subscriptions.erase(it);
				}
			}
		}
		if (subscriptions_updated)
		{
			char& c = *static_cast<char*>(received.data());
			c = (subscription ? '+' : '-');
			std::vector<zmq::message_t> temp_storage;
			temp_storage.emplace_back(std::move(received));
			_internal_queue.emplace_back(std::move(temp_storage));
			send_out_internal(socket);
		}
	}

public:
	Proxy() :
		_s(SharedState::instance())
	{
	}
	void run_proxy()
	{
		++_run_call_count;

               auto pull_binder = SocketCloser(_s, _sock_pull, zmq::socket_type::pull,
                               BindAndApplyGroup(_s, _s.cfgdata.push));
               auto xpub_binder = SocketCloser(_s, _sock_xpub, zmq::socket_type::xpub,
                               BindAndApplyGroup(_s, _s.cfgdata.sub));
               auto to_proxy_binder = SocketCloser(_s, _sock_to_proxy);
		{
			auto lock = _s.subscriptionsLocker.lock_unique();
			_s.to_proxy_socket_address = "inproc://to_proxy";
			to_proxy_binder.open(zmq::socket_type::pull, [this](zmq::socket_t& sock) {
					sock.bind(_s.to_proxy_socket_address);});
		}

		_poll_list.emplace_back(zmq::pollitem_t{_sock_pull, 0, ZMQ_POLLIN, 0});
		_poll_list.emplace_back(zmq::pollitem_t{_sock_xpub, 0, ZMQ_POLLIN, 0});
		_poll_list.emplace_back(zmq::pollitem_t{_sock_to_proxy, 0, ZMQ_POLLIN, 0});
		assert(item_pull()->socket == static_cast<void*>(_sock_pull));
		assert(item_xpub()->socket == static_cast<void*>(_sock_xpub));
		assert(item_internal()->socket == static_cast<void*>(_sock_to_proxy));

		{
			zmq::message_t empty;
			_sock_xpub.send(empty, zmq::send_flags::none);
		}

		_s.proxy_ready.notify_all();

		while (true)
		{
			const int events_count = zmq::poll(_poll_list);
			if (!events_count)
			{
				throw std::runtime_error("Poll without timeout returned 0 events");
			}
			if (_poll_list[0].revents)
			{
				publish();
			}
			if (_poll_list[1].revents)
			{
				manage_subscription(_sock_xpub);
			}
			if (_poll_list[2].revents)
			{
				publish_internal(_sock_to_proxy, _sock_xpub);
			}
		}
	}

private:
	zmq::pollitem_t* item_pull()
	{
		return &_poll_list[0];
	}
	zmq::pollitem_t* item_xpub()
	{
		return &_poll_list[1];
	}
	zmq::pollitem_t* item_internal()
	{
		return &_poll_list[2];
	}
	zmq::socket_t _sock_pull;
	zmq::socket_t _sock_xpub;
	zmq::socket_t _sock_to_proxy;
	std::vector<zmq::pollitem_t> _poll_list;

	SharedState& _s;

	PublicIdType _current_message_public_id = PublicIdType(0);
	PrivateIdType _current_message_private_id = PrivateIdType(0);
	std::vector<zmq::message_t> _sock_pull_message;

	std::vector<std::vector<zmq::message_t>> _internal_queue;

	int _run_call_count = 0;
};

void proxy()
{
	static Proxy the_proxy;
	the_proxy.run_proxy();
}
