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
#ifndef CONFIG_COMMON_OPTIONS_H
#define CONFIG_COMMON_OPTIONS_H

#include "config/data.h"
#include <boost/program_options.hpp>
#include <boost/make_shared.hpp>
#include <boost/algorithm/string.hpp>
#include <iostream>
#include <sys/types.h>
#include <grp.h>

namespace config
{
namespace po = boost::program_options;
using namespace std::literals;

class OptionsBase
{
protected:
	typedef po::option_description Desc;
	typedef boost::shared_ptr<Desc> SharedDesc;
	std::string _description;
	po::options_description _named;
	po::options_description _positional;
	boost::optional<po::positional_options_description> _pos;
	bool _early_exit_needed = false;
	bool _val_help = false;
	po::variables_map _vm;

public:
	OptionsBase(const std::string& desc) :
		_description(desc),
		_named("Named options"),
		_positional("Positional options")
	{
		_named.add_options()
			("help,h",     po::bool_switch(&_val_help),
			 "print this help message");
	}

protected:
	void parse(int argc, char* argv[])
	{
		po::options_description allowed("All allowed options (named and positional)");
		allowed.add(_named).add(_positional);
		if (!_pos)
		{
			_pos =  po::positional_options_description();
			_pos->add("positional", 0);
		}
		try
		{
			//po::store(po::parse_command_line(argc, argv, _help), _vm);
			//auto parsed = po::parse_command_line(argc, argv, _help);
			auto parsed = po::command_line_parser(argc, argv).
				options(allowed).
				positional(*_pos).
				run();
			po::store(parsed, _vm);
			po::notify(_vm);
		}
		catch (po::error& e)
		{
			report_options_parsing_error("Error: "s +  e.what());
		}
	}

		template <typename T>
	void add_option(const char* name, SharedDesc& option, T& value, const char* help)
	{
		option = boost::make_shared<po::option_description>(name, po::value(&value), help);
		_named.add(option);
	}

		template <typename T>
	void add_positional(const char* name, SharedDesc& option, T& value, const char* help)
	{
		if (!_pos)
		{
			_pos =  po::positional_options_description();
		}
		if (_pos->max_total_count() == std::numeric_limits<unsigned>::max())
		{
			throw std::runtime_error("Unable to add positional option after infitite number of them was already declared");
		}
		_pos->add(name, 1);
		option = boost::make_shared<po::option_description>(name, po::value(&value), help);
		_positional.add(option);
	}

		template <typename T>
	void ensure_user_gave_non_empty(SharedDesc& option, boost::optional<T>& value)
	{
		if (value)
		{
			boost::trim_left(*value);
			if (value->empty())
			{
				std::cerr << "Param " << option->canonical_display_name() << " cannot be empty";
				exit(1);
			}
		}
	}

	void check_help()
	{
		if (_val_help)
		{
			_early_exit_needed=true;
			print_help(std::cout);
		}
	}

	void print_help(std::ostream& ostr)
	{
		ostr << _description << "\n";
		if (_pos && _pos->max_total_count() && _positional.options().size() == _pos->max_total_count())
		{
			ostr << " Synopsis: [named options]";
			for (unsigned int i = 0; i < _pos->max_total_count(); ++i)
			{
				ostr << " " << _pos->name_for_position(i);
			}
			ostr << "\n";
			ostr << _positional << "\n";
		}
		ostr << _named << "\n";
	}

	[[noreturn]] void report_options_parsing_error(std::string_view sv)
	{
		print_help(std::cerr);
		std::cerr << "\n##########\n" << sv <<    "\n##########\n";
		exit(1);
	}

};

class CommonOptions : public OptionsBase
{
protected:

	config::Data& _out;
	boost::optional<std::string> _val_name;
	boost::optional<std::string> _val_dir;
	SharedDesc _name;
	SharedDesc _dir;
	SharedDesc _group;
	SharedDesc _req;
	SharedDesc _push;
	SharedDesc _sub;
	std::filesystem::path _path;

public:
	CommonOptions(config::Data& data, const std::string& desc) :
		OptionsBase(desc),
		_out(data)
	{
		add_option("dir,d", _dir, _val_dir,
			"directory in which IPC sockets will be located "
			"(we will try to use temporary directory if this option is not given)");
		add_option("group,g", _group, _out.group,
			"group to which IPC sockets will belong (defaults to primary user group)");
		add_option("name,n", _name, _val_name,
			"prefix name of IPC sockets (will default to group name if not given)");
		add_socket("req,r", _req, _out.req.first, "client managent");
		add_socket("push,p", _push, _out.push.first, "sending to forwarder");
		add_socket("sub,s", _sub, _out.sub.first, "listening to forwarder");
	}

protected:

	void validate_common_options()
	{
		check_help();
		validate_group();
		calculate_path_if_needed();
		set_ipc_socket_if_needed(_req, _out.req);
		set_ipc_socket_if_needed(_push, _out.push);
		set_ipc_socket_if_needed(_sub, _out.sub);

		if (_early_exit_needed)
		{
			exit(0);
		}
	}

		template <typename T>
	void add_socket(const char* name, SharedDesc& option, T& value, std::string_view help)
	{
		add_option(name, option, value,
				"manually specified socket for "s.append(help).
				append(" (has priority over one created in --dir)").c_str());
	}

private:
		template <typename T>
	void set_ipc_socket_if_needed(SharedDesc& option, T& value)
	{
		constexpr std::string_view ipc = "ipc://";
		ensure_user_gave_non_empty(option, value.first);
		if (value.first)
		{
			const std::string& val = *value.first;
			auto pos = val.find(ipc, 0);
			if (pos == 0)
			{
				value.second = val.substr(ipc.size());
			}
		}
		else
		{
			auto temp_path = _path;
			temp_path += option->long_name();
			value.second = temp_path;
			value.first = std::string(ipc).append(value.second);
		}
	}

	void validate_group()
	{
		ensure_user_gave_non_empty(_group, _out.group);
		if (_out.group)
		{
			auto groupent = ::getgrnam(_out.group->c_str());
			if (!groupent)
			{
				auto gid = boost::lexical_cast<::gid_t>(*_out.group);
				groupent = ::getgrgid(gid);
				if (!groupent)
				{
					report_options_parsing_error("Unable find group: "s + *_out.group);
				}
				_out.group = groupent->gr_name;
			}
			_out.gid = groupent->gr_gid;
		}
		else
		{
			_out.gid = ::getegid();
			auto groupent = ::getgrgid(*_out.gid);
			_out.group = groupent->gr_name;
		}
	}

	void calculate_path_if_needed()
	{
		if ((_out.req.first && _out.push.first && _out.sub.first) == false)
		{
			ensure_user_gave_non_empty(_dir, _val_dir);
			if (!_val_dir)
			{
				_val_dir = std::filesystem::temp_directory_path();
			}
			if (!_val_name)
			{
				if (_out.group)
				{
					_val_name = _out.group;
				}
				else
				{
					_val_name = "";
				}
			}
			else
			{
				boost::trim(*_val_name);
			}
			_path = *_val_dir;
			if (!std::filesystem::exists(_path))
			{
				report_options_parsing_error("Path does not exist: "s + _path.native());
			}

			_path /= *_val_name + (_val_name->empty() ? "" : ".");
		}
	}

};

} // namepsace config

#endif //CONFIG_COMMON_OPTIONS_H

