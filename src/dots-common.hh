/*******************************************************************************
   This file is part of Distributed OpenPGP Timestamping Service (DOTS).

 Copyright (C) 2019  Heiko Stamer <HeikoStamer@gmx.net>

   DOTS is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   DOTS is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with DOTS; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
*******************************************************************************/

#ifndef INCLUDED_dots_common_HH
	#define INCLUDED_dots_common_HH

	// include headers
	#include <string>
	#include <iostream>
	#include <sstream>
	#include <fstream>
	#include <vector>
	#include <cstring>
	#include <csignal>

	#include <unistd.h>
	#include <netdb.h>
	#include <netinet/in.h>
	#include <sys/socket.h>

	#include <libTMCG.hh>

	enum dots_status_t
	{
		DOTS_STATUS_UNKNOWN		= 0,
		DOTS_STATUS_SUBMITTED	= 1,
		DOTS_STATUS_CONFIRMED	= 2,
		DOTS_STATUS_STARTED		= 3,
		DOTS_STATUS_STAMPED		= 4,
		DOTS_STATUS_FAILED		= 50,
	};

	bool dots_http_request
		(const std::string &hostname,
	 	 const uint16_t port,
		 const std::string &url,
		 std::string &content,
		 std::string &type,
		 const int opt_verbose);
	bool dots_start_process
		(const std::string &cmd,
		 const std::vector<std::string> &peers,
		 const std::string &hostname,
		 const std::string &passwords,
		 const std::string &uri,
		 const int opt_W,
		 char **envp,
		 pid_t &pid,
		 bool &forked,
		 time_t &forked_time,
		 int &fd_in,
		 int &fd_out,
		 int &fd_err,
		 const std::string &lh,
		 const uint16_t port,
		 const std::string &sn,
		 const int opt_verbose);
	void dots_kill_process
		(const pid_t pid,
		 const int opt_verbose);
	bool dots_encrypt_fuzzy
		(const std::string &in,
		 const tmcg_openpgp_secure_string_t &passphrase,
		 std::string &out,
		 const tmcg_openpgp_byte_t count = 0xF0); // default S2K count

#endif

