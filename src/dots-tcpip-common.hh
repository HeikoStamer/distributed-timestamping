/*******************************************************************************
   This file is part of Distributed OpenPGP Timestamping Service (DOTS).

 Copyright (C) 2018, 2019  Heiko Stamer <HeikoStamer@gmx.net>

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

#ifndef INCLUDED_dots_tcpip_common_HH
	#define INCLUDED_dots_tcpip_common_HH

	// include headers
	#include <string>
	#include <iostream>
	#include <sstream>
	#include <fstream>
	#include <vector>
	#include <list>
	#include <map>
	#include <algorithm>
	#include <cassert>
	#include <cstring>
	#include <cstdio>
	#include <csignal>

	#include <unistd.h>
	#include <errno.h>
	#include <fcntl.h>
	#include <sys/types.h>
	#include <sys/wait.h>
	#include <netdb.h>
	#include <netinet/in.h>
	#include <sys/socket.h>

	#include <microhttpd.h>
	#include <gcrypt.h>
	#include <libTMCG.hh>

	void tcpip_init
		(const std::string &hostname);
	void tcpip_bindports
		(const uint16_t start, const bool broadcast);
	bool tcpip_fork
		();
	int tcpip_io
		();
	void tcpip_close
		();
	void tcpip_done
		();

#endif

