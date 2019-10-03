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

// include headers
#ifdef HAVE_CONFIG_H
	#include "dots_config.h"
#endif

// copy infos from DOTS package before overwritten by other headers
static const char *version = PACKAGE_VERSION " (" PACKAGE_NAME ")";
static const char *about = PACKAGE_STRING " " PACKAGE_URL;
static const char *protocol = "DOTS-dotsd-0.0";

#include <sstream>
#include <fstream>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <cstdio>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <csignal>

#include <gmp.h>

#include <libTMCG.hh>
#include <aiounicast_select.hh>

#include "dots-common.hh"
#include "dots-tcpip-common.hh"

int                                ctrlfd[2];
int                                pipefd[DOTS_MAX_N][DOTS_MAX_N][2];
int                                self_pipefd[2];
int                                broadcast_pipefd[DOTS_MAX_N][DOTS_MAX_N][2];
int                                broadcast_self_pipefd[2];
pid_t                              pid[DOTS_MAX_N];
time_t                             ping[DOTS_MAX_N];
std::vector<std::string>           peers;
bool                               instance_forked = false;
bool                               signal_caught = false;
bool                               dkgpg_forked = false;
pid_t                              dkgpg_pid = 0;
time_t                             dkgpg_time = 0;
char*                              *dkgpg_env = NULL;
std::string                        dkgpg_cmd = DOTS_PATH_DKGPG;
int                                dkgpg_fd_in = -1, dkgpg_fd_out = -1;
int                                dkgpg_fd_err = -1;

std::string                        passwords, hostname, port, URI;
std::string                        policyfilename;
std::stringstream                  policyfile;
std::map<std::string, std::string> map_passwords;


int                                opt_verbose = 0;
char                               *opt_passwords = NULL;
char                               *opt_hostname = NULL;
char                               *opt_URI = NULL;
unsigned long int                  opt_p = 56000, opt_W = 5;

bool ctrl
	(unsigned char *ctrl_buf, const size_t ctrl_buf_size, size_t &ctrl_len,
	 aiounicast_select *aiou, bool &signal_caught)
{
	fd_set rfds;
	struct timeval tv;
	int retval;
	FD_ZERO(&rfds);
	if (ctrlfd[0] < FD_SETSIZE)
	{
		FD_SET(ctrlfd[0], &rfds);
	}
	else
	{
		std::cerr << "ERROR: file descriptor value of control" <<
			" pipe exceeds FD_SETSIZE" << std::endl;
		signal_caught = true; // handle this as an interrupt
		return true;
	}
	tv.tv_sec = 0;
	tv.tv_usec = 100000; // sleep only for 100000us = 100ms
	retval = select((ctrlfd[0] + 1), &rfds, NULL, NULL, &tv);
	if (retval < 0)
	{
		if (errno == EINTR)
		{
			return true;
		}
		else
		{
			perror("ERROR: ctrl (select)");
			signal_caught = true; // handle this as an interrupt
			return true;
		}
	}
	size_t max = ctrl_buf_size - ctrl_len;
	if ((retval > 0) && FD_ISSET(ctrlfd[0], &rfds) && (max > 0))
	{
		ssize_t len = read(ctrlfd[0], ctrl_buf + ctrl_len, max);
		if (len < 0)
		{
			if ((errno == EWOULDBLOCK) || (errno == EINTR))
			{
				return true;
			}
			else if (errno == EAGAIN)
			{
				perror("WARNING: ctrl (read)");
				return true;
			}
			else
			{
				perror("ERROR: ctrl (read)");
				signal_caught = true; // handle this as an interrupt
				return true;
			}
		}
		else if (len == 0)
		{
			std::cerr << "ERROR: control pipe collapsed" << std::endl;
			signal_caught = true; // handle this as an interrupt
			return true;
		}
		else
			ctrl_len += len;
	}
	bool nl_found = false;
	size_t nl_pos = 0;
	for (size_t i = 0; i < ctrl_len; i++)
	{
		if (ctrl_buf[i] == '\n')
		{
			nl_found = true, nl_pos = i;
			break;
		}
	}
	if (nl_found)
	{
		char msg[1024];
		memset(msg, 0, sizeof(msg));
		memcpy(msg, ctrl_buf, nl_pos);
		if (opt_verbose > 1)
		{
			std::cerr << "INFO: control message received;" <<
				" msg = " << msg << std::endl;
		}
		std::string msg_str(msg);
		size_t msg_col = msg_str.find(":");
		if (msg_col != msg_str.npos)
		{
			std::string msg_cmd, msg_arg;
			msg_cmd = msg_str.substr(0, msg_col);
			if (msg_str.length() > 1)
			{
				msg_arg = msg_str.substr(msg_col + 1,
					msg_str.length() - msg_col - 1);
			}
			if (opt_verbose > 1)
			{
				std::cerr << "INFO: control message processed;" <<
					" cmd = " << msg_cmd << " arg = " << msg_arg << std::endl;
			}
			size_t peer = strtoul(msg_arg.c_str(), NULL, 10);
			if (msg_cmd == "CTRL_AIO_BROADCAST_RESET_IN")
				aiou->Reset(peer, true);
			if (msg_cmd == "CTRL_AIO_BROADCAST_RESET_OUT")
				aiou->Reset(peer, false);
		}
		else
		{
			std::cerr << "WARNING: bad control message;" <<
				" msg = " << msg << std::endl;
		}
		memmove(ctrl_buf, ctrl_buf + nl_pos + 1, ctrl_len - nl_pos - 1);
		ctrl_len -= (nl_pos + 1);
		memset(ctrl_buf + ctrl_len, 0, ctrl_buf_size - ctrl_len);
	}
	return false;
}

void run_instance
	(const size_t whoami)
{
	std::vector<std::string> active_peers;
	active_peers.insert(active_peers.end(), peers.begin(), peers.end());
	// create communication handles between all players
	std::vector<int> bP_in, bP_out;
	std::vector<std::string> bP_key;
	for (size_t i = 0; i < peers.size(); i++)
	{
		if (i == whoami)
			bP_in.push_back(broadcast_self_pipefd[0]);
		else
			bP_in.push_back(broadcast_pipefd[i][whoami][0]);
		bP_out.push_back(broadcast_pipefd[whoami][i][1]);
		bP_key.push_back(map_passwords[peers[i]]);
		ping[i] = 0; // initialize array for PING timestamps
	}
	// create asynchronous authenticated channels for broadcast (chunked mode)
	aiounicast_select *aiou = new aiounicast_select(peers.size(), whoami,
		bP_in, bP_out, bP_key, aiounicast::aio_scheduler_roundrobin,
		(opt_W * 60), true, true, true);
	// create an instance of a reliable broadcast protocol (RBC)
	std::string myID = "dotsd|" + std::string(protocol) + "|";
	for (size_t i = 0; i < peers.size(); i++)
		myID += peers[i] + "|";
	if (opt_verbose)
		std::cerr << "INFO: RBC myID = " << myID << std::endl;
	// assume maximum asynchronous t-resilience and create RBC channel
	size_t T_RBC = (peers.size() - 1) / 3;
	CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(
			peers.size(), T_RBC, whoami,
			aiou, aiounicast::aio_scheduler_roundrobin, (opt_W * 60));
	rbc->setID(myID, false); // disable FIFO-order in main protocol

	// initialize main protocol
	time_t last_event = time(NULL);
	size_t leader = 0, LEADER = 0, decisions = 0;
	bool trigger_timeout = false, trigger_decide = false;
	std::string sn = "", SN = "";
	std::vector<mpz_ptr> ping_val;
	for (size_t i = 0; i < peers.size(); i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init_set_ui(tmp, decisions); // undefined
		ping_val.push_back(tmp);
	}
	unsigned char ctrl_buf[peers.size() * 1024]; // buffer for control messages
	size_t ctrl_len = 0;
	time_t timeout = DOTS_TIME_SETUP; // timeout for initial setup
	time_t setup_time = time(NULL);
	while (!signal_caught && (time(NULL) < (setup_time + timeout)))
	{
		if (ctrl(ctrl_buf, sizeof(ctrl_buf), ctrl_len, aiou, signal_caught))
			continue;
	}
	// initialize algorithm "Randomized Binary Consensus" (5.12, 5.13) [CGR06]
	// extended by algorithm "Randomize Consensus with Large Domain" (5.14)
	size_t consensus_round = 0, consensus_phase = 0;
	mpz_t consensus_proposal, consensus_decision;
	mpz_init_set_ui(consensus_proposal, 0UL); // undefined
	mpz_init_set_ui(consensus_decision, 0UL); // undefined
	std::vector<mpz_ptr> consensus_val;
	for (size_t i = 0; i < peers.size(); i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init_set_ui(tmp, 0UL); // undefined
		consensus_val.push_back(tmp);
	}
	std::vector<mpz_ptr> consensus_values;
	// main loop: for each iteration an isolated consensus is done
	do
	{
		// sending protocol messages
		mpz_t msg;
		mpz_init_set_ui(msg, decisions);
		rbc->Broadcast(msg); // send a PING message
		if (consensus_phase == 0)
		{
			if (opt_verbose > 1)
			{
				std::cerr << "INFO: Randomized Large Domain Consensus:" <<
					" Propose" << std::endl;
			}
			consensus_round = 1, consensus_phase = 1;
			for (size_t i = 0; i < consensus_val.size(); i++)
				mpz_set_ui(consensus_val[i], 0UL); // set all to undefined
			mpz_set_ui(consensus_proposal, 0UL); // undefined
			mpz_set_ui(consensus_decision, 0UL); // undefined
			for (size_t i = 0; i < consensus_values.size(); i++)
			{
				mpz_clear(consensus_values[i]);
				delete [] consensus_values[i];
			}
			consensus_values.clear();
			mpz_set_ui(msg, 0UL); // undefined
			if (sn.length() > 0)
			{
				if (mpz_set_str(msg, sn.c_str(), 16) == 0)
				{
					mpz_mul_ui(msg, msg, 256UL); // encode leader into message
					mpz_add_ui(msg, msg, leader);
				}
				else
					mpz_set_ui(msg, 0UL); // undefined
			}
			else
				mpz_set_ui(msg, 1UL); // empty S/N
			std::stringstream rstr; // switch RBC to consensus subprotocol
			rstr << myID << " and consensus_round = " << consensus_round <<
				" and previous decisions = " << decisions << " PROPOSE";
			rbc->recoverID(rstr.str());
			rbc->Broadcast(msg); // send CONSENSUS_PROPOSE message
			rbc->unsetID(false); // return to main protocol; FIFO-order disabled
		}
		time_t entry = time(NULL);
		do
		{
			// inner loop: handle control messages from parent
			if (ctrl(ctrl_buf, sizeof(ctrl_buf), ctrl_len, aiou, signal_caught))
				continue;
			// inner loop: waiting for messages on RBC channel
			size_t p = 0, s = aiounicast::aio_scheduler_roundrobin;
			if (rbc->Deliver(msg, p, s, DOTS_TIME_POLL))
			{
				if (opt_verbose > 1)
				{
					std::cerr << "INFO: P_" << whoami << " received PING" <<
						" from P_" << p << ", m = " << msg << std::endl;
				}
				mpz_set(ping_val[p], msg);
				ping[p] = time(NULL);
			}
			std::stringstream rp; // switch RBC to consensus subprotocol
			rp << myID << " and consensus_round = " << consensus_round <<
				" and previous decisions = " << decisions << " PROPOSE";
			rbc->recoverID(rp.str());
			if (rbc->Deliver(msg, p, s, DOTS_TIME_POLL))
			{
				if (opt_verbose > 1)
				{
					std::cerr << "INFO: P_" << whoami << " received" <<
						" CONSENSUS_PROPOSE with value " << msg <<
						" from P_" << p << std::endl;
				}
				if (consensus_phase == 1)
				{
					mpz_set(consensus_val[p], msg);
					// Prepare array for Large Domain (algorithm 5.14 [CGR06])
					if (mpz_cmp_ui(consensus_val[p], 0UL))
					{
						bool add = true;
						for (size_t i = 0; i < consensus_values.size(); i++)
						{
							if (!mpz_cmp(consensus_val[p], consensus_values[i]))
							{
								add = false;
								break;
							}
						}
						if (add)
						{
							mpz_ptr tmp = new mpz_t();
							mpz_init_set(tmp, consensus_val[p]);
							consensus_values.push_back(tmp);
						}
					}
				}
				else
					rbc->QueueFrom(msg, p);
			}
			rbc->unsetID(false); // return to main protocol; FIFO-order disabled
			std::stringstream rd; // switch RBC to consensus subprotocol
			rd << myID << " and consensus_round = " << consensus_round <<
				" and previous decisions = " << decisions << " DECIDE";
			rbc->recoverID(rd.str());
			if (rbc->Deliver(msg, p, s, DOTS_TIME_POLL))
			{
				if (opt_verbose > 1)
				{
					std::cerr << "INFO: P_" << whoami << " received" <<
						" CONSENSUS_DECIDE with value " << msg <<
						" from P_" << p << std::endl;
				}
				if (consensus_phase == 2)
					mpz_set(consensus_val[p], msg);
				else
					rbc->QueueFrom(msg, p);
			}
			rbc->unsetID(false); // return to main protocol; FIFO-order disabled
			std::stringstream rdd; // switch RBC to consensus subprotocol
			rdd << myID << " and consensus_round = " << consensus_round <<
				" and previous decisions = " << decisions << " DECIDED";
			rbc->recoverID(rdd.str());
			if (rbc->Deliver(msg, p, s, DOTS_TIME_POLL))
			{
				if (opt_verbose > 1)
				{
					std::cerr << "INFO: P_" << whoami << " received" <<
						" DECIDED with value " << msg <<
						" from P_" << p << std::endl;
				}
				mpz_set(consensus_decision, msg);
				trigger_decide = true; // trigger Decide event
			}
			rbc->unsetID(false); // return to main protocol; FIFO-order disabled
			if (time(NULL) > (last_event + DOTS_TIME_EVENT))
				trigger_timeout = true; // trigger Timeout event
			// Randomized Binary Consensus: prepare
			size_t consensus_val_defined = 0;
			std::map<size_t, size_t> consensus_val_numbers;
			for (size_t i = 0; i < peers.size(); i++)
			{
				if (mpz_cmp_ui(consensus_val[i], 0UL) > 0)
				{
					consensus_val_defined++;
					bool add = true;
					for (std::map<size_t, size_t>::const_iterator
						j = consensus_val_numbers.begin();
						j != consensus_val_numbers.end(); ++j)
					{
						if (!mpz_cmp(consensus_val[i], consensus_val[j->first]))
						{
							consensus_val_numbers[j->first]++;
							add = false;
							break;
						}
					}
					if (add)
						consensus_val_numbers[i] = 1;
				}
			}
			// Randomized Binary Consensus: phase 1 (algorithm 5.12 [CGR06])
			if ((consensus_val_defined > (peers.size() / 2)) &&
				(consensus_phase == 1) && !mpz_cmp_ui(consensus_decision, 0UL))
			{
				if (opt_verbose > 1)
				{
					std::cerr << "INFO: Randomized Large Domain Consensus:" <<
						" #(val) > N/2 && phase == 1" << std::endl;
				}
				mpz_set_ui(consensus_proposal, 0UL); // undefined
				for (std::map<size_t, size_t>::const_iterator
					i = consensus_val_numbers.begin();
					i != consensus_val_numbers.end(); ++i)
				{
					if (i->second > (peers.size() / 2))
					{
						mpz_set(consensus_proposal, consensus_val[i->first]);
						break;
					}
				}
				consensus_val_defined = 0, consensus_val_numbers.clear();
				for (size_t i = 0; i < consensus_val.size(); i++)
					mpz_set_ui(consensus_val[i], 0UL); // set to undefined
				consensus_phase = 2;
				mpz_set(msg, consensus_proposal);
				std::stringstream r; // switch RBC to consensus subprotocol
				r << myID << " and consensus_round = " << consensus_round <<
					" and previous decisions = " << decisions << " DECIDE";
				rbc->recoverID(r.str());
				rbc->Broadcast(msg); // send CONSENSUS_DECIDE message
				rbc->unsetID(false); // return to main protocol; no FIFO-order
			}
			// Randomized Consensus: phase 2 (algorithm 5.13 [CGR06])
			if ((consensus_val_defined >= (peers.size() - T_RBC)) &&
				(consensus_phase == 2) && !mpz_cmp_ui(consensus_decision, 0UL))
			{
				if (opt_verbose > 1)
				{
					std::cerr << "INFO: Randomized Large Domain Consensus:" <<
						" #(val) >= N - f && phase == 2" << std::endl;
				}
				consensus_phase = 3; // DEVIATION: "imaginary phase" [CGR06] 
				// As "common coin" we use the so-called "Independent Choice",
				// however, in bad cases this results in an exponential number
				// of consensus rounds for termination.
				for (std::map<size_t, size_t>::const_iterator
					i = consensus_val_numbers.begin();
					i != consensus_val_numbers.end(); ++i)
				{
					if (i->second > T_RBC)
					{
						mpz_set(consensus_decision, consensus_val[i->first]);
						break;
					}
				}
				if (mpz_cmp_ui(consensus_decision, 0UL))
				{
					mpz_set(msg, consensus_decision);
					std::stringstream r; // switch RBC to consensus subprotocol
					r << myID << " and consensus_round = " << consensus_round <<
						" and previous decisions = " << decisions << " DECIDED";
					rbc->recoverID(r.str());
					rbc->Broadcast(msg); // send DECIDED message
					rbc->unsetID(false); // return to main protocol; no FIFO
				}
				else
				{
					// Use array for Large Domain (algorithm 5.14 [CGR06])
					size_t c = 0, sc = 0, m = consensus_values.size();
					mpz_set_ui(consensus_proposal, 0UL); // undefined
					if (m > 1)
						c = tmcg_mpz_srandom_mod(m); // toss the "common coin"
					for (size_t i = 0; i < m; i++, sc++)
					{
						mpz_set(consensus_proposal, consensus_values[i]);
						if (c == sc)
							break;
					}
					consensus_val_defined = 0, consensus_val_numbers.clear();
					for (size_t i = 0; i < consensus_val.size(); i++)
						mpz_set_ui(consensus_val[i], 0UL); // set to undefined
					consensus_round = consensus_round + 1;
					consensus_phase = 1;
					mpz_set(msg, consensus_proposal);
					std::stringstream r; // switch RBC to consensus subprotocol
					r << myID << " and consensus_round = " << consensus_round <<
						" and previous decisions = " << decisions << " PROPOSE";
					rbc->recoverID(r.str());
					rbc->Broadcast(msg); // send CONSENSUS_PROPOSE message
					rbc->unsetID(false); // return to main protocol; no FIFO
				}
			}
		}
		while ((time(NULL) < (entry + DOTS_TIME_LOOP)) && !signal_caught);
		mpz_clear(msg);
		// 1. print statistics about main protocol and consensus subprotocol
		if (opt_verbose > 1)
		{
			std::cerr << "INFO: decisions = " << decisions << 
				" consensus_round = " << consensus_round <<
				" consensus_phase = " << consensus_phase << std::endl;
			std::cerr << "INFO: consensus_proposal = ";
			if (mpz_cmp_ui(consensus_proposal, 0UL))
				std::cerr << consensus_proposal << std::endl;
			else
				std::cerr << "undefined" << std::endl;
			std::cerr << "INFO: consensus_decision = ";
			if (mpz_cmp_ui(consensus_decision, 0UL))
				std::cerr << consensus_decision << std::endl;
			else
				std::cerr << "undefined" << std::endl;
		}
		for (size_t i = 0; i < peers.size(); i++)
		{
			if (opt_verbose > 2)
			{
				std::cerr << "INFO: consensus_val[" << i << "] = ";
				if (mpz_cmp_ui(consensus_val[i], 0UL))
					std::cerr << consensus_val[i] << std::endl;
				else
					std::cerr << "undefined" << std::endl;
				std::cerr << "INFO: ping_val[" << i << "] = " <<
					ping_val[i] << std::endl;
			}
			std::vector<std::string>::iterator it;
			it = std::find(active_peers.begin(), active_peers.end(), peers[i]);
			if (it == active_peers.end())
				continue;
			if (opt_verbose > 1)
				std::cerr << "INFO: P_" << i << " is active " << std::endl;
		}
		// 2. check return of executed program and terminate stalled instances
		if (dkgpg_forked)
		{
			int wstatus = 0;
			if (waitpid(dkgpg_pid, &wstatus, WNOHANG) == dkgpg_pid)
			{
				if (!WIFEXITED(wstatus))
				{
					std::cerr << "WARNING: executed program";
					if (WIFSIGNALED(wstatus))
					{
						std::cerr << " terminated by signal " <<
							WTERMSIG(wstatus) << std::endl;
					}
					if (WCOREDUMP(wstatus))
						std::cerr << " dumped core" << std::endl;
				}
				else
				{
					if (opt_verbose)
					{
						std::cerr << "INFO: executed program (pid = " <<
							dkgpg_pid << ") terminated with exit status " <<
							WEXITSTATUS(wstatus) << std::endl;
					}
				}
				std::stringstream eft, oft, efn, ofn;
				if ((WIFEXITED(wstatus) && (WEXITSTATUS(wstatus) != 0)) ||
					!WIFEXITED(wstatus))
				{
					eft << "dotsd_" << hostname << "_" << SN << "_error";
					efn << "dotsd_" << hostname << "_" << SN << "_error.txt";
				}
				else
				{
					eft << "dotsd_" << hostname << "_" << SN << "_success";
					efn << "dotsd_" << hostname << "_" << SN << "_success.txt";
					oft << "dotsd_" << hostname << "_" << SN << "_stamp";
					ofn << "dotsd_" << hostname << "_" << SN << "_stamp.asc";
					if (rename((oft.str()).c_str(), (ofn.str()).c_str()) < 0)
						perror("WARNING: run_instance (rename)");
				}
				std::ofstream efs((eft.str()).c_str(), 
					std::ofstream::out | std::ofstream::trunc);
				if (!efs.is_open() || !efs.good())
				{
					std::cerr << "WARNING: cannot open error file" << std::endl;
				}
				else if (WIFSIGNALED(wstatus))
				{
					efs << "terminated by signal " << WTERMSIG(wstatus) <<
						std::endl;
					efs.close();
					if (rename((eft.str()).c_str(), (efn.str()).c_str()) < 0)
						perror("WARNING: run_instance (rename)");
				}
				else
				{
					if (WIFEXITED(wstatus))
					{
						efs << "exit code " << WEXITSTATUS(wstatus) <<
							std::endl;
					}
					else
						efs << "unknown termination" << std::endl;
					efs << "STDOUT of \"" << dkgpg_cmd << "\":" << std::endl;
					ssize_t num = 0;
					do
					{
						char buffer[1025];
						memset(buffer, 0, sizeof(buffer));
						num = read(dkgpg_fd_out, buffer, 1024);
						if (num > 0)
							efs << buffer; // write to file
					}
					while (num > 0);
					efs << "STDERR of \"" << dkgpg_cmd << "\":" << std::endl;
					num = 0;
					do
					{
						char buffer[1025];
						memset(buffer, 0, sizeof(buffer));
						num = read(dkgpg_fd_err, buffer, 1024);
						if (num > 0)
							efs << buffer; // write to file
					}
					while (num > 0);
					efs << "----------------------------------" << std::endl;
					if (!efs.good())
					{
						std::cerr << "WARNING: writing to file \"" <<
							eft.str() << "\" failed" << std::endl;
					}
					efs.close();
					if (rename((eft.str()).c_str(), (efn.str()).c_str()) < 0)
						perror("WARNING: run_instance (rename)");
				}
				if ((close(dkgpg_fd_in) < 0) ||
					(close(dkgpg_fd_out) < 0) ||
					(close(dkgpg_fd_err) < 0))
				{
					perror("WARNING: run_instance (close)");
				}
				dkgpg_forked = false;
				dkgpg_pid = 0;
				SN = "";
				LEADER = 0;
			}
			// send SIGTERM to executed DKGPG process
			if (dkgpg_forked && (time(NULL) > (dkgpg_time + DOTS_TIME_TERM)))
				dots_kill_process(dkgpg_pid, SIGTERM, opt_verbose);
			// send SIGKILL to executed DKGPG process
			if (dkgpg_forked && (time(NULL) > (dkgpg_time + DOTS_TIME_KILL)))
				dots_kill_process(dkgpg_pid, SIGKILL, opt_verbose);
			else if (dkgpg_forked && signal_caught)
				dots_kill_process(dkgpg_pid, SIGKILL, opt_verbose); 
		}
		// 3. start external timestamping process
		if (!dkgpg_forked && !signal_caught && (SN.length() > 0))
		{
			std::string pwlist;
			for (size_t i = 0; i < active_peers.size(); i++)
				pwlist += map_passwords[active_peers[i]] + "/";
			dots_start_process(dkgpg_cmd, active_peers, hostname,
				pwlist, URI, opt_W, dkgpg_env, dkgpg_pid,
				dkgpg_forked, dkgpg_time, dkgpg_fd_in,
				dkgpg_fd_out, dkgpg_fd_err, peers[LEADER],
				DOTS_MHD_PORT + LEADER, SN, opt_verbose);
		}
		// 3. handle events and request work load
		if (!dkgpg_forked && !signal_caught && (SN.length() == 0))
		{
			// Timeout event
			if (trigger_timeout)
			{
				last_event = time(NULL);
				trigger_timeout = false;
				if (opt_verbose > 1)
				{
					std::cerr << "INFO: Timeout event at" <<
						" decisions = " << decisions << " and" << 
						" consensus_decision = " << consensus_decision <<
						std::endl;
				}
				consensus_phase = 0;
				sn = "";
			}
			// Decide event
			if (trigger_decide)
			{
				last_event = time(NULL);
				trigger_decide = false;
				if (opt_verbose > 1)
				{
					std::cerr << "INFO: Decide event at" <<
						" decisions = " << decisions << " and" << 
						" consensus_decision = " << consensus_decision <<
						std::endl;
				}
				if (mpz_cmp_ui(consensus_decision, 256UL) >= 0)
				{
					char buf[1024];
					memset(buf, 0, sizeof(buf));
					LEADER = mpz_get_ui(consensus_decision) % 256;
					mpz_sub_ui(consensus_decision, consensus_decision, LEADER);
					mpz_fdiv_q_ui(consensus_decision, consensus_decision, 256UL);
					mpz_get_str(buf, 16, consensus_decision);
					for (size_t i = 0; i < sizeof(buf); i++)
					{
						if (buf[i] == 'a')
							buf[i] = 'A';
						else if (buf[i] == 'b')
							buf[i] = 'B';
						else if (buf[i] == 'c')
							buf[i] = 'C';
						else if (buf[i] == 'd')
							buf[i] = 'D';
						else if (buf[i] == 'e')
							buf[i] = 'E';
						else if (buf[i] == 'f')
							buf[i] = 'F';
					}
					SN = buf;
				}
				decisions++;
				consensus_phase = 0;
				sn = "";
			}
			else
			{
				size_t max = 0;
				for (size_t i = 0; i < peers.size(); i++)
				{
					if (std::find(active_peers.begin(), active_peers.end(),
						peers[i]) == active_peers.end())
					{
						continue;
					}
					size_t val = mpz_get_ui(ping_val[i]);
					if (val > max)
						max = val;
				}
				if (max > (decisions+1))
				{
// TODO: recover with adjusted counter decisions
				}
			}
			// request work load from a new random leader who is active
			size_t sc = 0;
			while ((sn.length() == 0) && (++sc < 256))
			{
				leader = tmcg_mpz_wrandom_ui() % peers.size();
				if (std::find(active_peers.begin(), active_peers.end(),
					peers[leader]) == active_peers.end())
				{
					continue;
				}
				std::string type;
				if (dots_http_request(peers[leader], DOTS_MHD_PORT + leader,
					"/start", sn, type, opt_verbose))
				{
					if (opt_verbose > 2)
					{
						std::cerr << "INFO: HTTP response of type = " << type <<
							" from leader " << leader << " contains" <<
							" sn = " << sn << std::endl;
					}
				}
				else
					sc += 64;
				if (sn == SN)
					sn = ""; // don't reassign already processed S/N
			}
		}
		// 4. maintain active_peers array
		time_t current_time = time(NULL);
		for (size_t i = 0; i < peers.size(); i++)
		{
			std::vector<std::string>::iterator it;
			it = std::find(active_peers.begin(), active_peers.end(), peers[i]);
			if (ping[i] < (current_time - DOTS_TIME_INACTIVE))
			{
				// peer timed out
				if (it != active_peers.end())
					active_peers.erase(it); // remove inactive peer
			}
			else
			{
				// peer is on-time
				if (it != active_peers.end())
					continue; // ignore, peer is already active
				active_peers.push_back(peers[i]); // add reactivated peer
				// canonicalize active_peers
				std::sort(active_peers.begin(), active_peers.end());
				it = std::unique(active_peers.begin(), active_peers.end());
				active_peers.resize(std::distance(active_peers.begin(), it));
			}
			// TODO: group-consensus on active_peers array required
		}
		// 5. print statistics about main protocol
		if (opt_verbose > 1)
		{
			std::cerr << "INFO: |active_peers| = " << active_peers.size() <<
				" leader = " << leader << " sn = " << sn <<
				" LEADER = " << LEADER << " SN = " << SN << std::endl;
		}
	}
	while (!signal_caught);
	// kill executed program
	if (dkgpg_forked)
	{
		dots_kill_process(dkgpg_pid, SIGKILL, opt_verbose);
		sleep(DOTS_TIME_POLL);
		if (waitpid(dkgpg_pid, NULL, WNOHANG) != dkgpg_pid)
			perror("WARNING: run_instance (waitpid)");
	}
	// release allocated ressources of main protocol
	for (size_t i = 0; i < ping_val.size(); i++)
	{
		mpz_clear(ping_val[i]);
		delete [] ping_val[i];
	}
	for (size_t i = 0; i < consensus_val.size(); i++)
	{
		mpz_clear(consensus_val[i]);
		delete [] consensus_val[i];
	}
	mpz_clear(consensus_proposal);
	mpz_clear(consensus_decision);
	for (size_t i = 0; i < consensus_values.size(); i++)
	{
		mpz_clear(consensus_values[i]);
		delete [] consensus_values[i];
	}
	// release RBC channel and P2P channels
	delete rbc;
	if (opt_verbose)
	{
		std::cerr << "INFO: P_" << whoami << ": P2P channels";
		aiou->PrintStatistics(std::cerr);
		std::cerr << std::endl;
	}
	delete aiou;
}

bool fork_instance
	(const size_t whoami)
{
	if ((pid[whoami] = fork()) < 0)
	{
		perror("ERROR: fork_instance (fork)");
		return false;
	}
	else
	{
		if (pid[whoami] == 0)
		{
			/* BEGIN child code: participant P_i */
			run_instance(whoami);
			if (opt_verbose)
				std::cerr << "INFO: P_" << whoami << ": exit(0)" << std::endl;
			exit(0);
			/* END child code: participant P_i */
		}
		else
		{
			if (opt_verbose)
				std::cerr << "INFO: fork() = " << pid[whoami] << std::endl;
			instance_forked = true;
		}
	}
	return true;
}

int main
	(int argc, char *const *argv, char **envp)
{
	static const char *usage =
		"dotsd [OPTIONS] -P <PASSWORDS> -H <hostname> <PEERS>";
	dkgpg_env = envp;

	// create peer list from remaining arguments
	for (size_t i = 0; i < (size_t)(argc - 1); i++)
	{
		std::string arg = argv[i+1];
		// ignore options
		if ((arg.find("-p") == 0) || (arg.find("-W") == 0) || 
			(arg.find("-P") == 0) || (arg.find("-H") == 0) ||
		    (arg.find("-U") == 0) || (arg.find("-Y") == 0))
		{
			size_t idx = ++i;
			if ((arg.find("-H") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_hostname == NULL))
			{
				hostname = argv[i+1];
				opt_hostname = (char*)hostname.c_str();
			}
			if ((arg.find("-P") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_passwords == NULL))
			{
				passwords = argv[i+1];
				opt_passwords = (char*)passwords.c_str();
			}
			if ((arg.find("-U") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_URI == NULL))
			{
				URI = argv[i+1];
				opt_URI = (char*)URI.c_str();
			}
			if ((arg.find("-p") == 0) && (idx < (size_t)(argc - 1)) &&
				(port.length() == 0))
			{
				port = argv[i+1];
			}
			if ((arg.find("-W") == 0) && (idx < (size_t)(argc - 1)) &&
				(opt_W == 5))
			{
				opt_W = strtoul(argv[i+1], NULL, 10);
			}
			if ((arg.find("-Y") == 0) && (idx < (size_t)(argc - 1)) &&
				(policyfilename.length() == 0))
			{
				policyfilename = argv[i+1];
			}
			continue;
		}
		else if ((arg.find("--") == 0) || (arg.find("-v") == 0) ||
			(arg.find("-h") == 0) || (arg.find("-V") == 0))
		{
			if ((arg.find("-h") == 0) || (arg.find("--help") == 0))
			{
				std::cout << usage << std::endl;
				std::cout << about << std::endl;
				std::cout << "Arguments mandatory for long options are also" <<
					" mandatory for short options." << std::endl;
				std::cout << "  -h, --help     print this help" << std::endl;
				std::cout << "  -H STRING      hostname (e.g. onion address)" <<
					" of this peer within PEERS" << std::endl;
				std::cout << "  -p INTEGER     start port for" <<
					" TCP point-to-point channels is INTEGER" << std::endl;
				std::cout << "  -P STRING      exchanged passwords to" <<
					" protect private and broadcast channels" << std::endl;
				std::cout << "  -U STRING      policy URI of TSA tied to all" <<
					" generated timestamps" << std::endl;
				std::cout << "  -v, --version  print the version number" <<
					std::endl;
				std::cout << "  -V, --verbose  turn on verbose output" <<
					std::endl;
				std::cout << "  -W TIME        timeout for point-to-point" <<
					" messages in minutes" << std::endl;
				std::cout << "  -Y FILENAME    read the service policy from" <<
					" FILENAME" << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-v") == 0) || (arg.find("--version") == 0))
			{
				std::cout << "dotsd v" << version << std::endl;
				return 0; // not continue
			}
			if ((arg.find("-V") == 0) || (arg.find("--verbose") == 0))
				opt_verbose++; // increase verbosity
			continue;
		}
		else if (arg.find("-") == 0)
		{
			std::cerr << "ERROR: unknown option \"" << arg << "\"" << std::endl;
			return -1;
		}
		// store argument for peer list
		if (arg.length() <= 255)
		{
			peers.push_back(arg);
		}
		else
		{
			std::cerr << "ERROR: peer identity \"" << arg << "\" too long" <<
				std::endl;
			return -1;
		}
	}

	// check command line arguments and options
	if (peers.size() < 1)
	{
		std::cerr << "ERROR: no peers given as argument; usage: " <<
			usage << std::endl;
		return -1;
	}
	if (hostname.length() == 0)
	{
		std::cerr << "ERROR: no option -H given; usage: " <<
			usage << std::endl;
		return -1;
	}
	if (passwords.length() == 0)
	{
		std::cerr << "ERROR: no option -P given; usage: " <<
			usage << std::endl;
		return -1;
	}
	if (port.length())
		opt_p = strtoul(port.c_str(), NULL, 10); // set TCP start port
	if ((opt_p < 1024) || (opt_p > 65535))
	{
		std::cerr << "ERROR: no valid TCP start port given" << std::endl;
		return -1;
	}
	if (policyfilename.length())
	{
		std::ifstream pfs(policyfilename.c_str(), std::ifstream::in);
		if (pfs.is_open())
		{
			std::string line;
			while (std::getline(pfs, line))
				policyfile << line << std::endl;
			if (!pfs.eof())
			{
				std::cerr << "ERROR: cannot read until EOF" <<
					"of policy file \"" <<
					policyfilename << "\"" << std::endl;
				pfs.close();
				return -1;
			}
			pfs.close();
		}
		else
		{
			std::cerr << "ERROR: cannot open policy file \"" <<
				policyfilename << "\"" << std::endl;
			return -1;
		}
	}

	// canonicalize peer list and check basic requirements
	std::sort(peers.begin(), peers.end());
	std::vector<std::string>::iterator it =
		std::unique(peers.begin(), peers.end());
	peers.resize(std::distance(peers.begin(), it));
	if ((peers.size() < 3)  || (peers.size() > DOTS_MAX_N))
	{
		std::cerr << "ERROR: too few or too many peers given" << std::endl;
		return -1;
	}
	if (opt_verbose)
	{
		std::cerr << "INFO: canonicalized peer list = ";
		for (size_t i = 0; i < peers.size(); i++)
			std::cerr << peers[i] << " ";
		std::cerr << std::endl;
	}

	// initialize LibTMCG
	if (!init_libTMCG(false))
	{
		std::cerr << "ERROR: initialization of LibTMCG failed" << std::endl;
		return -1;
	}
	if (opt_verbose)
	{
		std::cerr << "INFO: using LibTMCG version " << version_libTMCG() <<
			std::endl;
	}

	// extract and map provided passwords
	for (size_t i = 0; i < peers.size(); i++)
	{
		std::stringstream key;
		std::string pwd;
		if (!TMCG_ParseHelper::gs(passwords, '/', pwd))
		{
			std::cerr << "ERROR: cannot read password" <<
				" for protecting channel to P_" << i <<
				std::endl;
			return -1;
		}
		key << pwd;
		map_passwords[peers[i]] = pwd;
		if (((i + 1) < peers.size()) &&
			!TMCG_ParseHelper::nx(passwords, '/'))
		{
			std::cerr << "ERROR: cannot skip to next password" <<
				" for protecting channel to P_" << (i + 1) <<
				std::endl;
			return -1;
		}
	}
	
	// create underlying point-to-point channels over TCP/IP
	int ret = 0;
	tcpip_init(hostname);
	tcpip_bindports((uint16_t)opt_p, false);
	tcpip_bindports((uint16_t)opt_p, true);
// TODO: detach from terminal, redirect stdout and stderr, and daemonize itself
	if (tcpip_fork())
		ret = tcpip_io();
	else
		ret = -100; // fork to protocol instance failed
	tcpip_close();
	tcpip_done();
		
	return ret;
}

