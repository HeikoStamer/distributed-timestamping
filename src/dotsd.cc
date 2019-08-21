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

void run_instance
	(const size_t whoami)
{
	std::vector<std::string> active_peers;
	active_peers.insert(active_peers.end(), peers.begin(), peers.end());
	// create communication handles between all players
	std::vector<int> uP_in, uP_out, bP_in, bP_out;
	std::vector<std::string> uP_key, bP_key;
	for (size_t i = 0; i < peers.size(); i++)
	{
		if (i == whoami)
			uP_in.push_back(self_pipefd[0]);
		else
			uP_in.push_back(pipefd[i][whoami][0]);
		uP_out.push_back(pipefd[whoami][i][1]);
		uP_key.push_back(map_passwords[peers[i]]);
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
		std::cerr << "RBC: myID = " << myID << std::endl;
	// assume maximum asynchronous t-resilience for RBC and create main channel
	size_t T_RBC = (peers.size() - 1) / 3;
	CachinKursawePetzoldShoupRBC *rbc = new CachinKursawePetzoldShoupRBC(
			peers.size(), T_RBC, whoami,
			aiou, aiounicast::aio_scheduler_roundrobin, (opt_W * 60));
	rbc->setID(myID);

	// initialize main protocol
	size_t leader = 0, decisions = 0;
	bool leader_change = false, trigger_decide = false;
	std::string sn = "";
	std::vector<mpz_ptr> exec_sn_val;
	for (size_t i = 0; i < peers.size(); i++)
	{
		mpz_ptr tmp = new mpz_t();
		mpz_init_set_ui(tmp, 0UL); // undefined
		exec_sn_val.push_back(tmp);
	}
	// initialize algorithm "Randomized Binary Consensus" (5.12, 5.13) [CGR06]
	size_t consensus_round = 0, consensus_phase = 0;
	size_t consensus_proposal = peers.size(); // undefined
	size_t consensus_decision = peers.size(); // undefined
	std::vector<size_t> consensus_val;
	for (size_t i = 0; i < peers.size(); i++)
		consensus_val.push_back(peers.size()); // set all to undefined
	// main loop: for each change of the "leader" an isolated consensus is done  
	do
	{
		// sending messages
		mpz_t msg;
		mpz_init_set_ui(msg, 1UL);
		rbc->Broadcast(msg); // send a PING message
		if (consensus_phase == 0)
		{
			if (opt_verbose > 1)
			{
				std::cerr << "INFO: Randomized Binary Consensus:" <<
					" Propose" << std::endl;
			}
			consensus_round = 1, consensus_phase = 1;
			for (size_t i = 0; i < consensus_val.size(); i++)
				consensus_val[i] = peers.size(); // set all to undefined
			consensus_proposal = peers.size(); // undefined
			consensus_decision = peers.size(); // undefined
			if (leader_change)
				mpz_set_ui(msg, 1UL);
			else
				mpz_set_ui(msg, 0UL);
			std::stringstream rstr; // switch RBC to consensus subprotocol
			rstr << myID << " and consensus_round = " << consensus_round <<
				" and previous decisions = " << decisions;
			rbc->recoverID(rstr.str());
			rbc->Broadcast(msg); // send CONSENSUS_PROPOSE message
			rbc->unsetID(); // return to main protocol
		}
		time_t entry = time(NULL);
		do
		{
			// inner loop: waiting for messages on RBC channel
			size_t p = 0, s = aiounicast::aio_scheduler_roundrobin;
			if (rbc->Deliver(msg, p, s, DOTS_TIME_POLL))
			{
				if (mpz_cmp_ui(msg, 1UL) == 0)
				{
					if (opt_verbose > 1)
					{
						std::cerr << "INFO: P_" << whoami << " received PING" <<
							" from P_" << p << std::endl;
					}
					ping[p] = time(NULL);
				}
				else if (mpz_cmp_ui(msg, 1UL) > 0)
				{
					if (opt_verbose > 1)
					{
						std::cerr << "INFO: P_" << whoami << " received EXEC" <<
							"_SN from P_" << p << ", m = " << msg << std::endl;
					}
					mpz_set(exec_sn_val[p], msg);
				}
				else
				{
					std::cerr << "WARNING: received unknown message m = " <<
						mpz_get_ui(msg) << " from P_" << p << std::endl;
				}
			}
			std::stringstream rstr; // switch RBC to consensus subprotocol
			rstr << myID << " and consensus_round = " << consensus_round <<
				" and previous decisions = " << decisions;
			rbc->recoverID(rstr.str());
			if (rbc->Deliver(msg, p, s, DOTS_TIME_POLL))
			{
				if (mpz_cmp_ui(msg, peers.size()) < 0)
				{
					if (opt_verbose > 2)
					{
						std::cerr << "INFO: P_" << whoami <<
							" received CONSENSUS_PROPOSE with value " <<
							mpz_get_ui(msg) << " from P_" << p << std::endl;
					}
					if (consensus_phase == 1)
						consensus_val[p] = mpz_get_ui(msg);
					else
						rbc->QueueFrom(msg, p);
				}
				else if ((mpz_cmp_ui(msg, peers.size()) >= 0) &&
					(mpz_cmp_ui(msg, 2 * peers.size()) < 0))
				{
					if (opt_verbose > 2)
					{
						std::cerr << "INFO: P_" << whoami <<
							" received CONSENSUS_DECIDE with value " <<
							(mpz_get_ui(msg) - peers.size()) <<
							" from P_" << p << std::endl;
					}
					if (consensus_phase == 2)
						consensus_val[p] = mpz_get_ui(msg) - peers.size();
					else
						rbc->QueueFrom(msg, p);
				}
				else if ((mpz_cmp_ui(msg, 2 * peers.size()) >= 0) &&
					(mpz_cmp_ui(msg, 3 * peers.size()) < 0))
				{
					if (opt_verbose > 1)
					{
						std::cerr << "INFO: P_" << whoami <<
							" received DECIDED with value " <<
							(mpz_get_ui(msg) - (2 * peers.size())) <<
							" from P_" << p << std::endl;
					}
					consensus_decision = (mpz_get_ui(msg) - (2 * peers.size()));
					trigger_decide = true; // trigger Decide event
				}
				else
				{
					std::cerr << "WARNING: received unknown message m = " <<
						mpz_get_ui(msg) << " from P_" << p << std::endl;
				}
			}
			// Randomized Binary Consensus: prepare
			size_t consensus_val_defined = 0;
			std::map<size_t, size_t> consensus_val_numbers;
			for (size_t i = 0; i < peers.size(); i++)
			{
				if (consensus_val[i] < peers.size())
				{
					consensus_val_defined++;
					if (consensus_val_numbers.count(consensus_val[i]) == 0)
						consensus_val_numbers[consensus_val[i]] = 1;
					else
						consensus_val_numbers[consensus_val[i]]++;
				}
			}
			// Randomized Binary Consensus: phase 1 (algorithm 5.12 [CGR06])
			if ((consensus_val_defined > (peers.size() / 2)) &&
				(consensus_phase == 1) && (consensus_decision == peers.size()))
			{
				if (opt_verbose > 1)
				{
					std::cerr << "INFO: Randomized Binary Consensus: #(val)" <<
						" > N/2 && phase == 1" << std::endl;
				}
				for (std::map<size_t, size_t>::const_iterator
					it = consensus_val_numbers.begin();
					it != consensus_val_numbers.end(); ++it)
				{
					if (it->second > (peers.size() / 2))
						consensus_proposal = it->first;
					else
						consensus_proposal = peers.size(); // undefined
				}
				for (size_t i = 0; i < consensus_val.size(); i++)
					consensus_val[i] = peers.size(); // set all to undefined				
				consensus_phase = 2;
				mpz_set_ui(msg, consensus_proposal + peers.size());
				rbc->Broadcast(msg); // send CONSENSUS_DECIDE message
			}
			// Randomized Consensus: phase 2 (algorithm 5.13 [CGR06])
			if ((consensus_val_defined >= (peers.size() - T_RBC)) &&
				(consensus_phase == 2) && (consensus_decision == peers.size()))
			{
				if (opt_verbose > 1)
				{
					std::cerr << "INFO: Randomized Binary Consensus: #(val)" <<
						" >= N - f && phase == 2" << std::endl;
				}
				consensus_phase = 3; // DEVIATION: "imaginary phase" [CGR06] 
				// As "common coin" we use the so-called "Independent Choice",
				// however, in bad cases this results in an exponential number
				// of consensus rounds for termination.
				unsigned char c;
				gcry_randomize(&c, 1, GCRY_STRONG_RANDOM);
				for (std::map<size_t, size_t>::const_iterator
					it = consensus_val_numbers.begin();
					it != consensus_val_numbers.end(); ++it)
				{
					if (it->second > T_RBC)
						consensus_decision = it->first;
				}
				if (consensus_decision < peers.size())
				{
					mpz_set_ui(msg, consensus_decision + (2 * peers.size()));
					rbc->Broadcast(msg); // send DECIDED message
				}
				else
				{
					consensus_proposal = c % 2; // use "common coin" uniformly
					for (std::map<size_t, size_t>::iterator
						it = consensus_val_numbers.begin();
						it != consensus_val_numbers.end(); ++it)
					{
						consensus_proposal = it->second;
					}
					for (size_t i = 0; i < consensus_val.size(); i++)
						consensus_val[i] = peers.size(); // set all to undefined
					consensus_round = consensus_round + 1;
					consensus_phase = 1;
					mpz_set_ui(msg, consensus_proposal);
					rbc->Broadcast(msg); // send CONSENSUS_PROPOSE message
				}
			}
			rbc->unsetID(); // return to main protocol
		}
		while ((time(NULL) < (entry + DOTS_TIME_LOOP)) && !signal_caught);
		mpz_clear(msg);
		// 1. print statistics about consensus subprotocol
		if (opt_verbose > 1)
		{
			std::cerr << "INFO: decisions = " << decisions << 
				" consensus_round = " << consensus_round <<
				" consensus_phase = " << consensus_phase << std::endl;
			std::cerr << "INFO: consensus_proposal = ";
			if (consensus_proposal < peers.size())
				std::cerr << consensus_proposal << std::endl;
			else
				std::cerr << "undefined" << std::endl;
			std::cerr << "INFO: consensus_decision = ";
			if (consensus_decision < peers.size())
				std::cerr << consensus_decision << std::endl;
			else
				std::cerr << "undefined" << std::endl;
		}
		for (size_t i = 0; i < peers.size(); i++)
		{
			if (opt_verbose > 1)
			{
				std::cerr << "INFO: consensus_val[" << i << "] = ";
				if (consensus_val[i] < peers.size())
					std::cerr << consensus_val[i] << std::endl;
				else
					std::cerr << "undefined" << std::endl;
			}
			std::vector<std::string>::iterator it;
			it = std::find(active_peers.begin(), active_peers.end(),
				peers[i]);
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
					eft << "dotsd_" << hostname << "_" << sn << "_error";
					efn << "dotsd_" << hostname << "_" << sn << "_error.txt";
				}
				else
				{
					eft << "dotsd_" << hostname << "_" << sn << "_success";
					efn << "dotsd_" << hostname << "_" << sn << "_success.txt";
					oft << "dotsd_" << hostname << "_" << sn << "_stamp";
					ofn << "dotsd_" << hostname << "_" << sn << "_stamp.asc";
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
				sn = "";
				// invalidate S/N agreement array
				for (size_t i = 0; i < exec_sn_val.size(); i++)
					mpz_set_ui(exec_sn_val[i], 0UL); // undefined
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
		if (!dkgpg_forked && !signal_caught && (sn.length() > 0))
		{
			bool agree = true;
			for (size_t i = 1; i < exec_sn_val.size(); i++)
			{
				if (std::find(active_peers.begin(), active_peers.end(),
					peers[i]) == active_peers.end())
				{
					continue; // ignore, this peer is inactive
				}
				for (size_t j = 0; j < i; j++)
				{
					if (std::find(active_peers.begin(),
						active_peers.end(), peers[j]) ==
						active_peers.end())
					{
						continue; // ignore, this peer is inactive
					}
					if (mpz_cmp(exec_sn_val[i], exec_sn_val[j]) != 0)
						agree = false; // different values detected
					if (mpz_cmp_ui(exec_sn_val[i], 0UL) == 0)
						agree = false; // undefined value detected
					if (mpz_cmp_ui(exec_sn_val[j], 0UL) == 0)
						agree = false; // undefined value detected
					mpz_t sn_hash, leader_hash;
					mpz_init(sn_hash);
					if (mpz_set_str(sn_hash, sn.c_str(), 16) == -1)
						std::cerr << "WARNING: mpz_set_str() failed" << std::endl;
					mpz_init_set_ui(leader_hash, leader);
					mpz_init(msg);
					tmcg_mpz_shash(msg, 2, sn_hash, leader_hash);
					mpz_clear(sn_hash);
					mpz_clear(leader_hash);
					if (mpz_cmp(exec_sn_val[j], msg))
						agree = false; // wrong hash detected
					mpz_clear(msg);
				}
			}
			if (agree)
			{
				std::string pwlist;
				for (size_t i = 0; i < active_peers.size(); i++)
					pwlist += map_passwords[active_peers[i]] + "/";
				dots_start_process(dkgpg_cmd, active_peers, hostname,
					pwlist, URI, opt_W, dkgpg_env, dkgpg_pid,
					dkgpg_forked, dkgpg_time, dkgpg_fd_in,
					dkgpg_fd_out, dkgpg_fd_err, peers[leader],
					DOTS_MHD_PORT + leader, sn, opt_verbose);
			}
		}
		// 3. handle events and request work load
		if (!dkgpg_forked && !signal_caught)
		{
			// Decide event: choose a (new) leader
			if (trigger_decide && (consensus_decision < peers.size()))
			{
				trigger_decide = false;
				if ((leader_change && (consensus_decision == 0)) ||
					(!leader_change && (consensus_decision == 1)))
				{
					std::cerr << "WARNING: diverging state detected" <<
						" with leader_change = " << leader_change <<
						std::endl;
				}
				decisions++;
				leader += consensus_decision;
				if (leader == peers.size())
					leader = 0;
				if (consensus_decision > 0)
				{
					// start new round with empty S/N and a new leader
					sn = "";
					leader_change = false;
					// invalidate S/N agreement array
					for (size_t i = 0; i < exec_sn_val.size(); i++)
						mpz_set_ui(exec_sn_val[i], 0UL); // undefined
				}
				consensus_phase = 0;
			}
			// request work load from active leader
			std::string type;
			if (std::find(active_peers.begin(), active_peers.end(),
				peers[leader]) == active_peers.end())
			{
				std::cerr << "WARNING: leader \"" <<
					peers[leader] << "\" is inactive" << std::endl;
				leader_change = true; // inactive -> change leader
			}
			else if (dots_http_request(peers[leader], DOTS_MHD_PORT + leader,
				"/start", sn, type, opt_verbose))
			{
				if (opt_verbose > 2)
				{
					std::cerr << "INFO: HTTP response of type = \"" <<
						type << "\" from leader " << leader << " " << sn <<
						std::endl;
				}
				if (type != "text/plain")
					std::cerr << "WARNING: invalid content type" << std::endl;
				if (sn.length() > 0)
				{
					mpz_t sn_hash, leader_hash;
					mpz_init(sn_hash);
					if (mpz_set_str(sn_hash, sn.c_str(), 16) == -1)
						std::cerr << "WARNING: mpz_set_str() failed" << std::endl;
					mpz_init_set_ui(leader_hash, leader);
					mpz_init(msg);
					tmcg_mpz_shash(msg, 2, sn_hash, leader_hash);
					mpz_clear(sn_hash);
					mpz_clear(leader_hash);
					rbc->Broadcast(msg); // send EXEC_SN message
					mpz_clear(msg);
				}
				else
					leader_change = true; // no work load -> change leader
			}
			else
				leader_change = true; // HTTP request failed -> change leader
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
				" leader = " << leader << " sn = " << sn << std::endl;
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
	for (size_t i = 0; i < exec_sn_val.size(); i++)
	{
		mpz_clear(exec_sn_val[i]);
		delete [] exec_sn_val[i];
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
	static const char *usage = "dotsd [OPTIONS] -P <PASSWORDS> -H <hostname> <PEERS>";
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

	// extract and map passwords
	std::map<std::string, std::string> map_passwords;
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
	while (tcpip_connect((uint16_t)opt_p, false) < peers.size())
		sleep(1);
	while (tcpip_connect((uint16_t)opt_p, true) < peers.size())
		sleep(1);
	tcpip_accept();
// TODO: detach from terminal, redirect stdout and stderr, and daemonize itself
	if (tcpip_fork())
		ret = tcpip_io();
	else
		ret = -100; // fork to protocol instance failed
	tcpip_close();
	tcpip_done();
		
	return ret;
}

