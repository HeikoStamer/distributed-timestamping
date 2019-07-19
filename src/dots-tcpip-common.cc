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
#include "dots-common.hh"
#include "dots-tcpip-common.hh"

extern int						pipefd[DOTS_MAX_N][DOTS_MAX_N][2];
extern int						self_pipefd[2];
extern int						broadcast_pipefd[DOTS_MAX_N][DOTS_MAX_N][2];
extern int						broadcast_self_pipefd[2];
extern pid_t					pid[DOTS_MAX_N];
extern std::vector<std::string>	peers;
extern bool						instance_forked;
extern bool						signal_caught;
extern int						opt_verbose;
extern bool						fork_instance(const size_t whoami);
extern std::stringstream		policyfile;

static const size_t				tcpip_pipe_buffer_size = 4096;
uint16_t						tcpip_start = 0;

std::string 					tcpip_thispeer;
std::map<std::string, size_t> 	tcpip_peer2pipe;
std::map<size_t, std::string> 	tcpip_pipe2peer;
std::map<size_t, int>	 		tcpip_pipe2socket;
std::map<size_t, int>			tcpip_broadcast_pipe2socket;
std::map<size_t, int>	 		tcpip_pipe2socket_out;
std::map<size_t, int>			tcpip_broadcast_pipe2socket_out;
std::map<size_t, int>	 		tcpip_pipe2socket_in;
std::map<size_t, int>			tcpip_broadcast_pipe2socket_in;

typedef std::map<size_t, int>::const_iterator tcpip_mci_t;

std::string								tcpip_sn_seed;
std::map<std::string, dots_status_t>	tcpip_sn2status;
std::map<std::string, std::string>		tcpip_sn2signature;
std::map<std::string, std::string>		tcpip_sn2timestamp;
std::map<std::string, std::string>		tcpip_sn2log;
std::map<std::string, time_t>			tcpip_sn2time_submitted;
std::map<std::string, time_t>			tcpip_sn2time_stamped;
std::map<std::string, time_t>			tcpip_sn2time_failed;

typedef std::map<std::string, dots_status_t>::const_iterator tcpip_sn_mci_t;

typedef struct
{
	int ct;
	bool policy_accepted;
	char *sig;
	size_t len;
	struct MHD_PostProcessor *pp;
} tcpip_mhd_connection_info;
#define TCPIP_MHD_H2 "<header><h2>Distributed OpenPGP Timestamping Service (DOTS)</h2></header>"
#define TCPIP_MHD_HEADER "<!DOCTYPE html><html lang=\"en\"><head><title>" PACKAGE_STRING "</title></head><body>"
#define TCPIP_MHD_FOOTER "<p><footer>Powered by <a href=\"https://www.gnu.org/philosophy/free-sw.html\">free software</a>: <a href=\"https://savannah.nongnu.org/projects/distributed-timestamping/\">Distributed OpenPGP Timestamping</a></footer></body></html>"
static const char *tcpip_mhd_defaultpage = TCPIP_MHD_HEADER TCPIP_MHD_H2
	"This is an EXPERIMENTAL service provided free of charge and in the hope "
	"that it will be useful, but WITHOUT ANY WARRANTY; without even the implied "
	"warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.<p>"
	"If you agree to our <a href=\"/policy\">service policy</a>, then you are "
	"allowed to do the following operations: <ul>"
	"<li><a href=\"/submit\">Submit a detached signature for stamping</a></li>"
	"<li><a href=\"/confirm?sn=XYZ\">Confirm your submitted request</a></li>"
	"<li><a href=\"/queue\">Watch the queue of confirmed requests</a></li>"
	"<li><a href=\"/status\">Watch the status of any request</a></li>"
	"<li><a href=\"/timestamp?sn=XYZ\">Retrieve the timestamp signature of any "
		"recent request</a></li>"
	"<li><a href=\"/log?sn=XYZ\">Read the stamp-log of any recently failed "
		"request</a></li>"
	"</ul>" TCPIP_MHD_FOOTER;
static const char *tcpip_mhd_policypage = TCPIP_MHD_HEADER TCPIP_MHD_H2
	"The policy of this service is not defined yet."
	TCPIP_MHD_FOOTER;
static const char *tcpip_mhd_submitpage = TCPIP_MHD_HEADER TCPIP_MHD_H2
	"<form action=\"/input\" method=\"post\"><div>"
	"<label for=\"signature\">Please submit a detached ASCII-armored OpenPGP"
	" signature:</label><br>" // FIXME: keep in line with DOTS_MAX_SIG_LENGTH
	"<textarea name=\"signature\" minlength=\"80\" maxlength=\"4096\""
	" cols=\"80\" rows=\"14\" required></textarea><br>"
	"<label for=\"policycheck\"><input type=\"checkbox\" name=\"policycheck\""
	" value=\"policyaccepted\" required /> I accept the terms and conditions"
	" of the <a href=\"/policy\">service policy</a>.</label><br>"
	"<input type=\"submit\" name=\"submitbox\" value=\" Submit \" />"
	"</div></form>" TCPIP_MHD_FOOTER;
static const char *tcpip_mhd_duppage = TCPIP_MHD_HEADER TCPIP_MHD_H2
	"ERROR: signature with this S/N already submitted" TCPIP_MHD_FOOTER;
static const char *tcpip_mhd_confirmpage = TCPIP_MHD_HEADER TCPIP_MHD_H2
	"Your submitted request has been confirmed." TCPIP_MHD_FOOTER;
static const char *tcpip_mhd_notpage = "ERROR: signature/timestamp/log"
	" not found";
struct MHD_Daemon *tcpip_mhd;

// This signal handler is called when receiving SIGINT, SIGQUIT, and
// SIGTERM, respectively.
static RETSIGTYPE tcpip_sig_handler_quit
	(int sig)
{
	signal_caught = true;
	// parent process?
	if (instance_forked)
	{
		if (opt_verbose)
		{
			std::cerr << "tcpip_sig_handler_quit(): parent got signal " <<
				sig << std::endl;
		}
	}
	else
	{
		if (opt_verbose)
		{
			std::cerr << "tcpip_sig_handler_quit(): child got signal " <<
				sig << std::endl;
		}
	}
}

// This signal handler is called when receiving SIGPIPE.
static RETSIGTYPE tcpip_sig_handler_pipe
	(int sig)
{
	if (opt_verbose)
	{
		std::cerr << "tcpip_sig_handler_pipe(): got signal " << sig <<
			std::endl;
	}
}

static int tcpip_mhd_kv_print
	(void *cls, enum MHD_ValueKind kind, const char *key, const char *value)
{
	if (cls == NULL)
		cls = NULL; // dummy to avoid compiler warnings
	if ((kind == MHD_HEADER_KIND) && (cls == NULL))
		cls = NULL; // dummy to avoid compiler warnings
	std::cerr << "INFO: HTTP header " << key << " = \"" << value <<	"\"" <<
		std::endl;
	return MHD_YES;
}

static int tcpip_mhd_iterate_post
	(void *cls, enum MHD_ValueKind kind, const char *key,
	 const char *filename, const char *content_type,
	 const char *transfer_encoding, const char *data, uint64_t off,
	 size_t size)
{
	if ((kind == MHD_HEADER_KIND) && (cls == NULL))
		cls = NULL; // dummy to avoid compiler warnings
	if ((filename == NULL) && (cls == NULL))
		cls = NULL; // dummy to avoid compiler warnings
	if ((content_type == NULL) && (cls == NULL))
		cls = NULL; // dummy to avoid compiler warnings
	if ((transfer_encoding == NULL) && (cls == NULL))
		cls = NULL; // dummy to avoid compiler warnings
	if ((off == 0) && (cls == NULL))
		cls = NULL; // dummy to avoid compiler warnings
	tcpip_mhd_connection_info *con_info =
		(tcpip_mhd_connection_info*)cls;
	if (strcmp(key, "policycheck") == 0)
	{
		if ((size > 0) && (size <= 80))
		{
			if (strncmp(data, "policyaccepted", 14) == 0)
				con_info->policy_accepted = true; 
		}
		return MHD_YES;
	}
	else if (strcmp(key, "signature") == 0)
	{
		if ((size > 0) && (size <= DOTS_MAX_SIG_LENGTH))
		{
			if (con_info->sig == NULL)
				con_info->sig = (char*)malloc(DOTS_MAX_SIG_LENGTH + 1);
			if (con_info->sig == NULL)
				return MHD_NO;
			memset(con_info->sig, 0, DOTS_MAX_SIG_LENGTH + 1);
			memcpy(con_info->sig, data, size);
		}
		else
			con_info->sig = NULL;
		return MHD_YES;
	}
	return MHD_YES;
}

static void tcpip_mhd_request_completed
	(void *cls, struct MHD_Connection *con, void **con_cls,
	 enum MHD_RequestTerminationCode toe)
{
	if (cls == NULL)
		cls = NULL; // dummy to avoid compiler warnings
	if ((con == NULL) && (cls == NULL))
		cls = NULL; // dummy to avoid compiler warnings		
	if ((toe == MHD_REQUEST_TERMINATED_COMPLETED_OK) && (cls == NULL))
		cls = NULL; // dummy to avoid compiler warnings
	tcpip_mhd_connection_info *con_info =
		(tcpip_mhd_connection_info*)*con_cls;
	if (con_info == NULL)
		return;
	if (con_info->ct == 1)
	{
		MHD_destroy_post_processor(con_info->pp);
		if (con_info->sig != NULL)
			free(con_info->sig);
	}
	free(con_info);
	*con_cls = NULL;
}

static int tcpip_mhd_callback
	(void *cls, struct MHD_Connection *con, const char *url, const char *method,
	 const char *version, const char *upload_data, size_t *upload_data_size,
	 void **con_cls)
{
	if (cls == NULL)
		cls = NULL; // dummy to avoid compiler warnings
	int ret;
	if (*con_cls == NULL)
	{
		if (opt_verbose > 2)
		{
			std::cerr << "INFO: " << version << "-" << method << " request" <<
				" for URL \"" << url << "\" (initial call)" << std::endl;
		}
		if ((strcmp(url, "/policy") != 0) &&
			(strcmp(url, "/status") != 0) && 
			(strcmp(url, "/queue") != 0) &&
			(strcmp(url, "/start") != 0) &&
			(strncmp(url, "/signature", 10) != 0) &&
			(strncmp(url, "/timestamp", 10) != 0) &&
			(strncmp(url, "/log", 4) != 0) &&
			(strncmp(url, "/submit", 7) != 0) &&
			(strncmp(url, "/input", 6) != 0) &&
			(strncmp(url, "/confirm", 8) != 0))
		{
			std::cerr << "WARNING: got request for unknown URL" << std::endl;
		}
		size_t con_size = sizeof(tcpip_mhd_connection_info);
		tcpip_mhd_connection_info *con_info;
		con_info = (tcpip_mhd_connection_info*)malloc(con_size);
		if (con_info == NULL)
			return MHD_NO;
		con_info->policy_accepted = false;
		con_info->sig = NULL;
		con_info->len = 0;
		if (strcmp(method, "POST") == 0)
		{
			con_info->pp = MHD_create_post_processor(con, 512,
				tcpip_mhd_iterate_post, (void *)con_info);
			if (con_info->pp == NULL)
			{
				free(con_info);
				return MHD_NO;
			}
			con_info->ct = 1;
		}
		else
			con_info->ct = 0;
		*con_cls = (void *)con_info;
		return MHD_YES;
	}
	if (opt_verbose)
	{
		char ipaddr[INET6_ADDRSTRLEN];
		memset(ipaddr, 0, sizeof(ipaddr));
		const union MHD_ConnectionInfo *ci;
		ci = MHD_get_connection_info(con, MHD_CONNECTION_INFO_CLIENT_ADDRESS);
		if (ci != NULL)
		{
			struct sockaddr *sin = ci->client_addr;
			if ((ret = getnameinfo(sin, sizeof(struct sockaddr),
				ipaddr, sizeof(ipaddr), NULL, 0, NI_NUMERICHOST)) != 0)
			{
				std::cerr << "WARNING: resolving HTTP client address failed" <<
					std::endl;
			}
		}
		else
		{
			std::cerr << "WARNING: HTTP client IP address not available" <<
				std::endl;
		}
		std::cerr << "INFO: " << version << "-" << method << " request" <<
			" for URL \"" << url << "\" from address " << ipaddr << std::endl;
		if (opt_verbose > 1)
		{
			MHD_get_connection_values(con, MHD_HEADER_KIND, &tcpip_mhd_kv_print,
				NULL);
		}
	}
	struct MHD_Response *res = NULL;
	bool found = false;
	if (strcmp(method, "GET") == 0)
	{
		const char *tsn = MHD_lookup_connection_value(con,
			MHD_GET_ARGUMENT_KIND, "sn");
		if (strcmp(url, "/policy") == 0)
		{
			std::string page = policyfile.str(); 
			if (page.length() > 0)
			{
				res = MHD_create_response_from_buffer(
					page.length(),
					(void*)page.c_str(),
					MHD_RESPMEM_MUST_COPY);
			}
			else
			{
				res = MHD_create_response_from_buffer(
					strlen(tcpip_mhd_policypage),
					(void*)tcpip_mhd_policypage,
					MHD_RESPMEM_PERSISTENT);
			}
		}
		else if (strcmp(url, "/submit") == 0)
		{
			res = MHD_create_response_from_buffer(
				strlen(tcpip_mhd_submitpage),
				(void*)tcpip_mhd_submitpage,
				MHD_RESPMEM_PERSISTENT);
		}
		else if ((strncmp(url, "/confirm", 9) == 0) && (tsn != NULL))
		{
			std::string sn(tsn);
			if (tcpip_sn2status.count(sn) == 1)
			{
				if (tcpip_sn2status[sn] == DOTS_STATUS_SUBMITTED)
					tcpip_sn2status[sn] = DOTS_STATUS_CONFIRMED;
				res = MHD_create_response_from_buffer(
					strlen(tcpip_mhd_confirmpage),
					(void*)tcpip_mhd_confirmpage,
					MHD_RESPMEM_PERSISTENT);
			}
			else
			{
				res = MHD_create_response_from_buffer(
					strlen(tcpip_mhd_notpage),
					(void*)tcpip_mhd_notpage,
					MHD_RESPMEM_PERSISTENT);
			}
		}
		else if (strcmp(url, "/status") == 0)
		{
			std::stringstream tmp;
			for (tcpip_sn_mci_t q = tcpip_sn2status.begin();
				q != tcpip_sn2status.end(); ++q)
			{
				if (q->second != DOTS_STATUS_SUBMITTED)
					tmp << q->first << ":" << (int)q->second << std::endl;
			}
			std::string page = tmp.str();
			res = MHD_create_response_from_buffer(page.length(),
				(void*)page.c_str(), MHD_RESPMEM_MUST_COPY);
		}
		else if (strcmp(url, "/queue") == 0)
		{
			std::stringstream tmp;
			for (tcpip_sn_mci_t q = tcpip_sn2status.begin();
				q != tcpip_sn2status.end(); ++q)
			{
				if (q->second == DOTS_STATUS_STARTED)
				{
					tmp << q->first << std::endl;
					break;
				}
			}
			for (tcpip_sn_mci_t q = tcpip_sn2status.begin();
				q != tcpip_sn2status.end(); ++q)
			{
				if (q->second == DOTS_STATUS_CONFIRMED)
					tmp << q->first << std::endl;
			}
			std::string page = tmp.str();
			res = MHD_create_response_from_buffer(page.length(),
				(void*)page.c_str(), MHD_RESPMEM_MUST_COPY);
		}
		else if (strcmp(url, "/start") == 0)
		{
			std::stringstream tmp;
			for (tcpip_sn_mci_t q = tcpip_sn2status.begin();
				q != tcpip_sn2status.end(); ++q)
			{
				if (q->second == DOTS_STATUS_STARTED)
					tmp << q->first;
			}
			std::string page = tmp.str();
			res = MHD_create_response_from_buffer(page.length(),
				(void*)page.c_str(), MHD_RESPMEM_MUST_COPY);
		}
		else if ((strncmp(url, "/signature", 10) == 0) && (tsn != NULL))
		{
			std::string sn(tsn);
			if (tcpip_sn2signature.count(sn) == 1)
			{
				std::stringstream tmp;
				tmp << tcpip_sn2signature[sn];
				std::string page = tmp.str();
				res = MHD_create_response_from_buffer(page.length(),
					(void*)page.c_str(), MHD_RESPMEM_MUST_COPY);
				found = true;
			}
			else
			{
				res = MHD_create_response_from_buffer(
					strlen(tcpip_mhd_notpage),
					(void*)tcpip_mhd_notpage,
					MHD_RESPMEM_PERSISTENT);
			}
		}
		else if ((strncmp(url, "/timestamp", 10) == 0)  && (tsn != NULL))
		{
			std::string sn(tsn);
			if (tcpip_sn2timestamp.count(sn) == 1)
			{
				std::stringstream tmp;
				tmp << tcpip_sn2timestamp[sn];
				std::string page = tmp.str();
				res = MHD_create_response_from_buffer(page.length(),
					(void*)page.c_str(), MHD_RESPMEM_MUST_COPY);
				found = true;
			}
			else
			{
				res = MHD_create_response_from_buffer(
					strlen(tcpip_mhd_notpage),
					(void*)tcpip_mhd_notpage,
					MHD_RESPMEM_PERSISTENT);
			}
		}
		else if ((strncmp(url, "/log", 4) == 0)  && (tsn != NULL))
		{
			std::string sn(tsn);
			if (tcpip_sn2log.count(sn) == 1)
			{
				std::stringstream tmp;
				tmp << tcpip_sn2log[sn];
				std::string page = tmp.str();
				res = MHD_create_response_from_buffer(page.length(),
					(void*)page.c_str(), MHD_RESPMEM_MUST_COPY);
			}
			else
			{
				res = MHD_create_response_from_buffer(
					strlen(tcpip_mhd_notpage),
					(void*)tcpip_mhd_notpage,
					MHD_RESPMEM_PERSISTENT);
			}
		}
		else
		{
			// deliver default page
			res = MHD_create_response_from_buffer(
				strlen(tcpip_mhd_defaultpage),
				(void*)tcpip_mhd_defaultpage,
				MHD_RESPMEM_PERSISTENT);
		}
	}
	else if (strcmp(method, "POST") == 0)
	{
		tcpip_mhd_connection_info *con_info =
			(tcpip_mhd_connection_info*)*con_cls;
		if (*upload_data_size > 0)
		{
			if (con_info->len < DOTS_MAX_SIG_LENGTH)
				con_info->len += *upload_data_size;
			else
			{
				std::cerr << "WARNING: upload limit exceeded" << std::endl;
				return MHD_NO; // upload limit exceeded
			}
			MHD_post_process(con_info->pp,
				upload_data, *upload_data_size);
			*upload_data_size = 0;
			return MHD_YES;
		}
		else if ((con_info->sig != NULL) && (strcmp(url, "/input") == 0))
		{
			if (con_info->policy_accepted)
			{
				std::string sig(con_info->sig);
				tmcg_openpgp_secure_string_t pw;
				tmcg_openpgp_octets_t salt, hash;
				for (size_t i = 0; i < sig.length(); i++)
					pw += sig[i];
				for (size_t i = 0; i < tcpip_sn_seed.length(); i++)
					pw += tcpip_sn_seed[i]; // adding a fixed random seed
				CallasDonnerhackeFinneyShawThayerRFC4880::
					PacketTimeEncode(time(NULL), salt);
				salt.pop_back(); // remove two most significant octets of time, 
				salt.pop_back(); // thus salt will change at least after 18.5 days
				size_t sasi = salt.size();
				for (size_t i = 0; i < (8 - sasi); i++)
				{
					if (i < tcpip_thispeer.length())
						salt.push_back(tcpip_thispeer[i]);
					else
						salt.push_back(i);
				}
				tmcg_openpgp_secure_octets_t key;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					S2KCompute(TMCG_OPENPGP_HASHALGO_RMD160, 22, pw, salt, true,
					0x42, key);
				for (size_t i = 0; i < key.size(); i++)
					hash.push_back(key[i]);
				std::string sn;
				CallasDonnerhackeFinneyShawThayerRFC4880::
					FingerprintConvertPlain(hash, sn);
				if (tcpip_sn2signature.count(sn) == 0)
				{
					// store submitted data
					tcpip_sn2signature[sn] = sig;
					tcpip_sn2status[sn] = DOTS_STATUS_SUBMITTED;
					tcpip_sn2time_submitted[sn] = time(NULL);
					// encrypt S/N with a random password
					tmcg_openpgp_byte_t rand[9];
					gcry_randomize(rand, sizeof(rand), GCRY_STRONG_RANDOM);
					tmcg_openpgp_octets_t r;
					for (size_t i = 0; i < sizeof(rand); i++)
						r.push_back(rand[i]);
					std::string pwd1;
					CallasDonnerhackeFinneyShawThayerRFC4880::
						Radix64Encode(r, pwd1, false);
					tmcg_openpgp_secure_string_t pwd2;
					for (size_t i = 0; i < pwd1.length(); i++)
						pwd2 += pwd1[i];
					std::string encrypted_sn;
					if (!dots_encrypt_fuzzy_short(sn, pwd2, encrypted_sn))
						encrypted_sn = "FAILED";
					// deliver dynamic page with instructions
					std::stringstream tmp;
					tmp << TCPIP_MHD_HEADER << TCPIP_MHD_H2 << "Successfully " <<
						"submitted a signature for stamping.<br><br>" <<
						"Please confirm your request immediately by visiting " <<
						"<a href=\"/confirm?sn=XYZ\">/confirm?sn=XYZ</a>, where" <<
						" XYZ is a placeholder for the unique serial number " <<
						"(S/N) of this request.<br><br>" <<
						"You can obtain the required S/N by decrypting the " <<
						"following message with any OpenPGP-complient " <<
						"application (e.g. by calling gpg -d --pinentry-mode " <<
						"loopback --batch --passphrase '" << pwd2 << "'):<br>" <<
						"<pre>" << encrypted_sn << std::endl << "</pre>" <<
						"The corresponding password is \"" << pwd2 << "\"." <<
						TCPIP_MHD_FOOTER;
					std::string page = tmp.str();
					res = MHD_create_response_from_buffer(page.length(),
						(void*)page.c_str(), MHD_RESPMEM_MUST_COPY);
				}
				else
				{
					res = MHD_create_response_from_buffer(
						strlen(tcpip_mhd_duppage),
						(void*)tcpip_mhd_duppage,
						MHD_RESPMEM_PERSISTENT);
				}
			}
			else
			{
				res = MHD_create_response_from_buffer(
					strlen(tcpip_mhd_policypage),
					(void*)tcpip_mhd_policypage,
					MHD_RESPMEM_PERSISTENT);
			}
		}
	}
	if (res == NULL)
	{
		ret = MHD_queue_response(con, MHD_HTTP_INTERNAL_SERVER_ERROR, res);
	}
	else
	{
		if ((strcmp(url, "/status") == 0) ||
			(strcmp(url, "/queue") == 0) ||
			(strcmp(url, "/start") == 0) ||
			(strncmp(url, "/log", 4) == 0))
		{
			MHD_add_response_header(res, MHD_HTTP_HEADER_CONTENT_TYPE,
				"text/plain");
			MHD_add_response_header(res, MHD_HTTP_HEADER_CONNECTION,
				"close");
		}
		else if (found && ((strncmp(url, "/signature", 10) == 0) ||
			(strncmp(url, "/timestamp", 10) == 0)))
		{
			MHD_add_response_header(res, MHD_HTTP_HEADER_CONTENT_TYPE,
				"application/pgp-signature");
			MHD_add_response_header(res, MHD_HTTP_HEADER_CONNECTION,
				"close");
		}
		else
		{
			MHD_add_response_header(res, MHD_HTTP_HEADER_CONTENT_TYPE,
				"text/html");
		}
		ret = MHD_queue_response(con, MHD_HTTP_OK, res);
	}
	MHD_destroy_response(res);
	return ret;
}

void tcpip_init
	(const std::string &hostname)
{
	// initialize peer identity
	tcpip_thispeer = hostname;
	// initialize peer2pipe and pipe2peer mapping
	if (std::find(peers.begin(), peers.end(), tcpip_thispeer) == peers.end())
	{
		std::cerr << "ERROR: cannot find hostname \"" << tcpip_thispeer <<
			"\" of this peer within PEERS" << std::endl;
		exit(-1);
	}
	for (size_t i = 0; i < peers.size(); i++)
	{
		tcpip_peer2pipe[peers[i]] = i;
		tcpip_pipe2peer[i] = peers[i];
	}
	// initialize random S/N seed
	tmcg_openpgp_byte_t rand[32];
	gcry_randomize(rand, sizeof(rand), GCRY_STRONG_RANDOM);
	tmcg_openpgp_octets_t r;
	for (size_t i = 0; i < sizeof(rand); i++)
		r.push_back(rand[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::Radix64Encode(r, tcpip_sn_seed);
	// initialize HTTP server (MHD)
	struct sigaction act;
	memset(&act, 0, sizeof(act));
	act.sa_handler = &tcpip_sig_handler_pipe;
#ifdef SA_INTERRUPT
	act.sa_flags = SA_INTERRUPT;
#else
	act.sa_flags = SA_RESTART;
#endif
	if (sigaction(SIGPIPE, &act, NULL) < 0)
	{
		perror("ERROR: dots-tcpip-common (sigaction)");
		exit(-1);
	}
	tcpip_mhd = MHD_start_daemon(MHD_NO_FLAG,
		DOTS_MHD_PORT + tcpip_peer2pipe[tcpip_thispeer],
		NULL, NULL, &tcpip_mhd_callback, NULL, 
		MHD_OPTION_NOTIFY_COMPLETED, tcpip_mhd_request_completed, NULL,
		MHD_OPTION_CONNECTION_LIMIT, FD_SETSIZE - 5 - (4 * peers.size()),
		MHD_OPTION_CONNECTION_TIMEOUT, 120, // connection timeout in seconds
		MHD_OPTION_PER_IP_CONNECTION_LIMIT, 12, // max. concurrent connections
		MHD_OPTION_END);
	if (tcpip_mhd == NULL)
	{
		std::cerr << "ERROR: initialization of HTTP daemon failed" << std::endl;
		exit(-1);
	}
	// open pipes to communicate with forked instance
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if (pipe2(pipefd[i][j], O_NONBLOCK) < 0)
			{
				perror("ERROR: dots-tcpip-common (pipe2)");
				exit(-1);
			}
			if (pipe2(broadcast_pipefd[i][j], O_NONBLOCK) < 0)
			{
				perror("ERROR: dots-tcpip-common (pipe2)");
				exit(-1);
			}
		}
	}
	if (pipe2(self_pipefd, O_NONBLOCK) < 0)
	{
		perror("ERROR: dots-tcpip-common (pipe2)");
		exit(-1);
	}
	if (pipe2(broadcast_self_pipefd, O_NONBLOCK) < 0)
	{
		perror("ERROR: dots-tcpip-common (pipe2)");
		exit(-1);
	}	
	// install our own signal handlers to quit
	memset(&act, 0, sizeof(act));
	act.sa_handler = &tcpip_sig_handler_quit;
#ifdef SA_INTERRUPT
	act.sa_flags = SA_INTERRUPT;
#else
	act.sa_flags = SA_RESTART;
#endif
	if (sigaction(SIGINT, &act, NULL) < 0)
	{
		perror("ERROR: dots-tcpip-common (sigaction)");
		exit(-1);
	}
	if (sigaction(SIGQUIT, &act, NULL) < 0)
	{
		perror("ERROR: dots-tcpip-common (sigaction)");
		exit(-1);
	}
	if (sigaction(SIGTERM, &act, NULL) < 0)
	{
		perror("ERROR: dots-tcpip-common (sigaction)");
		exit(-1);
	}
}

void tcpip_bindports
	(const uint16_t start, const bool broadcast)
{
	if (opt_verbose > 2)
	{
		std::cerr << "INFO: tcpip_bindports(" << start << ", " <<
			(broadcast ? "true" : "false") << ") called" << std::endl;
		std::cerr << "INFO: FD_SETSIZE = " << FD_SETSIZE << std::endl;
	}
	uint16_t peers_size = 0;
	if (peers.size() <= DOTS_MAX_N)
	{
		peers_size = (uint16_t)peers.size();
	}
	else
	{
		std::cerr << "ERROR: too many peers defined" << std::endl;
		tcpip_close();
		tcpip_done();
		exit(-1);
	}
	uint16_t peer_offset = tcpip_peer2pipe[tcpip_thispeer] * peers_size;
	if (opt_verbose > 2)
		std::cerr << "INFO: peer_offset = " << peer_offset << std::endl;
	uint16_t local_start = start + peer_offset;
	uint16_t local_end = local_start + peers_size;
	size_t i = 0;
	if (broadcast)
	{
		local_start += peers_size * peers_size; // use different port range
		local_end += peers_size * peers_size;
	}
	for (uint16_t port = local_start; port < local_end; port++, i++)
	{
		struct addrinfo hints = { 0, 0, 0, 0, 0, 0, 0, 0 }, *res, *rp;
		hints.ai_family = AF_UNSPEC; // AF_INET; FIXME: resolving IPv4-only
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_PASSIVE | AI_NUMERICSERV | AI_ADDRCONFIG;
		std::stringstream ports;
		ports << port;
		int ret;
		if ((ret = getaddrinfo(NULL, (ports.str()).c_str(), &hints, &res)) != 0)
		{
			std::cerr << "ERROR: resolving wildcard address failed: ";
			if (ret == EAI_SYSTEM)
				perror("tcpip_bindports (getaddrinfo)");
			else
				std::cerr << gai_strerror(ret);
			std::cerr << std::endl;
			tcpip_close();
			tcpip_done();
			exit(-1);
		}
		int sockfd = -1;
		for (rp = res; rp != NULL; rp = rp->ai_next)
		{
			if ((sockfd = socket(rp->ai_family, rp->ai_socktype,
				rp->ai_protocol)) < 0)
			{
				perror("WARNING: tcpip_bindports (socket)");
				continue; // try next address
			}
			char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
			memset(hbuf, 0, sizeof(hbuf));
			memset(sbuf, 0, sizeof(sbuf));
			if ((ret = getnameinfo(rp->ai_addr, rp->ai_addrlen,
				hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
				NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
			{
				std::cerr << "ERROR: resolving wildcard address failed: ";
				if (ret == EAI_SYSTEM)
					perror("tcpip_bindports (getnameinfo)");
				else
					std::cerr << gai_strerror(ret);
				std::cerr << std::endl;
				if (close(sockfd) < 0)
					perror("WARNING: tcpip_bindports (close)");
				freeaddrinfo(res);
				tcpip_close();
				tcpip_done();
				exit(-1);
			}
			if (opt_verbose)
			{
				std::cerr << "INFO: bind TCP/IP port " << port <<
					" at address " << hbuf << std::endl;
			}
			if (bind(sockfd, rp->ai_addr, rp->ai_addrlen) < 0)
			{
				perror("WARNING: tcpip_bindports (bind)");
				if (close(sockfd) < 0)
					perror("WARNING: tcpip_bindports (close)");
				sockfd = -1;
				continue; // try next address
			}
			break; // on success: leave the loop
		}
		freeaddrinfo(res);
		if ((rp == NULL) || (sockfd < 0))
		{
			std::cerr << "ERROR: cannot bind TCP/IP port " << port <<
				" for any valid IP address of this host" << std::endl;
			tcpip_close();
			tcpip_done();
			exit(-1);
		}
		else if (listen(sockfd, SOMAXCONN) < 0)
		{
			perror("ERROR: tcpip_bindports (listen)");
			if (close(sockfd) < 0)
				perror("WARNING: tcpip_bindports (close)");
			tcpip_close();
			tcpip_done();
			exit(-1);
		}
		if (broadcast)
			tcpip_broadcast_pipe2socket[i] = sockfd;
		else
			tcpip_pipe2socket[i] = sockfd;
	}
}

size_t tcpip_connect
	(const uint16_t start, const bool broadcast)
{
	tcpip_start = start; // save TCP/IP starting port
	if (opt_verbose > 2)
	{
		std::cerr << "INFO: tcpip_connect(" << start << ", " <<
			(broadcast ? "true" : "false") << ") called" << std::endl;
	}
	for (size_t i = 0; i < peers.size(); i++)
	{
		if ((broadcast && (tcpip_broadcast_pipe2socket_out.count(i) == 0)) ||
			(!broadcast && (tcpip_pipe2socket_out.count(i) == 0)))
		{
			uint16_t peers_size = 0;
			if (peers.size() <= DOTS_MAX_N)
			{
				peers_size = (uint16_t)peers.size();
			}
			else
			{
				std::cerr << "ERROR: too many peers defined" << std::endl;
				tcpip_close();
				tcpip_done();
				exit(-1);
			}
			uint16_t peer_offset = (uint16_t)tcpip_peer2pipe[tcpip_thispeer];
			uint16_t port = start + (i * peers_size) + peer_offset;
			int ret;
			struct addrinfo hints = { 0, 0, 0, 0, 0, 0, 0, 0 }, *res, *rp;
			hints.ai_family = AF_UNSPEC; // AF_INET; FIXME: resolving IPv4-only
			hints.ai_socktype = SOCK_STREAM;
			hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
			if (broadcast)
				port += peers_size * peers_size; // use different port range
			std::stringstream ports;
			ports << port;
			if ((ret = getaddrinfo(peers[i].c_str(), (ports.str()).c_str(),
				&hints, &res)) != 0)
			{
				std::cerr << "ERROR: resolving hostname \"" <<
					peers[i] << "\" failed: ";
				if (ret == EAI_SYSTEM)
					perror("tcpip_connect (getaddrinfo)");
				else
					std::cerr << gai_strerror(ret);
				std::cerr << std::endl;
				tcpip_close();
				tcpip_done();
				exit(-1);
			}
			for (rp = res; rp != NULL; rp = rp->ai_next)
			{
				int sockfd;
				if ((sockfd = socket(rp->ai_family, rp->ai_socktype,
					rp->ai_protocol)) < 0)
				{
					perror("WARNING: tcpip_connect (socket)");
					continue; // try next address
				}
				if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) < 0)
				{
					if (errno != ECONNREFUSED)
						perror("WARNING: tcpip_connect (connect)");					
					if (close(sockfd) < 0)
						perror("WARNING: tcpip_connect (close)");
					continue; // try next address
				}
				else
				{
					char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
					memset(hbuf, 0, sizeof(hbuf));
					memset(sbuf, 0, sizeof(sbuf));
					if ((ret = getnameinfo(rp->ai_addr, rp->ai_addrlen,
						hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
						NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
					{
						std::cerr << "ERROR: resolving hostname \"" <<
							peers[i] << "\" failed: ";
						if (ret == EAI_SYSTEM)
							perror("tcpip_connect (getnameinfo)");
						else
							std::cerr << gai_strerror(ret);
						std::cerr << std::endl;
						if (close(sockfd) < 0)
							perror("WARNING: tcpip_connect (close)");
						freeaddrinfo(res);
						tcpip_close();
						tcpip_done();
						exit(-1);
					}
					if (opt_verbose)
					{
						std::cerr << "INFO: resolved hostname \"" <<
							peers[i] << "\" to address " << hbuf << std::endl;
					}
					if (opt_verbose)
					{
						std::cerr << "INFO: connected to host \"" <<
							peers[i] << "\" on port " << port << std::endl;
					}
					if (broadcast)
						tcpip_broadcast_pipe2socket_out[i] = sockfd;
					else
						tcpip_pipe2socket_out[i] = sockfd;
					break; // on success: leave the loop
				}
			}
			freeaddrinfo(res);
		}
	}
	if (broadcast)
		return tcpip_broadcast_pipe2socket_out.size();
	else
		return tcpip_pipe2socket_out.size();
}

bool tcpip_reconnect
	(const size_t peer, const bool broadcast)
{
	if (opt_verbose > 1)
	{
		std::cerr << "INFO: tcpip_reconnect(" << peer << ", " <<
			(broadcast ? "true" : "false") << ") called" << std::endl;
	}
	if ((broadcast && (tcpip_broadcast_pipe2socket_out.count(peer) == 0)) ||
		(!broadcast && (tcpip_pipe2socket_out.count(peer) == 0)))
	{
		uint16_t peers_size = 0;
		if (peers.size() <= DOTS_MAX_N)
		{
			peers_size = (uint16_t)peers.size();
		}
		else
		{
			std::cerr << "ERROR: too many peers defined" << std::endl;
			return false;
		}
		uint16_t peer_offset = (uint16_t)tcpip_peer2pipe[tcpip_thispeer];
		uint16_t port = tcpip_start + (peer * peers_size) + peer_offset;
		int ret;
		struct addrinfo hints = { 0, 0, 0, 0, 0, 0, 0, 0 }, *res, *rp;
		hints.ai_family = AF_UNSPEC; // AF_INET; FIXME: resolving IPv4-only
		hints.ai_socktype = SOCK_STREAM;
		hints.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
		if (broadcast)
			port += peers_size * peers_size; // use different port range
		std::stringstream ports;
		ports << port;
		if ((ret = getaddrinfo(peers[peer].c_str(), (ports.str()).c_str(),
			&hints, &res)) != 0)
		{
			std::cerr << "ERROR: resolving hostname \"" << peers[peer] <<
				"\" failed: ";
			if (ret == EAI_SYSTEM)
				perror("tcpip_reconnect (getaddrinfo)");
			else
				std::cerr << gai_strerror(ret);
			std::cerr << std::endl;
			return false;
		}
		for (rp = res; rp != NULL; rp = rp->ai_next)
		{
			int sockfd;
			if ((sockfd = socket(rp->ai_family, rp->ai_socktype,
				rp->ai_protocol)) < 0)
			{
				perror("WARNING: tcpip_reconnect (socket)");
				continue; // try next address
			}
			if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) < 0)
			{
				if (errno != ECONNREFUSED)
					perror("WARNING: tcpip_reconnect (connect)");					
				if (close(sockfd) < 0)
					perror("WARNING: tcpip_reconnect (close)");
				continue; // try next address
			}
			else
			{
				char hbuf[NI_MAXHOST], sbuf[NI_MAXSERV];
				memset(hbuf, 0, sizeof(hbuf));
				memset(sbuf, 0, sizeof(sbuf));
				if ((ret = getnameinfo(rp->ai_addr, rp->ai_addrlen,
					hbuf, sizeof(hbuf), sbuf, sizeof(sbuf),
					NI_NUMERICHOST | NI_NUMERICSERV)) != 0)
				{
					std::cerr << "ERROR: resolving hostname \"" <<
						peers[peer] << "\" failed: ";
					if (ret == EAI_SYSTEM)
						perror("tcpip_reconnect (getnameinfo)");
					else
						std::cerr << gai_strerror(ret);
					std::cerr << std::endl;
					if (close(sockfd) < 0)
						perror("WARNING: tcpip_reconnect (close)");
					freeaddrinfo(res);
					return false;
				}
				if (opt_verbose)
				{
					std::cerr << "INFO: resolved hostname \"" << peers[peer] <<
						"\" to address " << hbuf << std::endl;
				}
				if (opt_verbose)
				{
					std::cerr << "INFO: connected to host \"" << peers[peer] <<
						"\" on port " << port << std::endl;
				}
				if (broadcast)
					tcpip_broadcast_pipe2socket_out[peer] = sockfd;
				else
					tcpip_pipe2socket_out[peer] = sockfd;
				freeaddrinfo(res);
				return true;
			}
		}
		freeaddrinfo(res);
	}
	return false;
}

void tcpip_accept
	()
{
	if (opt_verbose > 2)
	{
		std::cerr << "INFO: tcpip_accept(...) called" << std::endl;
		std::cerr << "INFO: FD_SETSIZE = " << FD_SETSIZE << std::endl;
	}
	while ((tcpip_pipe2socket_in.size() < peers.size()) ||
		(tcpip_broadcast_pipe2socket_in.size() < peers.size()))
	{
		fd_set rfds;
		struct timeval tv;
		int retval, maxfd = 0;
		FD_ZERO(&rfds);
		for (tcpip_mci_t pi = tcpip_pipe2socket.begin();
			pi != tcpip_pipe2socket.end(); ++pi)
		{
			if (pi->second < FD_SETSIZE)
			{
				FD_SET(pi->second, &rfds);
				if (pi->second > maxfd)
					maxfd = pi->second;
			}
			else
			{
				std::cerr << "ERROR: file descriptor value of internal pipe" <<
					" exceeds FD_SETSIZE" << std::endl;
				tcpip_close();
				tcpip_done();
				exit(-1);
			}
		}
		for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket.begin();
			pi != tcpip_broadcast_pipe2socket.end(); ++pi)
		{
			if (pi->second < FD_SETSIZE)
			{
				FD_SET(pi->second, &rfds);
				if (pi->second > maxfd)
					maxfd = pi->second;
			}
			else
			{
				std::cerr << "ERROR: file descriptor value of internal pipe" <<
					" exceeds FD_SETSIZE" << std::endl;
				tcpip_close();
				tcpip_done();
				exit(-1);
			}
		}
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		retval = select((maxfd + 1), &rfds, NULL, NULL, &tv);
		if (retval < 0)
		{
			if ((errno == EAGAIN) || (errno == EINTR))
			{
				if (errno == EAGAIN)
					perror("WARNING: tcpip_accept (select)");
				continue;
			}
			else
			{
				perror("ERROR: tcpip_accept (select)");
				tcpip_close();
				tcpip_done();
				exit(-1);
			}
		}
		if (retval == 0)
			continue; // timeout
		for (tcpip_mci_t pi = tcpip_pipe2socket.begin();
			pi != tcpip_pipe2socket.end(); ++pi)
		{
			if (FD_ISSET(pi->second, &rfds))
			{
				struct sockaddr_storage sin;
				socklen_t slen = (socklen_t)sizeof(sin);
				memset(&sin, 0, sizeof(sin));
				int connfd = accept(pi->second, (struct sockaddr*)&sin, &slen);
				if (connfd < 0)
				{
					perror("ERROR: tcpip_accept (accept)");
					tcpip_close();
					tcpip_done();
					exit(-1);
				}
				tcpip_pipe2socket_in[pi->first] = connfd;
				char ipaddr[INET6_ADDRSTRLEN];
				int ret;
				if ((ret = getnameinfo((struct sockaddr *)&sin, slen,
					ipaddr, sizeof(ipaddr), NULL, 0, NI_NUMERICHOST)) != 0)
				{
					std::cerr << "ERROR: resolving incoming address failed: ";
					if (ret == EAI_SYSTEM)
						perror("tcpip_accept (getnameinfo)");
					else
						std::cerr << gai_strerror(ret);
					std::cerr << std::endl;
					tcpip_close();
					tcpip_done();
					exit(-1);
				}
				if (opt_verbose)
				{
					std::cerr << "INFO: accept connection for P_" <<
						pi->first << " from address " << ipaddr << std::endl;
				}
			}
		}
		for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket.begin();
			pi != tcpip_broadcast_pipe2socket.end(); ++pi)
		{
			if (FD_ISSET(pi->second, &rfds))
			{
				struct sockaddr_storage sin;
				socklen_t slen = (socklen_t)sizeof(sin);
				memset(&sin, 0, sizeof(sin));
				int connfd = accept(pi->second, (struct sockaddr*)&sin, &slen);
				if (connfd < 0)
				{
					perror("ERROR: tcpip_accept (accept)");
					tcpip_close();
					tcpip_done();
					exit(-1);
				}
				tcpip_broadcast_pipe2socket_in[pi->first] = connfd;
				char ipaddr[INET6_ADDRSTRLEN];
				int ret;
				if ((ret = getnameinfo((struct sockaddr *)&sin, slen,
					ipaddr, sizeof(ipaddr), NULL, 0, NI_NUMERICHOST)) != 0)
				{
					std::cerr << "ERROR: resolving incoming address failed: ";
					if (ret == EAI_SYSTEM)
						perror("tcpip_accept (getnameinfo)");
					else
						std::cerr << gai_strerror(ret);
					std::cerr << std::endl;
					tcpip_close();
					tcpip_done();
					exit(-1);
				}
				if (opt_verbose)
				{
					std::cerr << "INFO: accept broadcast connection for" <<
						" P_" << pi->first << " from address " << 
						ipaddr << std::endl;
				}
			}
		}
	}
}

bool tcpip_reaccept
	(const size_t peer, const bool broadcast)
{
	if (opt_verbose > 1)
	{
		std::cerr << "INFO: tcpip_reaccept(" << peer << ", " <<
			(broadcast ? "true" : "false") << ") called" << std::endl;
	}
	bool good = false;
	if (broadcast)
	{
		if (tcpip_broadcast_pipe2socket_in.count(peer) == 0)
			tcpip_broadcast_pipe2socket_in[peer] = 0;
		if (tcpip_broadcast_pipe2socket_in[peer] == 0)
			good = true;
		if (!good)
		{
			tcpip_broadcast_pipe2socket_in.erase(peer);
			return false;
		}
	}
	else
	{
		if (tcpip_pipe2socket_in.count(peer) == 0)
			tcpip_pipe2socket_in[peer] = 0;
		else if (tcpip_pipe2socket_in[peer] == 0)
			good = true;
		if (!good)
		{
			tcpip_pipe2socket_in.erase(peer);
			return false;
		}
	}
	size_t rounds = 0;
	do
	{
		fd_set rfds;
		struct timeval tv;
		int retval, maxfd = 0;
		FD_ZERO(&rfds);
		if (broadcast)
		{
			FD_SET(tcpip_broadcast_pipe2socket[peer], &rfds);
			if (tcpip_broadcast_pipe2socket[peer] > maxfd)
				maxfd = tcpip_broadcast_pipe2socket[peer];
		}
		else
		{
			FD_SET(tcpip_pipe2socket[peer], &rfds);
			if (tcpip_pipe2socket[peer] > maxfd)
				maxfd = tcpip_pipe2socket[peer];
		}
		tv.tv_sec = DOTS_TIME_POLL;
		tv.tv_usec = 0;
		retval = select((maxfd + 1), &rfds, NULL, NULL, &tv);
		if (retval < 0)
		{
			if ((errno == EAGAIN) || (errno == EINTR))
			{
				if (errno == EAGAIN)
					perror("WARNING: tcpip_reaccept (select)");
				continue;
			}
			else
			{
				perror("ERROR: tcpip_reaccept (select)");
				return false;
			}
		}
		if (retval == 0)
			return false; // timeout
		if (!broadcast && FD_ISSET(tcpip_pipe2socket[peer], &rfds))
		{
			struct sockaddr_storage sin;
			socklen_t slen = (socklen_t)sizeof(sin);
			memset(&sin, 0, sizeof(sin));
			int connfd = accept(tcpip_pipe2socket[peer],
				(struct sockaddr*)&sin, &slen);
			if (connfd < 0)
			{
				perror("ERROR: tcpip_reaccept (accept)");
				return false;
			}
			tcpip_pipe2socket_in[peer] = connfd;
			char ipaddr[INET6_ADDRSTRLEN];
			int ret;
			if ((ret = getnameinfo((struct sockaddr *)&sin, slen,
				ipaddr, sizeof(ipaddr), NULL, 0, NI_NUMERICHOST)) != 0)
			{
				std::cerr << "WARNING: resolving incoming address failed: ";
				if (ret == EAI_SYSTEM)
					perror("tcpip_reaccept (getnameinfo)");
				else
					std::cerr << gai_strerror(ret);
				std::cerr << std::endl;
				return true;
			}
			if (opt_verbose)
			{
				std::cerr << "INFO: accept connection for P_" <<
					peer << " from address " << ipaddr << std::endl;
			}
			return true;
		}
		if (broadcast && FD_ISSET(tcpip_broadcast_pipe2socket[peer], &rfds))
		{
			struct sockaddr_storage sin;
			socklen_t slen = (socklen_t)sizeof(sin);
			memset(&sin, 0, sizeof(sin));
			int connfd = accept(tcpip_broadcast_pipe2socket[peer],
				(struct sockaddr*)&sin, &slen);
			if (connfd < 0)
			{
				perror("ERROR: tcpip_reaccept (accept)");
				return false;
			}
			tcpip_broadcast_pipe2socket_in[peer] = connfd;
			char ipaddr[INET6_ADDRSTRLEN];
			int ret;
			if ((ret = getnameinfo((struct sockaddr *)&sin, slen,
				ipaddr, sizeof(ipaddr), NULL, 0, NI_NUMERICHOST)) != 0)
			{
				std::cerr << "WARNING: resolving incoming address failed: ";
				if (ret == EAI_SYSTEM)
					perror("tcpip_reaccept (getnameinfo)");
				else
					std::cerr << gai_strerror(ret);
				std::cerr << std::endl;
				return true;
			}
			if (opt_verbose)
			{
				std::cerr << "INFO: accept broadcast connection for" <<
					" P_" << peer << " from address " << 
					ipaddr << std::endl;
			}
			return true;
		}
	}
	while (++rounds < 5);
	return false;
}

bool tcpip_fork
	()
{
	if ((tcpip_pipe2socket_in.size() == peers.size()) &&
		(tcpip_broadcast_pipe2socket_in.size() == peers.size()))
	{
		// fork instance
		if (opt_verbose)
			std::cerr << "INFO: forking the protocol instance ..." << std::endl;
		if (!fork_instance(tcpip_peer2pipe[tcpip_thispeer]))
			return false;
	}
	else
	{
		std::cerr << "ERROR: not enough connections established" << std::endl;
		return false;
	}
	return true;
}

bool tcpip_work
	(int &returncode, std::string &current)
{
	size_t thisidx = tcpip_peer2pipe[tcpip_thispeer]; // index of this peer
	if (instance_forked)
	{
		// exit, if forked instance has terminated 
		int wstatus = 0;
		int thispid = pid[thisidx];
		int ret = waitpid(thispid, &wstatus, WNOHANG);
		if (ret < 0)
		{
			perror("WARNING: tcpip_io (waitpid)");
		}
		else if (ret == thispid)
		{
			instance_forked = false;
			if (!WIFEXITED(wstatus))
			{
				std::cerr << "ERROR: protocol instance ";
				if (WIFSIGNALED(wstatus))
				{
					std::cerr << thispid << " terminated by signal " <<
						WTERMSIG(wstatus) << std::endl;
				}
				if (WCOREDUMP(wstatus))
					std::cerr << thispid << " dumped core" << std::endl;
				returncode = -200;
				return false;
			}
			else
			{
				if (opt_verbose)
				{
					std::cerr << "INFO: protocol instance " << thispid <<
						" terminated with exit status " <<
						WEXITSTATUS(wstatus) << std::endl;
				}
				returncode = WEXITSTATUS(wstatus);
				return false;
			}
		}
	}
	std::string next = "";
	bool started = false;
	std::vector<std::string> cleanup_submitted, cleanup_failed, cleanup_stamped;
	time_t current_time = time(NULL);
	for (tcpip_sn_mci_t q = tcpip_sn2status.begin();
		q != tcpip_sn2status.end(); ++q)
	{
		if (q->second == DOTS_STATUS_STARTED)
			started = true;
		if ((q->second == DOTS_STATUS_CONFIRMED) && (next.length() == 0))
			next = q->first;
		if (q->second == DOTS_STATUS_SUBMITTED)
		{
			time_t st = tcpip_sn2time_submitted[q->first];
			if (st < (current_time - DOTS_TIME_UNCONFIRMED))
				cleanup_submitted.push_back(q->first);
		}
		else if (q->second == DOTS_STATUS_FAILED)
		{
			time_t st = tcpip_sn2time_failed[q->first];
			if (st < (current_time - DOTS_TIME_LOG))
				cleanup_failed.push_back(q->first);
		}
		else if (q->second == DOTS_STATUS_STAMPED)
		{
			time_t st = tcpip_sn2time_stamped[q->first];
			if (st < (current_time - DOTS_TIME_STAMP))
				cleanup_stamped.push_back(q->first);
		}
	}
	for (size_t i = 0; i < cleanup_submitted.size(); i++)
	{
		tcpip_sn2status.erase(cleanup_submitted[i]);
		tcpip_sn2signature.erase(cleanup_submitted[i]);
		tcpip_sn2time_submitted.erase(cleanup_submitted[i]);
	}
	for (size_t i = 0; i < cleanup_failed.size(); i++)
	{
		tcpip_sn2status.erase(cleanup_failed[i]);
		tcpip_sn2signature.erase(cleanup_failed[i]);
		tcpip_sn2log.erase(cleanup_failed[i]);
		tcpip_sn2time_failed.erase(cleanup_failed[i]);
	}
	for (size_t i = 0; i < cleanup_stamped.size(); i++)
	{
		tcpip_sn2status.erase(cleanup_failed[i]);
		tcpip_sn2signature.erase(cleanup_failed[i]);
		tcpip_sn2timestamp.erase(cleanup_failed[i]);
		tcpip_sn2time_stamped.erase(cleanup_failed[i]);
	}
	if (!started && (next.length() > 0))
	{
		current = next;
		tcpip_sn2status[current] = DOTS_STATUS_STARTED;
	}
	if (started && (current.length() > 0))
	{
		std::stringstream efilename, ofilename;
		efilename << "dotsd_" << tcpip_thispeer << "_" << current <<
			"_error.txt";
		ofilename << "dotsd_" << tcpip_thispeer << "_" << current <<
			"_stamp.asc";
		std::ifstream efs((efilename.str()).c_str(), std::ifstream::in);
		std::ifstream ofs((ofilename.str()).c_str(), std::ifstream::in);
		if (efs.is_open())
		{
			std::stringstream errorlog;
			std::string line;
			while (std::getline(efs, line))
				errorlog << line << std::endl;
			if (efs.eof())
			{
				tcpip_sn2log[current] = errorlog.str();
			}
			else
			{
				tcpip_sn2log[current] = "reading from error file \"" +
					efilename.str() + "\" until EOF failed";
				std::cerr << "WARNING: " << tcpip_sn2log[current] <<
					std::endl;
			}
			efs.close();
			tcpip_sn2status[current] = DOTS_STATUS_FAILED;
			tcpip_sn2time_failed[current] = time(NULL);
			started = false;
		}
		else if (ofs.is_open())
		{
			std::stringstream timestamp;
			std::string line;
			while (std::getline(ofs, line))
				timestamp << line << std::endl;
			if (ofs.eof())
			{
				tcpip_sn2status[current] = DOTS_STATUS_STAMPED;
				tcpip_sn2time_stamped[current] = time(NULL);
				tcpip_sn2timestamp[current] = timestamp.str();
				started = false;
			}
			else
			{
				std::cerr << "WARNING: reading from output file \"" <<
					ofilename.str() << "\" until EOF failed" << std::endl;
			}
			ofs.close();
		}
	}
	return true;
}

int tcpip_io
	()
{
	size_t thisidx = tcpip_peer2pipe[tcpip_thispeer]; // index of this peer
	std::string current = ""; // S/N selected for processing
	char buf_in[peers.size()][tcpip_pipe_buffer_size];
	char broadcast_buf_in[peers.size()][tcpip_pipe_buffer_size];
	char buf_out[peers.size()][tcpip_pipe_buffer_size];
	char broadcast_buf_out[peers.size()][tcpip_pipe_buffer_size];
	std::vector<size_t> len_in, broadcast_len_in, len_out, broadcast_len_out;
	for (size_t i = 0; i < peers.size(); i++)
	{
		len_in.push_back(0);
		broadcast_len_in.push_back(0);
		len_out.push_back(0);
		broadcast_len_out.push_back(0);
	}
	while (!signal_caught)
	{
		// do some other work beside I/O
		int ret = 0;
		if (!tcpip_work(ret, current))
			return ret;
		// do buffered I/O for DOTS and MHD
		fd_set rfds, wfds;
		MHD_socket maxfd = 0;
		FD_ZERO(&rfds);
		FD_ZERO(&wfds);
		for (tcpip_mci_t pi = tcpip_pipe2socket_in.begin();
			pi != tcpip_pipe2socket_in.end(); ++pi)
		{
			if (pi->second < FD_SETSIZE)
			{
				FD_SET(pi->second, &rfds);
				if (pi->second > maxfd)
					maxfd = pi->second;
			}
			else
			{
				std::cerr << "ERROR: file descriptor value of internal" <<
					" pipe exceeds FD_SETSIZE" << std::endl;
				return -201;
			}
		}
		for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket_in.begin();
			pi != tcpip_broadcast_pipe2socket_in.end(); ++pi)
		{
			if (pi->second < FD_SETSIZE)
			{
				FD_SET(pi->second, &rfds);
				if (pi->second > maxfd)
					maxfd = pi->second;
			}
			else
			{
				std::cerr << "ERROR: file descriptor value of internal" <<
					" pipe exceeds FD_SETSIZE" << std::endl;
				return -201;
			}
		}
		for (tcpip_mci_t pi = tcpip_pipe2socket_out.begin();
			pi != tcpip_pipe2socket_out.end(); ++pi)
		{
			if (pi->second < FD_SETSIZE)
			{
				FD_SET(pi->second, &wfds);
				if (pi->second > maxfd)
					maxfd = pi->second;
			}
			else
			{
				std::cerr << "ERROR: file descriptor value of internal" <<
					" pipe exceeds FD_SETSIZE" << std::endl;
				return -201;
			}
		}
		for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket_out.begin();
			pi != tcpip_broadcast_pipe2socket_out.end(); ++pi)
		{
			if (pi->second < FD_SETSIZE)
			{
				FD_SET(pi->second, &wfds);
				if (pi->second > maxfd)
					maxfd = pi->second;
			}
			else
			{
				std::cerr << "ERROR: file descriptor value of internal" <<
					" pipe exceeds FD_SETSIZE" << std::endl;
				return -201;
			}
		}
		for (size_t i = 0; i < peers.size(); i++)
		{
			if (pipefd[thisidx][i][0] < FD_SETSIZE)
			{
				FD_SET(pipefd[thisidx][i][0], &rfds);
				if (pipefd[thisidx][i][0] > maxfd)
					maxfd = pipefd[thisidx][i][0];
			}
			else
			{
				std::cerr << "ERROR: file descriptor value of internal" <<
					" pipe exceeds FD_SETSIZE" << std::endl;
				return -201;
			}
			if (pipefd[i][thisidx][1] < FD_SETSIZE)
			{
				FD_SET(pipefd[i][thisidx][1], &wfds);
				if (pipefd[i][thisidx][1] > maxfd)
					maxfd = pipefd[i][thisidx][1];
			}
			else
			{
				std::cerr << "ERROR: file descriptor value of internal" <<
					" pipe exceeds FD_SETSIZE" << std::endl;
				return -201;
			}
			if (self_pipefd[1] < FD_SETSIZE)
			{
				FD_SET(self_pipefd[1], &wfds);
				if (self_pipefd[1] > maxfd)
					maxfd = self_pipefd[1];
			}
			else
			{
				std::cerr << "ERROR: file descriptor value of internal" <<
					" pipe exceeds FD_SETSIZE" << std::endl;
				return -201;
			}
			if (broadcast_pipefd[thisidx][i][0] < FD_SETSIZE)
			{
				FD_SET(broadcast_pipefd[thisidx][i][0], &rfds);
				if (broadcast_pipefd[thisidx][i][0] > maxfd)
					maxfd = broadcast_pipefd[thisidx][i][0];
			}
			else
			{
				std::cerr << "ERROR: file descriptor value of internal" <<
					" pipe exceeds FD_SETSIZE" << std::endl;
				return -201;
			}
			if (broadcast_pipefd[i][thisidx][1] < FD_SETSIZE)
			{
				FD_SET(broadcast_pipefd[i][thisidx][1], &wfds);
				if (broadcast_pipefd[i][thisidx][1] > maxfd)
					maxfd = broadcast_pipefd[i][thisidx][1];
			}
			else
			{
				std::cerr << "ERROR: file descriptor value of internal" <<
					" pipe exceeds FD_SETSIZE" << std::endl;
				return -201;
			}
			if (broadcast_self_pipefd[1] < FD_SETSIZE)
			{
				FD_SET(broadcast_self_pipefd[1], &wfds);
				if (broadcast_self_pipefd[1] > maxfd)
					maxfd = broadcast_self_pipefd[1];
			}
			else
			{
				std::cerr << "ERROR: file descriptor value of internal" <<
					" pipe exceeds FD_SETSIZE" << std::endl;
				return -201;
			}
		}
		if (MHD_get_fdset(tcpip_mhd, &rfds, &wfds, NULL, &maxfd) != MHD_YES)
		{
			std::cerr << "ERROR: MHD_get_fdset() failed" << std::endl;
			return -201;
		}
		struct timeval tv;
		tv.tv_sec = 1;
		tv.tv_usec = 0;
		int retval = select((maxfd + 1), &rfds, &wfds, NULL, &tv);
		if (retval < 0)
		{
			if ((errno == EAGAIN) || (errno == EINTR))
			{
				if (errno == EAGAIN)
					perror("WARNING: tcpip_io (select)");
				continue;
			}
			else
			{
				perror("ERROR: tcpip_io (select)");
				return -202;
			}
		}
		if (retval == 0)
			continue; // timeout
		for (tcpip_mci_t pi = tcpip_pipe2socket_in.begin();
			pi != tcpip_pipe2socket_in.end(); ++pi)
		{
			size_t max = tcpip_pipe_buffer_size - len_in[pi->first];
			if (FD_ISSET(pi->second, &rfds) && (max > 0))
			{
				ssize_t len = read(pi->second,
					buf_in[pi->first] + len_in[pi->first], max);
				if (len < 0)
				{
					if ((errno == EWOULDBLOCK) || (errno == EINTR))
					{
						continue;
					}
					else if (errno == EAGAIN)
					{
						perror("WARNING: tcpip_io (read)");
						continue;
					}
					else
					{
						perror("ERROR: tcpip_io (read)");
						return -203;
					}
				}
				else if (len == 0)
				{
					std::cerr << "WARNING: connection collapsed for" <<
						" P_" << pi->first << std::endl;
					if (close(tcpip_pipe2socket_in[pi->first]) < 0)
						perror("WARNING: tcpip_io (close)");
					tcpip_pipe2socket_in[pi->first] = 0;
					if (tcpip_reaccept(pi->first, false))
					{
						std::cerr << "INFO: reaccept successful" << std::endl;
						continue;
					}
					tcpip_pipe2socket_in.erase(pi->first);
					break;
				}
				else
				{
					if (opt_verbose > 2)
					{
						std::cerr << "INFO: received " << len << " bytes on " <<
							"connection for P_" << pi->first << std::endl;
					}
					len_in[pi->first] += len;
				}
			}
		}
		for (size_t i = 0; i < peers.size(); i++)
		{
			if (((i == thisidx) && FD_ISSET(self_pipefd[1], &wfds) &&
				(len_in[i] > 0)) ||
				((i != thisidx) && FD_ISSET(pipefd[i][thisidx][1], &wfds) &&
				(len_in[i] > 0)))
			{
				size_t wnum = 0;
				do
				{
					ssize_t num = 0;
					if (i == thisidx)
					{
						num = write(self_pipefd[1],
							buf_in[i] + wnum,
							len_in[i] - wnum);
					}
					else
					{
						num = write(pipefd[i][thisidx][1],
							buf_in[i] + wnum,
							len_in[i] - wnum);
					}
					if (num < 0)
					{
						if ((errno == EWOULDBLOCK) || (errno == EINTR))
						{
							break;
						}
						else if (errno == EAGAIN)
						{
							perror("WARNING: tcpip_io (write)");
							break;
						}
						else
						{
							perror("ERROR: tcpip_io (write)");
							std::cerr << "DEBUG: pipefd[" << i <<
								"][" << thisidx << "]" << std::endl;
							return -204;
						}
					}
					else
						wnum += num;
				}
				while (wnum < len_in[i]);
				if (wnum > 0)
				{
					len_in[i] -= wnum;
					memmove(buf_in[i], buf_in[i] + wnum, len_in[i]);
				}
			}
		}
		for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket_in.begin();
			pi != tcpip_broadcast_pipe2socket_in.end(); ++pi)
		{
			size_t max = tcpip_pipe_buffer_size - broadcast_len_in[pi->first];
			if (FD_ISSET(pi->second, &rfds) && (max > 0))
			{
				ssize_t len = read(pi->second, broadcast_buf_in[pi->first] +
					broadcast_len_in[pi->first], max);
				if (len < 0)
				{
					if ((errno == EWOULDBLOCK) || (errno == EINTR))
					{
						continue;
					}
					else if (errno == EAGAIN)
					{
						perror("WARNING: tcpip_io (read)");
						continue;
					}
					else
					{
						perror("ERROR: tcpip_io (read)");
						return -203;
					}
				}
				else if (len == 0)
				{
					std::cerr << "WARNING: broadcast connection collapsed for" <<
						" P_" << pi->first << std::endl;
					if (close(tcpip_broadcast_pipe2socket_in[pi->first]) < 0)
						perror("WARNING: tcpip_io (close)");
					tcpip_broadcast_pipe2socket_in[pi->first] = 0;
					if (tcpip_reaccept(pi->first, true))
					{
						std::cerr << "INFO: reaccept successful" << std::endl;
						continue;
					}
					tcpip_broadcast_pipe2socket_in.erase(pi->first);
					break;
				}
				else
				{
					if (opt_verbose > 2)
					{
						std::cerr << "INFO: received " << len << " bytes on " <<
							"broadcast connection for P_" << pi->first <<
							std::endl;
					}
					broadcast_len_in[pi->first] += len;
				}
			}
		}
		for (size_t i = 0; i < peers.size(); i++)
		{
			if (((i == thisidx) && FD_ISSET(broadcast_self_pipefd[1], &wfds) &&
				(broadcast_len_in[i] > 0)) ||
				((i != thisidx) && FD_ISSET(broadcast_pipefd[i][thisidx][1],
					&wfds) && (broadcast_len_in[i] > 0)))
			{
				size_t wnum = 0;
				do
				{
					ssize_t num = 0;
					if (i == thisidx)
					{
						num = write(broadcast_self_pipefd[1],
							broadcast_buf_in[i] + wnum,
							broadcast_len_in[i] - wnum);
					}
					else
					{
						num = write(broadcast_pipefd[i][thisidx][1],
							broadcast_buf_in[i] + wnum,
							broadcast_len_in[i] - wnum);
					}
					if (num < 0)
					{
						if ((errno == EWOULDBLOCK) || (errno == EINTR))
						{
							break;
						}
						else if (errno == EAGAIN)
						{
							perror("WARNING: tcpip_io (write)");
							break;
						}
						else
						{
							perror("ERROR: tcpip_io (write)");
							std::cerr << "DEBUG: broadcast_pipefd[" << i <<
								"][" << thisidx << "]" << std::endl;
							return -204;
						}
					}
					else
						wnum += num;
				}
				while (wnum < broadcast_len_in[i]);
				broadcast_len_in[i] -= wnum;
			}
		}
		for (size_t i = 0; i < peers.size(); i++)
		{
			size_t max = tcpip_pipe_buffer_size - len_out[i];
			if (FD_ISSET(pipefd[thisidx][i][0], &rfds) && (max > 0))
			{
				ssize_t len = read(pipefd[thisidx][i][0],
					buf_out[i] + len_out[i], max);
				if (len < 0)
				{
					if ((errno == EWOULDBLOCK) || (errno == EINTR))
					{
						continue;
					}
					else if (errno == EAGAIN)
					{
						perror("WARNING: tcpip_io (read)");
						continue;
					}
					else
					{
						perror("ERROR: tcpip_io (read)");
						return -203;
					}
				}
				else if (len == 0)
				{
					std::cerr << "ERROR: pipe to child collapsed" << std::endl;
					continue;
				}
				else if (tcpip_pipe2socket_out.count(i))
				{
					len_out[i] += len;
				}
				else
				{
					if (opt_verbose > 2)
					{
						std::cerr << "INFO: discarding " << len << " bytes" <<
							" for P_" << i << std::endl;
					}
				}
			}
			max = tcpip_pipe_buffer_size - broadcast_len_out[i];
			if (FD_ISSET(broadcast_pipefd[thisidx][i][0], &rfds))
			{
				ssize_t len = read(broadcast_pipefd[thisidx][i][0],
					broadcast_buf_out[i] + broadcast_len_out[i], max);
				if (len < 0)
				{
					if ((errno == EWOULDBLOCK) || (errno == EINTR))
					{
						continue;
					}
					else if (errno == EAGAIN)
					{
						perror("WARNING: tcpip_io (read)");
						continue;
					}
					else
					{
						perror("ERROR: tcpip_io (read)");
						return -203;
					}
				}
				else if (len == 0)
				{
					continue;
				}
				else if (tcpip_broadcast_pipe2socket_out.count(i))
				{
					broadcast_len_out[i] += len;
				}
				else
				{
					if (opt_verbose > 2)
					{
						std::cerr << "INFO: discarding " << len << " bytes" <<
							" for P_" << i << std::endl;
					}
				}
			}
		}
		for (size_t i = 0; i < peers.size(); i++)
		{
			if (tcpip_pipe2socket_out.count(i) == 0)
				continue;
			if (FD_ISSET(tcpip_pipe2socket_out[i], &wfds) && (len_out[i] > 0))
			{
				if (opt_verbose > 2)
				{
					std::cerr << "INFO: sending " << len_out[i] << " bytes" <<
						" on connection to P_" << i << std::endl;
				}
				size_t wnum = 0;
				do
				{
					ssize_t num = write(tcpip_pipe2socket_out[i],
						buf_out[i] + wnum,
						len_out[i] - wnum);
					if (num < 0)
					{
						if ((errno == EWOULDBLOCK) || (errno == EINTR))
						{
							break;
						}
						else if (errno == EAGAIN)
						{
							perror("WARNING: tcpip_io (write)");
							break;
						}
						else if ((errno == ECONNRESET) || (errno == EPIPE))
						{
							std::cerr << "WARNING: connection collapsed" <<
								" for P_" << i << std::endl;
							if (close(tcpip_pipe2socket_out[i]) < 0)
								perror("WARNING: tcpip_io (close)");
							tcpip_pipe2socket_out.erase(i);
							if (tcpip_reconnect(i, false))
							{
								std::cerr << "INFO: reconnect successful" <<
									std::endl;
								continue;
							}
							break;
						}
						else
						{
							perror("ERROR: tcpip_io (write)");
							std::cerr << "DEBUG: tcpip_pipe2socket_out[" <<
								i << "]" << std::endl;
							return -204;
						}
					}
					else
						wnum += num;
				}
				while (wnum < broadcast_len_out[i]);
				if (wnum > 0)
				{
					len_out[i] -= wnum;
					memmove(buf_out[i], buf_out[i] + wnum, len_out[i]);
				}
			}
			if (tcpip_broadcast_pipe2socket_out.count(i) == 0)
				continue;
			if (FD_ISSET(tcpip_broadcast_pipe2socket_out[i], &wfds) &&
				(broadcast_len_out[i] > 0))
			{
				if (opt_verbose > 2)
				{
					std::cerr << "INFO: sending " << broadcast_len_out[i] <<
						" bytes on broadcast connection to P_" << i <<
						std::endl;
				}
				size_t wnum = 0;
				do
				{
					ssize_t num = write(tcpip_broadcast_pipe2socket_out[i],
						broadcast_buf_out[i] + wnum,
						broadcast_len_out[i] - wnum);
					if (num < 0)
					{
						if ((errno == EWOULDBLOCK) || (errno == EINTR))
						{
							break;
						}
						else if (errno == EAGAIN)
						{
							perror("WARNING: tcpip_io (write)");
							break;
						}
						else if ((errno == ECONNRESET) || (errno == EPIPE))
						{
							std::cerr << "WARNING: broadcast connection" <<
								" collapsed for P_" << i << std::endl;
							if (close(tcpip_broadcast_pipe2socket_out[i]) < 0)
								perror("WARNING: tcpip_io (close)");
							tcpip_broadcast_pipe2socket_out.erase(i);
							if (tcpip_reconnect(i, true))
							{
								std::cerr << "INFO: reconnect successful" <<
									std::endl;
								continue;
							}
							break;
						}
						else
						{
							perror("ERROR: tcpip_io (write)");
							std::cerr << "DEBUG: tcpip_broadcast_pipe2" <<
								"socket_out[" << i << "]" << std::endl;
							return -204;
						}
					}
					else
						wnum += num;
				}
				while (wnum < broadcast_len_out[i]);
				if (wnum > 0)
				{
					broadcast_len_out[i] -= wnum;
					memmove(broadcast_buf_out[i], broadcast_buf_out[i] + wnum,
						broadcast_len_out[i]);
				}
			}
		}

		if (MHD_run_from_select(tcpip_mhd, &rfds, &wfds, NULL) != MHD_YES)
		{
			std::cerr << "ERROR: MHD_run_from_select() failed" << std::endl;
			return -205;
		}
	}
	sleep(5 * DOTS_TIME_POLL); // sleep few seconds to terminate gracefully
	return -206;
}

void tcpip_close
	()
{
	for (tcpip_mci_t pi = tcpip_pipe2socket_in.begin();
		pi != tcpip_pipe2socket_in.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("WARNING: tcpip_close (close)");
	}
	for (tcpip_mci_t pi = tcpip_pipe2socket_out.begin();
		pi != tcpip_pipe2socket_out.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("WARNING: tcpip_close (close)");
	}
	for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket_in.begin();
		pi != tcpip_broadcast_pipe2socket_in.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("WARNING: tcpip_close (close)");
	}
	for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket_out.begin();
		pi != tcpip_broadcast_pipe2socket_out.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("WARNING: tcpip_close (close)");
	}
	for (tcpip_mci_t pi = tcpip_pipe2socket.begin();
		pi != tcpip_pipe2socket.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("WARNING: tcpip_close (close)");
	}
	for (tcpip_mci_t pi = tcpip_broadcast_pipe2socket.begin();
		pi != tcpip_broadcast_pipe2socket.end(); ++pi)
	{
		if (close(pi->second) < 0)
			perror("WARNING: tcpip_close (close)");
	}
}

void tcpip_done
	()
{
	if (instance_forked)
	{
		int thispid = pid[tcpip_peer2pipe[tcpip_thispeer]];
		if (opt_verbose)
			std::cerr << "INFO: kill(" << thispid << ", SIGTERM)" << std::endl;
		if (kill(thispid, SIGTERM))
			perror("WARNING: tcpip_done (kill)");
		if (opt_verbose)
		{
			std::cerr << "INFO: waitpid(" << thispid << ", NULL, 0)" <<
				std::endl;
		}
		if (waitpid(thispid, NULL, 0) != thispid)
			perror("WARNING: tcpip_done (waitpid)");
	}
	for (size_t i = 0; i < peers.size(); i++)
	{
		for (size_t j = 0; j < peers.size(); j++)
		{
			if ((close(pipefd[i][j][0]) < 0) || (close(pipefd[i][j][1]) < 0))
				perror("WARNING: tcpip_done (close)");
			if ((close(broadcast_pipefd[i][j][0]) < 0) ||
				(close(broadcast_pipefd[i][j][1]) < 0))
			{
				perror("WARNING: tcpip_done (close)");
			}
		}
	}
	if ((close(self_pipefd[0]) < 0) || (close(self_pipefd[1]) < 0))
		perror("WARNING: tcpip_done (close)");
	if ((close(broadcast_self_pipefd[0]) < 0) ||
		(close(broadcast_self_pipefd[1]) < 0))
	{
		perror("WARNING: tcpip_done (close)");
	}
	MHD_stop_daemon(tcpip_mhd);
}

