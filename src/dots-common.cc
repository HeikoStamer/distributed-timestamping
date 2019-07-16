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

// include headers
#ifdef HAVE_CONFIG_H
	#include "dots_config.h"
#endif
#include "dots-common.hh"

bool dots_http_request
	(const std::string &hostname,
	 const uint16_t port,
	 const std::string &url,
	 std::string &content,
	 std::string &type,
	 const int opt_verbose)
{
	struct addrinfo h = { 0, 0, 0, 0, 0, 0, 0, 0 }, *r, *rp;
	h.ai_family = AF_UNSPEC;
	h.ai_socktype = SOCK_STREAM;
	h.ai_flags = AI_NUMERICSERV | AI_ADDRCONFIG;
	std::stringstream p;
	p << port;
	int ret, s = -1;
	if ((ret = getaddrinfo(hostname.c_str(), (p.str()).c_str(), &h, &r)) != 0)
	{
		std::cerr << "ERROR: resolving peer \"" << hostname << "\" failed: ";
		if (ret == EAI_SYSTEM)
			perror("dots_http_request (getaddrinfo)");
		else
			std::cerr << gai_strerror(ret);
		std::cerr << std::endl;
		return false;
	}
	for (rp = r; rp != NULL; rp = rp->ai_next)
	{
		if ((s = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol)) < 0)
		{
			perror("WARNING: dots_http_request (socket)");
			continue; // try next address
		}
		if (connect(s, rp->ai_addr, rp->ai_addrlen) < 0)
		{
			if (errno != ECONNREFUSED)
				perror("WARNING: dots_http_request (connect)");					
			if (close(s) < 0)
				perror("WARNING: dots_http_request (close)");
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
				std::cerr << "ERROR: resolving \"" << hostname << "\" failed: ";
				if (ret == EAI_SYSTEM)
					perror("dots_http_request (getnameinfo)");
				else
					std::cerr << gai_strerror(ret);
				std::cerr << std::endl;
				if (close(s) < 0)
					perror("WARNING: dots_http_request (close)");
				freeaddrinfo(r);
				return false;
			}
			if (opt_verbose > 2)
			{
				std::cerr << "INFO: resolved hostname \"" <<
					hostname << "\" to address " << hbuf << std::endl;
			}
			if (opt_verbose > 2)
			{
				std::cerr << "INFO: connected to host \"" <<
					hostname << "\" on port " << port << std::endl;
			}
			break; // on success: leave the loop
		}
	}
	freeaddrinfo(r);
	std::stringstream req;
	req << "GET " << url << " HTTP/1.1" << "\r\n" <<
		"Host: " << hostname << "\r\n" <<
		"Connection: close" << "\r\n\r\n";
	size_t len = (req.str()).length();
	char buf[4096];
	if (len > sizeof(buf))
	{
		std::cerr << "ERROR: HTTP request buffer exceeded" << std::endl;
		if (close(s) < 0)
			perror("WARNING: dots_http_request (close)");
		return false;
	}
	memcpy(buf, (req.str()).c_str(), len);
	size_t wnum = 0;
	do
	{
		ssize_t num = write(s, buf + wnum, len - wnum);
		if (num < 0)
		{
			if ((errno == EWOULDBLOCK) || (errno == EINTR) || (errno == EAGAIN))
			{
				if (opt_verbose > 2)
				{
					std::cerr << "INFO: sleeping for a change ..." << std::endl;
					sleep(1);
					continue;
				}
			}
			else if (errno == ECONNRESET)
			{
				std::cerr << "ERROR: HTTP connection collapsed" << std::endl;
				if (close(s) < 0)
					perror("WARNING: dots_http_request (close)");
				return false;
			}
			else
			{
				perror("ERROR: dots_http_request (write)");
				if (close(s) < 0)
					perror("WARNING: dots_http_request (close)");
				return false;
			}
		}
		else
			wnum += num;
	}
	while (wnum < len);
	std::stringstream response;
	do
	{
		memset(buf, 0, sizeof(buf));
		ssize_t num = read(s, buf, sizeof(buf) - 1);
		if (num < 0)
		{
			if ((errno == EWOULDBLOCK) || (errno == EINTR) || (errno == EAGAIN))
			{
				if (opt_verbose > 2)
				{
					std::cerr << "INFO: sleeping for a change ..." << std::endl;
					sleep(1);
					continue;
				}
			}
			else if (errno == ECONNRESET)
			{
				std::cerr << "ERROR: HTTP connection collapsed" << std::endl;
				if (close(s) < 0)
					perror("WARNING: dots_http_request (close)");
				return false;
			}
			else
			{
				perror("ERROR: dots_http_request (read)");
				if (close(s) < 0)
					perror("WARNING: dots_http_request (close)");
				return false;
			}
		}
		else if (num == 0)
		{
			break; // HTTP connection closed by server -- leave the loop
		}
		response << buf;
	}
	while (1);
	content = response.str();
	size_t ct_pos = content.find("Content-Type: ", 0);
	if (ct_pos != content.npos)
	{
		size_t ct_end = content.find("\r\n", ct_pos);
		if (ct_end != content.npos)
			type = content.substr(ct_pos + 14, ct_end - ct_pos - 14);
	}
	size_t body_pos = content.find("\r\n\r\n", 0);
	if (body_pos == content.npos)
	{
		std::cerr << "ERROR: no HTTP body found" << std::endl;
		if (close(s) < 0)
			perror("WARNING: dots_http_request (close)");
		return false;
	}
	content = content.substr(body_pos + 4, content.length() - body_pos - 4);
	if (close(s) < 0)
		perror("WARNING: dots_http_request (close)");
	return true;
}

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
	 const int opt_verbose)
{
	int pipe1fd[2], pipe2fd[2], pipe3fd[2];
	if ((pipe(pipe1fd) < 0) || (pipe(pipe2fd) < 0) || (pipe(pipe3fd) < 0))
	{
		perror("ERROR: dots_start_process (pipe)");
		return false;
	}
	else if ((pid = fork()) < 0)
	{
		perror("ERROR: dots_start_process (fork)");
		return false;
	}
	else
	{
		if (pid == 0)
		{
			/* BEGIN child code (execute program) */
			if ((dup2(pipe1fd[0], fileno(stdin)) < 0) ||
				(dup2(pipe2fd[1], fileno(stdout)) < 0) ||
				(dup2(pipe3fd[1], fileno(stderr)) < 0))
			{
				perror("ERROR: dots_start_process (dup2)");
				exit(-1);
			}
			if ((close(pipe1fd[0]) < 0) || (close(pipe1fd[1]) < 0) ||
				(close(pipe2fd[0]) < 0) || (close(pipe2fd[1]) < 0) ||
				(close(pipe3fd[0]) < 0) || (close(pipe3fd[1]) < 0))
			{
				perror("ERROR: dots_start_process (close)");
				exit(-1);
			}
			std::stringstream ifilename;
			ifilename << "dotsd_" << hostname << "_" << sn << ".asc";
			std::string url = "/signature?sn=" + sn;
			std::string type, signature;
			if (dots_http_request(lh, port, url, signature, type, opt_verbose))
			{
				if (type != "application/pgp-signature")
				{
					std::cerr << "ERROR: invalid content type" << std::endl;
					exit(-1);
				}
				std::ofstream ofs((ifilename.str()).c_str(), 
					std::ofstream::out | std::ofstream::trunc);
				if (!ofs.is_open() || !ofs.good())
				{
					std::cerr << "ERROR: cannot open input file" << std::endl;
					exit(-1);
				}
				ofs << signature;
				if (!ofs.good())
				{
					ofs.close();
					std::cerr << "ERROR: writing to file failed" <<std::endl;
					exit(-1);
				}
				ofs.close();
			}
			else
			{
				std::cerr << "ERROR: HTTP request failed" << std::endl;
				exit(-1);
			}
			std::stringstream ofilename;
			ofilename << "dotsd_" << hostname << "_" << sn << "_stamp";
			std::vector<std::string> dkgpg_args;
			dkgpg_args.push_back(cmd); //
			dkgpg_args.push_back("-V"); // -V
dkgpg_args.push_back("-V"); // -V FIXME: remove because output may contain secrets
			dkgpg_args.push_back("-a"); // -a
			std::stringstream serial;
			serial << "serialnumber@" << lh << ":" << sn;
			dkgpg_args.push_back("-s"); // -s
			dkgpg_args.push_back(serial.str());
			if (opt_W != 5)
			{
				std::stringstream tmp;
				tmp << opt_W;
				dkgpg_args.push_back("-W"); // -W INTEGER
				dkgpg_args.push_back(tmp.str());
			}
			if (uri.length() > 0)
			{
				dkgpg_args.push_back("-U"); // -U STRING
				dkgpg_args.push_back(uri);
			}
			dkgpg_args.push_back("-i"); // -i STRING
			dkgpg_args.push_back(ifilename.str());
			dkgpg_args.push_back("-o"); // -o STRING
			dkgpg_args.push_back(ofilename.str());
			if (passwords.length() > 0)
			{
				dkgpg_args.push_back("-P"); // -P STRING
				dkgpg_args.push_back(passwords);
			}
			if (hostname.length() > 0)
			{
				dkgpg_args.push_back("-H"); // -H STRING
				dkgpg_args.push_back(hostname);
			}
			for (size_t i = 0; i < peers.size(); i++)
				dkgpg_args.push_back(peers[i]); // PEERS
			char *dkgpg_arg[dkgpg_args.size() + 1];
			for (size_t i = 0; i < dkgpg_args.size(); i++)
			{
				dkgpg_arg[i] = (char*)dkgpg_args[i].c_str();
				dkgpg_arg[i+1] = NULL;
			}
			if (execve(cmd.c_str(), dkgpg_arg, envp) < 0)
			{
				perror("ERROR: dots_start_process (execve)");
				exit(-1);
			}
			/* END child code (execute program) */
		}
		else
		{
			forked = true;
			forked_time = time(NULL);
			if (opt_verbose)
			{
				std::cerr << "INFO: executed \"" << cmd << "\"" <<
					" (pid = " << pid << ") at " << forked_time << std::endl;
			}
			if ((close(pipe1fd[0]) < 0) ||
				(close(pipe2fd[1]) < 0) ||
				(close(pipe3fd[1]) < 0))
			{
				perror("ERROR: dots_start_process (close)");
				return false;
			}
			// save required file descriptors for stdin, stdout, and stderr
			fd_in = pipe1fd[1], fd_out = pipe2fd[0], fd_err = pipe3fd[0];
		}
	}
	return true;
}

void dots_kill_process
	(const pid_t pid,
	 const int sig,
	 const int opt_verbose)
{
	if (opt_verbose)
		std::cerr << "INFO: kill(" << pid << ", " << sig << ")" << std::endl;
	if (kill(pid, sig))
		perror("WARNING: dots_kill_process (kill)");
}

gcry_error_t encrypt_kek
	(const tmcg_openpgp_octets_t &kek, const tmcg_openpgp_skalgo_t algo,
	 const tmcg_openpgp_secure_octets_t &key, tmcg_openpgp_octets_t &out)
{
	gcry_error_t ret = 0;
	size_t bs = CallasDonnerhackeFinneyShawThayerRFC4880::
		AlgorithmIVLength(algo); // get block size of algorithm
	size_t ks = CallasDonnerhackeFinneyShawThayerRFC4880::
		AlgorithmKeyLength(algo); // get key size of algorithm
	if ((bs == 0) || (ks == 0))
		return gcry_error(GPG_ERR_CIPHER_ALGO); // error: bad algorithm
	size_t buflen = (kek.size() >= key.size()) ? kek.size() : key.size();
	unsigned char *buf = (unsigned char*)gcry_malloc_secure(buflen);
	if (buf == NULL)
		return gcry_error(GPG_ERR_RESOURCE_LIMIT); // cannot alloc secure memory
	gcry_cipher_hd_t hd;
	ret = gcry_cipher_open(&hd, CallasDonnerhackeFinneyShawThayerRFC4880::
		AlgorithmSymGCRY(algo), GCRY_CIPHER_MODE_CFB, GCRY_CIPHER_SECURE);
	if (ret)
	{
		gcry_free(buf);
		return ret;
	}
	for (size_t i = 0; i < key.size(); i++)
		buf[i] = key[i];
	ret = gcry_cipher_setkey(hd, buf, key.size());
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	// set "an IV of all zeros" [RFC 4880]
	ret = gcry_cipher_setiv(hd, NULL, 0);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	for (size_t i = 0; i < kek.size(); i++)
		buf[i] = kek[i];
	ret = gcry_cipher_encrypt(hd, buf, kek.size(), NULL, 0);
	if (ret)
	{
		gcry_free(buf);
		gcry_cipher_close(hd);
		return ret;
	}
	for (size_t i = 0; i < kek.size(); i++)
		out.push_back(buf[i]);
	gcry_free(buf);
	gcry_cipher_close(hd);
	return ret;
}

bool dots_encrypt_fuzzy
	(const std::string &in, const tmcg_openpgp_secure_string_t &passphrase,
	 std::string &out, const tmcg_openpgp_byte_t count)
{
	tmcg_openpgp_octets_t msg;
	for (size_t i = 0; i < in.length(); i++)
		msg.push_back(in[i]);
	msg.push_back('\n'); // append a newline character
	// encrypt the provided message and create MDC packet
	gcry_error_t ret;
	tmcg_openpgp_octets_t lit, prefix, enc;
	tmcg_openpgp_secure_octets_t seskey;
	tmcg_openpgp_skalgo_t skalgo = TMCG_OPENPGP_SKALGO_AES256;
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketLitEncode(msg, lit);
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::
		SymmetricEncryptAES256(lit, seskey, prefix, true, enc); // prepare
	if (ret)
	{
		std::cerr << "ERROR: SymmetricEncryptAES256() failed (rc = " <<
			gcry_err_code(ret) << ")" << std::endl;
		return false;
	}
	tmcg_openpgp_octets_t mdc_hashing, hash, mdc, seipd;
	enc.clear();
	mdc_hashing.insert(mdc_hashing.end(), prefix.begin(), prefix.end());
	mdc_hashing.insert(mdc_hashing.end(), lit.begin(), lit.end());
	mdc_hashing.push_back(0xD3);
	mdc_hashing.push_back(0x14);
	hash.clear();
	CallasDonnerhackeFinneyShawThayerRFC4880::
		HashCompute(TMCG_OPENPGP_HASHALGO_SHA1, mdc_hashing, hash);
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketMdcEncode(hash, mdc);
	lit.insert(lit.end(), mdc.begin(), mdc.end()); // append MDC packet
	// generate a fresh session key, but keep the previous prefix
	seskey.clear();
	ret = CallasDonnerhackeFinneyShawThayerRFC4880::
		SymmetricEncryptAES256(lit, seskey, prefix, false, enc); // encrypt
	if (ret)
	{
		std::cerr << "ERROR: SymmetricEncryptAES256() failed (rc = " <<
			gcry_err_code(ret) << ")" << std::endl;
		return false;
	}
	CallasDonnerhackeFinneyShawThayerRFC4880::PacketSeipdEncode(enc, seipd);
	// encrypt session key with passphrase according to S2K
	tmcg_openpgp_octets_t plain, salt, iv, es;
	tmcg_openpgp_hashalgo_t s2k_hashalgo = TMCG_OPENPGP_HASHALGO_SHA512;
	tmcg_openpgp_byte_t rand[8];
	tmcg_openpgp_secure_octets_t kek;
	gcry_randomize(rand, sizeof(rand), GCRY_STRONG_RANDOM);
	for (size_t i = 0; i < sizeof(rand); i++)
		salt.push_back(rand[i]);
	CallasDonnerhackeFinneyShawThayerRFC4880::
		S2KCompute(s2k_hashalgo, 32, passphrase, salt, true, count, kek);
	if ((seskey.size() == 35) && (kek.size() == 32))
	{
		// strip the always appended checksum from session key
		plain.insert(plain.end(), seskey.begin(), seskey.end()-2);
	}
	else
	{
		std::cerr << "ERROR: bad session key for SKESK" << std::endl;
		return false;
	}
	ret = encrypt_kek(plain, skalgo, kek, es);
	if (ret)
	{
		std::cerr << "ERROR: encrypt_kek() failed (rc = " <<
			gcry_err_code(ret) << ")" << std::endl;
		return false;
	}
	// create one valid SKESK packet and a lot of false (dummy) SKESK packets
	tmcg_openpgp_byte_t salt2[salt.size()], rand2[es.size() + 1];
	gcry_randomize(salt2, sizeof(salt2), GCRY_STRONG_RANDOM);
	gcry_randomize(rand2, sizeof(rand2), GCRY_STRONG_RANDOM);
	tmcg_openpgp_octets_t all;
	for (size_t i = 0; i < 256; i++)
	{
		CallasDonnerhackeFinneyShawThayerRFC4880::PacketTagEncode(3, all);
		CallasDonnerhackeFinneyShawThayerRFC4880::
			PacketLengthEncode(5+salt.size()+es.size(), all);
		all.push_back(4); // V4 format
		all.push_back(skalgo);
		all.push_back(TMCG_OPENPGP_STRINGTOKEY_ITERATED); // Iterated+Salted
		all.push_back(s2k_hashalgo); // S2K hash algo
		if (i == rand2[es.size()])
			all.insert(all.end(), salt.begin(), salt.end()); // valid salt
		else
		{
			for (size_t j = 0; j < salt.size(); j++)
				all.push_back(salt2[j]); // dummy salt
			gcry_randomize(salt2, sizeof(salt2), GCRY_STRONG_RANDOM);
		}
		all.push_back(count); // count, a one-octet, coded value
		if (i == rand2[es.size()])
			all.insert(all.end(), es.begin(), es.end()); // valid key
		else
		{
			for (size_t j = 0; j < es.size(); j++)
				all.push_back(rand2[j]); // dummy key
			gcry_randomize(rand2, sizeof(rand2) - 1, GCRY_STRONG_RANDOM);
		}
	}
	// append SEIPD packet
	all.insert(all.end(), seipd.begin(), seipd.end());
	// encode all packages in ASCII armor
	CallasDonnerhackeFinneyShawThayerRFC4880::
		ArmorEncode(TMCG_OPENPGP_ARMOR_MESSAGE, all, out);
	return true;
}

