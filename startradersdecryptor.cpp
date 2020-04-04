/*
	startradersdecryptor - Star Traders: Frontiers database decryptor
	Copyright (C) 2020-2020 Johannes Bauer

	This file is part of startradersdecryptor.

	startradersdecryptor is free software; you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation; this program is ONLY licensed under
	version 3 of the License, later versions are explicitly excluded.

	startradersdecryptor is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with startradersdecryptor; if not, write to the Free Software
	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

	Johannes Bauer <JohannesBauer@gmx.de>
*/

#include <stdio.h>
#include <botan/rng.h>
#include <botan/auto_rng.h>
#include <botan/cipher_mode.h>
#include <botan/hex.h>
#include <botan/pbkdf2.h>
#include <botan/cmac.h>
#include <stdint.h>
#include <vector>

#define SQLITE_PAGESIZE		1024

static std::vector<uint8_t> read_infile(const std::string &infile) {
	std::vector<uint8_t> contents;
	FILE *f = fopen(infile.c_str(), "r");
	if (!f) {
		perror(infile.c_str());
		exit(EXIT_FAILURE);
	}
	while (true) {
		uint8_t chunk[1024 * 1024];
		size_t len = fread(chunk, 1, sizeof(chunk), f);
		if (len < 0) {
			perror("fread");
			exit(EXIT_FAILURE);
		} else if (len == 0) {
			break;
		}
		contents.insert(contents.end(), chunk, chunk + len);
	}
	fclose(f);
	return contents;
}

static void write_outfile(const std::string &outfile, std::vector<uint8_t> &contents) {
	FILE *f = fopen(outfile.c_str(), "w");
	if (!f) {
		perror(outfile.c_str());
		exit(EXIT_FAILURE);
	}
	if (fwrite(&contents[0], 1, contents.size(), f) != contents.size()) {
		fprintf(stderr, "%s: short write\n", outfile.c_str());
	}
	fclose(f);
}

static std::vector<uint8_t> get_master_key(const std::string &keyname) {
	if (keyname == "core") {
		return Botan::hex_decode("41376f23566d29655473335b5f4b6675");
	} else if (keyname == "data") {
		return Botan::hex_decode("5654384b6a5f342d644631312e336e2c");
	} else if (keyname == "unknown") {
		return Botan::hex_decode("6674384b7172342d6446745662676363");
	} else if (keyname == "game") {
		return Botan::hex_decode("4239294b54466771235f2464342c6445");
	} else if (keyname == "map") {
		return Botan::hex_decode("444a3256682d355f446634342c345821");
	} else {
		fprintf(stderr, "Unknown key name: %s\n", keyname.c_str());
		exit(EXIT_FAILURE);
	}
}

static Botan::secure_vector<uint8_t> get_iv(const std::vector <uint8_t> &cmac_key, unsigned int pageno) {
	std::vector<uint8_t> cmac_data;
	cmac_data.resize(4);
	cmac_data[0] = (pageno >> 0) & 0xff;
	cmac_data[1] = (pageno >> 8) & 0xff;
	cmac_data[2] = (pageno >> 16) & 0xff;
	cmac_data[3] = (pageno >> 24) & 0xff;

	std::unique_ptr<Botan::MessageAuthenticationCode> cmac = Botan::MessageAuthenticationCode::create("CMAC(Twofish)");
	cmac->set_key(cmac_key);
	cmac->update(cmac_data);
	return cmac->final();
}

int main(int argc, char **argv) {
	if (argc != 4) {
		fprintf(stderr, "%s [keyname] [infile] [outfile]\n", argv[0]);
		fprintf(stderr, "   keyname can be one of 'core', 'data', 'game' or 'map'.\n");
		fprintf(stderr, "   example: %s core ~/.config/startraders2/core.db core_decrypted.db\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	std::string keyname(argv[1]);
	std::string infilename(argv[2]);
	std::string outfilename(argv[3]);

	std::vector<uint8_t> infile = read_infile(infilename);
	fprintf(stderr, "Read %lu bytes.\n", infile.size());
	if ((infile.size() % SQLITE_PAGESIZE) != 0) {
		fprintf(stderr, "Warning: file size %lu not evenly divisible by page size %d -- truncating file.\n", infile.size(), SQLITE_PAGESIZE);
	}

	const std::vector<uint8_t> master_key = get_master_key(keyname);
	const std::vector<uint8_t> salt = Botan::hex_decode("2444335e472e385b");

	uint8_t dkey[80];
	const Botan::PBKDF* kdf = Botan::get_pbkdf("PBKDF2(SHA-1)");
	kdf->pbkdf_iterations(dkey, sizeof(dkey), std::string(master_key.begin(), master_key.end()), &salt[0], salt.size(), 128);

	std::vector<uint8_t> xts_key(dkey, dkey + 64);
	std::vector<uint8_t> cmac_key(dkey + 64, dkey + 80);
	printf("XTS key     : %s\n", Botan::hex_encode(xts_key).c_str());
	printf("CMAC key    : %s\n", Botan::hex_encode(cmac_key).c_str());

	std::vector<uint8_t> plaintext;
	for (unsigned int pageindex = 0; pageindex < infile.size() / 1024; pageindex++) {
		const unsigned int pageno = pageindex + 1;
		Botan::secure_vector<uint8_t> page(infile.begin() + (1024 * pageindex), infile.begin() + (1024 * (pageindex + 1)));
		Botan::secure_vector<uint8_t> iv = get_iv(cmac_key, pageno);
		//printf("page #%-3d IV: %s\n", pageno, Botan::hex_encode(iv).c_str());

		std::unique_ptr<Botan::Cipher_Mode> dec = Botan::Cipher_Mode::create("Twofish/XTS/Nopadding", Botan::DECRYPTION);
		dec->set_key(xts_key);
		dec->start(iv);
		dec->finish(page);

		plaintext += page;
	}

	write_outfile(outfilename, plaintext);
}
