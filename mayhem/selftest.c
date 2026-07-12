/*
 * AUTHORED behavioral oracle for dislocker.
 *
 * Upstream ships NO real test suite: the only CMake "test" target (src/CMakeLists.txt
 * `travis-test`) merely runs each tool with `-h` and `man -w` — a smoke check that a
 * no-op / exit(0) sabotage would still pass. So this is an AUTHORED known-answer oracle
 * (tests_found=0). It asserts BEHAVIOR of the exact code exercised by the fuzz targets:
 *   - crc32() (encryption/crc32.c) against canonical CRC-32/ISO-HDLC vectors;
 *   - AES-XTS / AES-CBC / Elephant-diffuser encrypt<->decrypt round-trips
 *     (encryption/{encommon,encrypt,decrypt,diffuser,aes-xts}.c), verifying that
 *     decrypt(encrypt(x)) == x and that the ciphertext actually differs from x;
 *   - dis_crypt_set_fvekey() rejects an unsupported algorithm.
 *
 * Prints one "ok N - <name>" / "not ok N - <name>" line per assertion (TAP-ish) and
 * exits non-zero on any failure. Because it is a project binary under /mayhem, the
 * verify-repo sabotage neuter (_exit(0) before main) makes it emit nothing -> the
 * oracle is provably behavioral, not reward-hackable.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dislocker/encryption/crc32.h"
#include "dislocker/encryption/encommon.h"
#include "dislocker/encryption/encrypt.h"
#include "dislocker/encryption/decrypt.h"
#include "dislocker/return_values.h"

static int g_pass = 0;
static int g_fail = 0;

static void check(const char *name, int cond)
{
	if (cond) {
		g_pass++;
		printf("ok %d - %s\n", g_pass + g_fail, name);
	} else {
		g_fail++;
		printf("not ok %d - %s\n", g_pass + g_fail, name);
	}
}

/* Canonical CRC-32/ISO-HDLC (zlib) known-answer vectors. */
static void test_crc32(void)
{
	check("crc32 empty == 0x00000000",
	      crc32((const unsigned char *) "", 0) == 0x00000000u);
	check("crc32 \"123456789\" == 0xCBF43926",
	      crc32((const unsigned char *) "123456789", 9) == 0xCBF43926u);
	check("crc32 quick-brown-fox == 0x414FA339",
	      crc32((const unsigned char *)
	            "The quick brown fox jumps over the lazy dog", 43)
	          == 0x414FA339u);
}

#define SECTOR 512

/* encrypt then decrypt one sector; assert the round-trip is lossless and that the
 * ciphertext really differs from the plaintext (i.e. crypto actually ran). */
static void roundtrip(const char *name, uint16_t cipher)
{
	uint8_t fvekey[64];
	uint8_t plain[SECTOR], enc[SECTOR], dec[SECTOR];
	unsigned i;

	for (i = 0; i < sizeof(fvekey); i++)
		fvekey[i] = (uint8_t) (i * 7 + 1);
	for (i = 0; i < SECTOR; i++)
		plain[i] = (uint8_t) (i & 0xff);
	memset(enc, 0, sizeof(enc));
	memset(dec, 0, sizeof(dec));

	dis_crypt_t crypt = dis_crypt_new(SECTOR, cipher);
	if (!crypt) { check(name, 0); return; }

	if (dis_crypt_set_fvekey(crypt, cipher, fvekey) != DIS_RET_SUCCESS) {
		check(name, 0);
		dis_crypt_destroy(crypt);
		return;
	}

	encrypt_sector(crypt, plain, SECTOR, enc);
	decrypt_sector(crypt, enc, SECTOR, dec);

	int lossless = memcmp(plain, dec, SECTOR) == 0;
	int changed = memcmp(plain, enc, SECTOR) != 0;
	check(name, lossless && changed);

	dis_crypt_destroy(crypt);
}

static void test_set_fvekey_rejects_bad_algo(void)
{
	uint8_t fvekey[64] = {0};
	dis_crypt_t crypt = dis_crypt_new(SECTOR, AES_XTS_128);
	int rc = dis_crypt_set_fvekey(crypt, 0xdead, fvekey);
	check("dis_crypt_set_fvekey rejects unsupported algorithm",
	      rc == DIS_RET_ERROR_CRYPTO_ALGORITHM_UNSUPPORTED);
	dis_crypt_destroy(crypt);
}

int main(void)
{
	test_crc32();
	roundtrip("AES-XTS-128 round-trip", AES_XTS_128);
	roundtrip("AES-XTS-256 round-trip", AES_XTS_256);
	roundtrip("AES-CBC-128 (no diffuser) round-trip", AES_128_NO_DIFFUSER);
	roundtrip("AES-CBC-256 (no diffuser) round-trip", AES_256_NO_DIFFUSER);
	roundtrip("AES-CBC-128 + diffuser round-trip", AES_128_DIFFUSER);
	roundtrip("AES-CBC-256 + diffuser round-trip", AES_256_DIFFUSER);
	test_set_fvekey_rejects_bad_algo();

	printf("1..%d\n", g_pass + g_fail);
	printf("SELFTEST passed=%d failed=%d\n", g_pass, g_fail);
	fflush(stdout);
	return g_fail == 0 ? 0 : 1;
}
