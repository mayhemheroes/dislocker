/*
 * In-process libFuzzer harness for dislocker's sector crypto layer.
 *
 * Target name: dis-crypt-new (kept from the original integration). The original
 * harness only called dis_crypt_new() — an allocate-and-return stub, a handful of
 * edges. This broadens the SAME code path (encryption/encommon.c) to actually drive
 * the AES-XTS / AES-CBC / Elephant-diffuser sector-decryption implementations
 * (encryption/decrypt.c, diffuser.c, aes-xts.c) over fuzzer-controlled key + sector
 * bytes, which is where the interesting parsing/arithmetic lives.
 *
 * Layout of the fuzz input:
 *   byte 0            cipher selector (mod #ciphers)
 *   bytes 1..64       64-byte FVEK material (dis_crypt_set_fvekey reads up to 0x40)
 *   bytes 65..        ciphertext sector bytes (truncated/zero-padded to SECTOR_SIZE)
 */
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// dislocker's headers carry no extern "C" guards; wrap them so the C library
// symbols keep C linkage when compiled as C++ (no upstream header edits needed).
extern "C" {
#include "dislocker/encryption/encommon.h"
#include "dislocker/encryption/decrypt.h"
#include "dislocker/return_values.h"
}

/* BitLocker's on-disk sector size; fixed so decrypt_xts's (addr / sector_size)
 * can never divide by zero and the diffuser's per-sector loops stay in bounds. */
#define SECTOR_SIZE 512
#define FVEK_LEN    64

static const uint16_t kCiphers[] = {
	AES_128_DIFFUSER, AES_256_DIFFUSER,
	AES_128_NO_DIFFUSER, AES_256_NO_DIFFUSER,
	AES_XTS_128, AES_XTS_256,
};

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	if (size < 1 + FVEK_LEN)
		return 0;

	uint16_t cipher = kCiphers[data[0] % (sizeof(kCiphers) / sizeof(kCiphers[0]))];

	uint8_t fvekey[FVEK_LEN];
	memcpy(fvekey, data + 1, FVEK_LEN);

	const uint8_t *rest = data + 1 + FVEK_LEN;
	size_t rest_size = size - (1 + FVEK_LEN);

	dis_crypt_t crypt = dis_crypt_new(SECTOR_SIZE, cipher);
	if (!crypt)
		return 0;

	if (dis_crypt_set_fvekey(crypt, cipher, fvekey) == DIS_RET_SUCCESS) {
		uint8_t *sector = (uint8_t *) calloc(1, SECTOR_SIZE);
		uint8_t *out = (uint8_t *) calloc(1, SECTOR_SIZE);
		if (sector && out) {
			size_t n = rest_size < SECTOR_SIZE ? rest_size : SECTOR_SIZE;
			memcpy(sector, rest, n);
			off_t addr = (off_t) SECTOR_SIZE; /* one sector in */
			decrypt_sector(crypt, sector, addr, out);
		}
		free(sector);
		free(out);
	}

	dis_crypt_destroy(crypt);
	return 0;
}
