#include <stdint.h>
#include <stdio.h>
#include <climits>

#include <fuzzer/FuzzedDataProvider.h>

#include "encommon.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    uint16_t sector_size = provider.ConsumeIntegral<uint16_t>();
    uint16_t cipher = provider.ConsumeIntegral<uint16_t>();
    dis_crypt_new(sector_size, cipher);

    return 0;
}