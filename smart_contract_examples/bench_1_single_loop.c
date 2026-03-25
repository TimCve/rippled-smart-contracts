#include "smart_contract_abi.h"
#include <stdint.h>

#define GUARD(max_iters) _g(__LINE__, max_iters)

static volatile uint64_t sink;

__attribute__((export_name("entrypoint")))
int32_t
entrypoint(int64_t opt)
{
    uint64_t acc = (uint64_t)opt + 1u;

    for (uint32_t i = 0; i < 64; ++i)
    {
        GUARD(64);
        acc = (acc * 33u) ^ (uint64_t)(i + 1u);
    }

    sink = acc;
    return 0;
}
