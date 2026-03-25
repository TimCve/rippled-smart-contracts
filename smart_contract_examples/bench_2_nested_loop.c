#include "smart_contract_abi.h"
#include <stdint.h>

#define GUARD(max_iters) _g(__LINE__, max_iters)

static volatile uint64_t sink;

__attribute__((export_name("entrypoint")))
int32_t
entrypoint(int64_t opt)
{
    uint64_t acc = (uint64_t)opt + 7u;

    for (uint32_t outer = 0; outer < 64; ++outer)
    {
        GUARD(64);

        for (uint32_t inner = 0; inner < 64; ++inner)
        {
            GUARD(64);
            acc = (acc + (uint64_t)(outer + 1u)) ^ (uint64_t)(inner + 3u);
        }
    }

    sink = acc;
    return 0;
}
