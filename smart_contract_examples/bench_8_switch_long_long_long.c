#include "smart_contract_abi.h"
#include <stdint.h>

#define GUARD(max_iters) _g(__LINE__, max_iters)

static volatile uint64_t sink;

__attribute__((export_name("entrypoint")))
int32_t
entrypoint(int64_t opt)
{
    uint64_t acc = 13u;

    switch ((int32_t)(opt % 3))
    {
        case 0:
            for (uint32_t i = 0; i < 120; ++i)
            {
                GUARD(120);
                acc = (acc * 17u) ^ (uint64_t)(i + 5u);
            }
            break;

        case 1:
            for (uint32_t i = 0; i < 120; ++i)
            {
                GUARD(120);
                acc = (acc * 11u) + (uint64_t)(i + 7u);
            }
            break;

        default:
            for (uint32_t i = 0; i < 120; ++i)
            {
                GUARD(120);
                acc = (acc + 3u) ^ (uint64_t)(i + 1u);
            }
            break;
    }

    sink = acc;
    return 0;
}
