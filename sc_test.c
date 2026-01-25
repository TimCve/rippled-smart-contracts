#include <stdint.h>
#include "include/xrpl/protocol/smart_contract_abi.h"

static int
addr_eq(addr_t const* a, addr_t const* b)
{
    for (uint32_t i = 0; i < ADDR_SIZE; ++i)
    {
        if (a->bytes[i] != b->bytes[i])
            return 0;
    }
    return 1;
}

__attribute__((export_name("entrypoint")))
int32_t
entrypoint(int32_t opt)
{
    (void)opt;

    addr_t caller;
    addr_t owner;

    if (get_caller((int32_t)&caller) != 0)
        return -1;
    if (get_owner((int32_t)&owner) != 0)
        return -2;

    if (!addr_eq(&caller, &owner))
    {
        if (pay((int32_t)&caller, 1) != 0)
            return -3;
    }

    return 0;
}
