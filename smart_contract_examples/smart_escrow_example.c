#include "../include/xrpl/protocol/smart_contract_abi.h"
#include <stdint.h>

typedef struct PACKED
{
    uint32_t amount;
    addr_t recipient;
} params1_t;

typedef struct PACKED
{
    id256_t state_id;
} params2_t;

typedef struct PACKED
{
    addr_t recipient;
    uint32_t amount;
} state_t;

// TODO: move into ABI and include as standard
static int memeq(const void* a, const void* b, uint32_t n) {
    const uint8_t* p = (const uint8_t*)a;
    const uint8_t* q = (const uint8_t*)b;
    for (uint32_t i = 0; i < n; ++i) {
        if (p[i] != q[i]) return 0;
    }
    return 1;
}

__attribute__((export_name("entrypoint")))
int32_t entrypoint(int64_t opt)
{
    if (!paramsPassed()) return -1;

    // opt = 1 : create
    if (opt == 1) {
        params1_t params;
        int32_t got = getParams((int32_t)&params, (int32_t)sizeof(params1_t));
        if(got != (int32_t)sizeof(params1_t)) return -2;
        
        state_t state;
        state.recipient = params.recipient;
        state.amount = params.amount;
        if(lockCallerXRP((int32_t)params.amount) != 0)
            return -3;

        id256_t state_id;
        if(createState((int32_t)&state, (int32_t)sizeof(state_t), (int32_t)&state_id) != 0)
            return -4;

    // opt = 2 : claim
    } else if (opt == 2) {
        params2_t params;
        int32_t got = getParams((int32_t)&params, (int32_t)sizeof(params2_t));
        if(got != (int32_t)sizeof(params2_t)) return -5;

        state_t state;
        int32_t sz = getState((int32_t)&params.state_id, (int32_t)&state, sizeof(state_t));
        if(sz != (int32_t)sizeof(state_t)) return -6;
        
        addr_t caller;
        if(getCallerAddr((int32_t)&caller) != 0)
            return -7;

        if(memeq(&caller, &state.recipient, ADDR_SIZE)) {
            if(unlockXRP((int32_t)state.amount, (int32_t)&caller) != 0)
                return -9;
            
            if(deleteState((int32_t)&params.state_id) != 0)
                return -10;
        } else return -8;
    } else return -11;

    return 0;
}
