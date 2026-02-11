#include "smart_contract_abi.h"
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
        if(createSmartObject((int32_t)&state, (int32_t)sizeof(state_t), (int32_t)&state_id) != 0)
            return -4;

    // opt = 2 : claim
    } else if (opt == 2) {
        params2_t params;
        int32_t got = getParams((int32_t)&params, (int32_t)sizeof(params2_t));
        if(got != (int32_t)sizeof(params2_t)) return -5;

        state_t state;
        int32_t sz = getSmartObject((int32_t)&params.state_id, (int32_t)&state, sizeof(state_t));
        if(sz != (int32_t)sizeof(state_t)) return -6;
        
        addr_t caller;
        if(getCallerAddr((int32_t)&caller) != 0)
            return -7;

        if(MEMEQ(&caller, &state.recipient, ADDR_SIZE)) {
            if(unlockXRP((int32_t)state.amount, (int32_t)&caller) != 0)
                return -9;
            
            if(deleteSmartObject((int32_t)&params.state_id) != 0)
                return -10;
        } else return -8;
    } else return -11;

    return 0;
}
