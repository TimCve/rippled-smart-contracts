#include <stdint.h>
#include "../include/xrpl/protocol/smart_contract_abi.h"

static void* sc_memcpy(void* dst, const void* src, uint32_t n) {
    uint8_t* d = (uint8_t*)dst;
    const uint8_t* s = (const uint8_t*)src;
    for (uint32_t i = 0; i < n; ++i) d[i] = s[i];
    return dst;
}

static void sc_memset(void* dst, uint8_t v, uint32_t n) {
    uint8_t* d = (uint8_t*)dst;
    for (uint32_t i = 0; i < n; ++i) d[i] = v;
}

static int sc_memeq(const void* a, const void* b, uint32_t n) {
    const uint8_t* p = (const uint8_t*)a;
    const uint8_t* q = (const uint8_t*)b;
    for (uint32_t i = 0; i < n; ++i) {
        if (p[i] != q[i]) return 0;
    }
    return 1;
}

static uint64_t read_u64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= ((uint64_t)p[i]) << (8 * i);
    return v;
}

typedef struct __attribute__((packed)) {
    uint64_t amount;
    addr_t recipient;
    id256_t escrow_id;
} escrow_state_t;

__attribute__((export_name("entrypoint")))
int32_t entrypoint(int64_t opt)
{
    // opt: 1=create, 2=claim
    if (opt == 1) {
        if (!paramsPassed()) return -1;

        uint8_t params[8 + ADDR_SIZE];
        int32_t got = getParams((int32_t)params, (int32_t)sizeof(params));
        if (got != (int32_t)sizeof(params)) return -2;

        uint64_t amount = read_u64_le(params);
        if (amount == 0) return -3;

        addr_t recipient;
        sc_memcpy(&recipient, params + 8, ADDR_SIZE);

        // lock funds from caller
        id256_t escrow_id;
        if (escrowCallerXRP((int32_t)&escrow_id, (int64_t)amount) != 0)
            return -4;

        // store state with escrow reference + recipient
        escrow_state_t state;
        sc_memset(&state, 0, (uint32_t)sizeof(state));
        state.amount = amount;
        state.recipient = recipient;
        state.escrow_id = escrow_id;

        id256_t state_id;
        if (createState((int32_t)&state, (int32_t)sizeof(state),
                        (int32_t)&state_id) != 0)
            return -5;

        return 0;
    }

    if (opt == 2) {
        if (!paramsPassed()) return -10;

        id256_t state_id;
        int32_t got = getParams((int32_t)&state_id, ID256_SIZE);
        if (got != (int32_t)ID256_SIZE) return -11;

        escrow_state_t state;
        int32_t sz = getStateSize((int32_t)&state_id);
        if (sz != (int32_t)sizeof(state)) return -12;

        if (getState((int32_t)&state_id, (int32_t)&state, sz) != sz)
            return -13;

        addr_t caller;
        if (getCallerAddr((int32_t)&caller) != 0) return -14;

        if (!sc_memeq(&caller, &state.recipient, ADDR_SIZE)) return -15;

        // release escrow to caller
        if (releaseEscrowedXRP((int32_t)&state.escrow_id,
                                 (int32_t)&caller) != 0)
            return -16;

        // delete state
        if (deleteState((int32_t)&state_id) != 0) return -17;

        return 0;
    }

    return -100;
}
