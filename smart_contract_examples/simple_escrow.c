/*
Implementation of simple escrow system:
Escrow Creation:
- user specifies recipient and amount
- information about recipient and amount stored in escrow smart object
Escrow Claim:
- user specifies previously created escrow smart object
- money transferred to claimer's account
*/

#include "smart_contract_abi.h"
#include <stdint.h>

#define TRUE 1
#define FALSE 0

typedef struct PACKED {
    uint64_t amount;
    addr_t recipient;
} params1_t;

typedef struct PACKED {
    id256_t escrow_id;
} params2_t;

typedef struct PACKED {
    addr_t recipient;
    uint64_t amount;
} escrow_t;

_Static_assert(sizeof(params1_t) == 28, "params1_t size mismatch");
_Static_assert(sizeof(params2_t) == 32, "params2_t size mismatch");
_Static_assert(sizeof(escrow_t) == 28, "escrow_t size mismatch");

int32_t addr_eq(addr_t* a, addr_t* b) {
    if (((uint8_t*)a)[0] == ((uint8_t*)b)[0] && ((uint8_t*)a)[1] == ((uint8_t*)b)[1] &&
        ((uint8_t*)a)[2] == ((uint8_t*)b)[2] && ((uint8_t*)a)[3] == ((uint8_t*)b)[3] &&
        ((uint8_t*)a)[4] == ((uint8_t*)b)[4] && ((uint8_t*)a)[5] == ((uint8_t*)b)[5] &&
        ((uint8_t*)a)[6] == ((uint8_t*)b)[6] && ((uint8_t*)a)[7] == ((uint8_t*)b)[7] &&
        ((uint8_t*)a)[8] == ((uint8_t*)b)[8] && ((uint8_t*)a)[9] == ((uint8_t*)b)[9] &&
        ((uint8_t*)a)[10] == ((uint8_t*)b)[10] && ((uint8_t*)a)[11] == ((uint8_t*)b)[11] &&
        ((uint8_t*)a)[12] == ((uint8_t*)b)[12] && ((uint8_t*)a)[13] == ((uint8_t*)b)[13] &&
        ((uint8_t*)a)[14] == ((uint8_t*)b)[14] && ((uint8_t*)a)[15] == ((uint8_t*)b)[15] &&
        ((uint8_t*)a)[16] == ((uint8_t*)b)[16] && ((uint8_t*)a)[17] == ((uint8_t*)b)[17] &&
        ((uint8_t*)a)[18] == ((uint8_t*)b)[18] && ((uint8_t*)a)[19] == ((uint8_t*)b)[19])
        return TRUE;
    else return FALSE;
}

__attribute__((export_name("entrypoint")))
int32_t entrypoint(int64_t opt)
{
    if (!paramsPassed()) return -1;

    if (opt == 1) { // create escrow
        params1_t params;
        int32_t got = getParams((int32_t)&params, sizeof(params1_t));
        if(got != sizeof(params1_t)) return -2;
        
        escrow_t escrow;
        escrow.recipient = params.recipient;
        escrow.amount = params.amount;
        lockCallerXRP((int64_t)params.amount);

        id256_t escrow_id;
        createSmartObject((int32_t)&escrow, sizeof(escrow_t), (int32_t)&escrow_id);

    } else if (opt == 2) { // claim escrow
        params2_t params;
        int32_t got = getParams((int32_t)&params, sizeof(params2_t));
        if(got != sizeof(params2_t)) return -5;

        escrow_t escrow;
        int32_t sz = getSmartObjectData(
            (int32_t)&params.escrow_id,
            (int32_t)&escrow,
            (int32_t)sizeof(escrow_t));
        if(sz != sizeof(escrow_t)) return -6;
        
        addr_t caller;
        getCallerAddr((int32_t)&caller);

        if(addr_eq(&caller, &escrow.recipient)) {
            unlockXRP((int64_t)escrow.amount, (int32_t)&caller);
            
            deleteSmartObject((int32_t)&params.escrow_id);
        } else return -8;
    } else return -11;

    return 0;
}
