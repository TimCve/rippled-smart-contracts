#ifndef SMART_CONTRACT_ABI_H_INCLUDED
#define SMART_CONTRACT_ABI_H_INCLUDED

#include <stdint.h>

#define SC_HOST_MOD "host"

#define WASM_IMPORT(mod, name) __attribute__((import_module(mod), import_name(name)))
#define PACKED __attribute__((packed))

#define ADDR_SIZE 20u
#define ID256_SIZE 32u

typedef struct PACKED
{
    uint8_t bytes[20];
} addr_t;

typedef struct PACKED
{
    uint8_t bytes[32];
} id256_t;

void
_g(int32_t id, int32_t max_iters) WASM_IMPORT(SC_HOST_MOD, "_g");

#define MEMEQ(a, b, n) \
    ({ \
        const uint8_t* _a = (const uint8_t*)(a); \
        const uint8_t* _b = (const uint8_t*)(b); \
        uint32_t _n = (uint32_t)(n); \
        int _eq = 1; \
        for (uint32_t _i = 0; _i < _n; ++_i) { \
            if (_a[_i] != _b[_i]) { \
                _eq = 0; \
                break; \
            } \
        } \
        _eq; \
    })

int32_t  // seconds since 2000-01-01 00:00:00 UTC
getLedgerTimestamp(void) WASM_IMPORT(SC_HOST_MOD, "getLedgerTimestamp");

int32_t
getCallerAddr(int32_t a_ptr) WASM_IMPORT(SC_HOST_MOD, "getCallerAddr");

int32_t
getOwnerAddr(int32_t a_ptr) WASM_IMPORT(SC_HOST_MOD, "getOwnerAddr");

int32_t
getParams(int32_t out_ptr, int32_t out_len)
    WASM_IMPORT(SC_HOST_MOD, "getParams");

int32_t
paramsPassed(void) WASM_IMPORT(SC_HOST_MOD, "paramsPassed");

int32_t
lockCallerXRP(int32_t amount) WASM_IMPORT(SC_HOST_MOD, "lockCallerXRP");

int32_t
lockOwnerXRP(int32_t amount) WASM_IMPORT(SC_HOST_MOD, "lockOwnerXRP");

int32_t
unlockXRP(int32_t amount, int32_t account_ptr)
    WASM_IMPORT(SC_HOST_MOD, "unlockXRP");

int32_t
createSmartObject(int32_t data_ptr, int32_t data_len, int32_t id_ptr)
    WASM_IMPORT(SC_HOST_MOD, "createSmartObject");

int32_t
getSmartObject(int32_t id_ptr, int32_t out_ptr, int32_t out_len)
    WASM_IMPORT(SC_HOST_MOD, "getSmartObject");

int32_t
deleteSmartObject(int32_t id_ptr) WASM_IMPORT(SC_HOST_MOD, "deleteSmartObject");

int32_t
setSmartObject(int32_t id_ptr, int32_t data_ptr, int32_t data_len)
    WASM_IMPORT(SC_HOST_MOD, "setSmartObject");

#endif
