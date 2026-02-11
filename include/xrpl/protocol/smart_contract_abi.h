#ifndef RIPPLE_PROTOCOL_SMART_CONTRACT_ABI_H_INCLUDED
#define RIPPLE_PROTOCOL_SMART_CONTRACT_ABI_H_INCLUDED

#include <stdint.h>

#define SC_HOST_MOD "host"

#if defined(__wasm__)
#define WASM_IMPORT(mod, name) __attribute__((import_module(mod), import_name(name)))
#else
#define WASM_IMPORT(mod, name)
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
#define PACKED __attribute__((packed))
#else
#define PACKED
#endif

void
_g(int32_t id, int32_t max_iters) WASM_IMPORT(SC_HOST_MOD, "_g");

typedef struct PACKED
{
    uint8_t bytes[20];
} addr_t;

#define ADDR_SIZE 20u

typedef struct PACKED
{
    uint8_t bytes[32];
} id256_t;

#define ID256_SIZE 32u

int32_t // seconds since 2000-01-01 00:00:00 UTC
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

#ifdef __cplusplus
}
#endif

#endif
