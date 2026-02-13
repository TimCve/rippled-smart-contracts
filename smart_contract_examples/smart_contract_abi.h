#ifndef SMART_CONTRACT_ABI_H_INCLUDED
#define SMART_CONTRACT_ABI_H_INCLUDED

#include <stdint.h>

#define SC_HOST_MOD "host"

#define WASM_IMPORT(mod, name) __attribute__((import_module(mod), import_name(name)))

#define ADDR_SIZE 20u
#define ID256_SIZE 32u
#define HASH256_WORDS 4u
#define HASH256_SIZE 32u

typedef struct
{
    uint8_t bytes[ADDR_SIZE];
} addr_t;

typedef struct
{
    uint8_t bytes[ID256_SIZE];
} id256_t;

typedef struct
{
    uint64_t words[HASH256_WORDS];
} hash256_t;

void
_g(int32_t id, int32_t max_iters) WASM_IMPORT(SC_HOST_MOD, "_g");

int32_t  // seconds since 2000-01-01 00:00:00 UTC
getLedgerTimestamp(void) WASM_IMPORT(SC_HOST_MOD, "getLedgerTimestamp");

void
sha256(int32_t data_ptr, int32_t data_len, int32_t out_ptr)
    WASM_IMPORT(SC_HOST_MOD, "sha256");

void
getCallerAddr(int32_t a_ptr) WASM_IMPORT(SC_HOST_MOD, "getCallerAddr");

void
getOwnerAddr(int32_t a_ptr) WASM_IMPORT(SC_HOST_MOD, "getOwnerAddr");

void
getContractId(int32_t id_ptr) WASM_IMPORT(SC_HOST_MOD, "getContractId");

int64_t
getContractBalance(void) WASM_IMPORT(SC_HOST_MOD, "getContractBalance");

int32_t
getParams(int32_t out_ptr, int32_t out_len)
    WASM_IMPORT(SC_HOST_MOD, "getParams");

int32_t
paramsPassed(void) WASM_IMPORT(SC_HOST_MOD, "paramsPassed");

void
lockCallerXRP(int32_t amount) WASM_IMPORT(SC_HOST_MOD, "lockCallerXRP");

void
lockOwnerXRP(int32_t amount) WASM_IMPORT(SC_HOST_MOD, "lockOwnerXRP");

void
unlockXRP(int32_t amount, int32_t account_ptr)
    WASM_IMPORT(SC_HOST_MOD, "unlockXRP");

void
createSmartObject(int32_t data_ptr, int32_t data_len, int32_t id_ptr)
    WASM_IMPORT(SC_HOST_MOD, "createSmartObject");

int32_t
// OWNER ADDRESS (20 bytes) + DATA
getSmartObject(int32_t id_ptr, int32_t out_ptr, int32_t out_len)
    WASM_IMPORT(SC_HOST_MOD, "getSmartObject");

int32_t
getSmartObjectData(int32_t id_ptr, int32_t out_ptr, int32_t out_len)
    WASM_IMPORT(SC_HOST_MOD, "getSmartObjectData");

void
deleteSmartObject(int32_t id_ptr) WASM_IMPORT(SC_HOST_MOD, "deleteSmartObject");

void
setSmartObject(int32_t id_ptr, int32_t data_ptr, int32_t data_len)
    WASM_IMPORT(SC_HOST_MOD, "setSmartObject");

#endif
