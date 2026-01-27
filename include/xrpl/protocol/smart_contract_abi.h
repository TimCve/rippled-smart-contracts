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

int32_t
getCallerAddr(int32_t a_ptr) WASM_IMPORT(SC_HOST_MOD, "getCallerAddr");

int32_t
getOwnerAddr(int32_t a_ptr) WASM_IMPORT(SC_HOST_MOD, "getOwnerAddr");

int32_t
escrowCallerXRP(int32_t id_ptr, int64_t amount)
    WASM_IMPORT(SC_HOST_MOD, "escrowCallerXRP");

int32_t
escrowOwnerXRP(int32_t id_ptr, int64_t amount)
    WASM_IMPORT(SC_HOST_MOD, "escrowOwnerXRP");

int32_t
releaseEscrowedXRP(int32_t id_ptr, int32_t dest_ptr)
    WASM_IMPORT(SC_HOST_MOD, "releaseEscrowedXRP");

int32_t
createState(int32_t data_ptr, int32_t data_len, int32_t id_ptr)
    WASM_IMPORT(SC_HOST_MOD, "createState");

int32_t
getState(int32_t id_ptr, int32_t out_ptr, int32_t out_len)
    WASM_IMPORT(SC_HOST_MOD, "getState");

int32_t
deleteState(int32_t id_ptr) WASM_IMPORT(SC_HOST_MOD, "deleteState");

int32_t
setState(int32_t id_ptr, int32_t data_ptr, int32_t data_len)
    WASM_IMPORT(SC_HOST_MOD, "setState");

int32_t
getParams(int32_t out_ptr, int32_t out_len)
    WASM_IMPORT(SC_HOST_MOD, "getParams");

int32_t
paramsPassed(void) WASM_IMPORT(SC_HOST_MOD, "paramsPassed");

#ifdef __cplusplus
}
#endif

#endif
