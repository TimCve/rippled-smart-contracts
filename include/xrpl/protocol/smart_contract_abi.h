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

int32_t
get_caller(int32_t a_ptr) WASM_IMPORT(SC_HOST_MOD, "get_caller");

int32_t
get_owner(int32_t a_ptr) WASM_IMPORT(SC_HOST_MOD, "get_owner");

int32_t
pay(int32_t a_ptr, int64_t amount) WASM_IMPORT(SC_HOST_MOD, "pay");

#ifdef __cplusplus
}
#endif

#endif
