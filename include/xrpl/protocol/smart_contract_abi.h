#ifndef RIPPLE_PROTOCOL_SMART_CONTRACT_ABI_H_INCLUDED
#define RIPPLE_PROTOCOL_SMART_CONTRACT_ABI_H_INCLUDED

#include <cstdint>

namespace ripple {

inline constexpr char SC_HOST_MOD[] = "host";

inline constexpr std::uint32_t ADDR_SIZE = 20u;
inline constexpr std::uint32_t ID256_SIZE = 32u;
inline constexpr std::uint32_t HASH256_WORDS = 4u;
inline constexpr std::uint32_t HASH256_SIZE = 32u;

struct addr_t
{
    std::uint8_t bytes[ADDR_SIZE];
};

struct id256_t
{
    std::uint8_t bytes[ID256_SIZE];
};

struct hash256_t
{
    std::uint64_t words[HASH256_WORDS];
};

// Size/alignment checks catch ABI drift and prevent unaligned uint64_t access.
static_assert(sizeof(addr_t) == ADDR_SIZE, "addr_t size mismatch");
static_assert(sizeof(id256_t) == ID256_SIZE, "id256_t size mismatch");
static_assert(sizeof(hash256_t) == HASH256_SIZE, "hash256_t size mismatch");
static_assert(
    alignof(hash256_t) >= alignof(std::uint64_t),
    "hash256_t alignment must allow uint64_t access");

}  // namespace ripple

#endif
