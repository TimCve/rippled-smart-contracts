#ifndef RIPPLE_PROTOCOL_SMART_CONTRACT_ABI_H_INCLUDED
#define RIPPLE_PROTOCOL_SMART_CONTRACT_ABI_H_INCLUDED

#include <cstdint>

namespace ripple {

inline constexpr char SC_HOST_MOD[] = "host";

inline constexpr std::uint32_t ADDR_SIZE = 20u;
inline constexpr std::uint32_t ID256_SIZE = 32u;
inline constexpr std::uint32_t HASH256_WORDS = 4u;
inline constexpr std::uint32_t HASH256_SIZE = 32u;
inline constexpr std::uint32_t SMART_OBJECT_VIEW_PREFIX_SIZE = ADDR_SIZE;

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

// Prefix returned by host.getSmartObject before object payload bytes.
struct smart_object_view_prefix_t
{
    addr_t owner_address;
};

}  // namespace ripple

#endif
