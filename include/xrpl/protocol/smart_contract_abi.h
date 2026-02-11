#ifndef RIPPLE_PROTOCOL_SMART_CONTRACT_ABI_H_INCLUDED
#define RIPPLE_PROTOCOL_SMART_CONTRACT_ABI_H_INCLUDED

#include <cstdint>

namespace ripple {

inline constexpr char SC_HOST_MOD[] = "host";

inline constexpr std::uint32_t ADDR_SIZE = 20u;
inline constexpr std::uint32_t ID256_SIZE = 32u;

struct addr_t
{
    std::uint8_t bytes[ADDR_SIZE];
};

struct id256_t
{
    std::uint8_t bytes[ID256_SIZE];
};

}  // namespace ripple

#endif
