#ifndef RIPPLE_PROTOCOL_SMART_CONTRACT_ABI_H_INCLUDED
#define RIPPLE_PROTOCOL_SMART_CONTRACT_ABI_H_INCLUDED

#include <cstdint>

#ifndef PACKED
#if defined(__GNUC__) || defined(__clang__)
#define PACKED __attribute__((packed))
#else
#define PACKED
#endif
#endif

namespace ripple {

inline constexpr char SC_HOST_MOD[] = "host";

inline constexpr std::uint32_t ADDR_SIZE = 20u;
inline constexpr std::uint32_t ID256_SIZE = 32u;
inline constexpr std::uint32_t HASH256_WORDS = 4u;
inline constexpr std::uint32_t HASH256_SIZE = 32u;

struct PACKED addr_t
{
    std::uint8_t bytes[ADDR_SIZE];
};

struct PACKED id256_t
{
    std::uint8_t bytes[ID256_SIZE];
};

struct PACKED hash256_t
{
    std::uint64_t words[HASH256_WORDS];
};

}  // namespace ripple

#endif
