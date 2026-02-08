#include "../include/xrpl/protocol/smart_contract_abi.h"
#include <stdint.h>

__attribute__((export_name("entrypoint")))
int32_t entrypoint(int64_t opt)
{
    if (opt == 0) {
        for (uint32_t i = 0; i < 100; i++) {
            _g(8, 100);
            volatile uint32_t x = i * i;
        }
    } else if (opt == 1) {
        for (uint32_t i = 0; i < 100; i++) {
            _g(14, 100);
            volatile uint32_t x = i * i;
        }
    }

    return 0;
}
