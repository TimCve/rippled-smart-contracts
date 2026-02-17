#include "smart_contract_abi.h"
#include <stddef.h>
#include <stdint.h>

#define TRUE 1
#define FALSE 0

#define REVEAL_TIMEOUT_DURATION (24u * 60u * 60u)
#define MAX_BET 50000000000000000ULL

typedef struct {
    hash256_t commit;
    uint8_t accepted;
    uint32_t accepted_timestamp;
    addr_t player;
    uint64_t player_entry;
    uint64_t player_bet;
} game_t;

typedef struct PACKED {
    hash256_t commit;
} params1_t;

typedef struct PACKED {
    id256_t game_id;
    uint64_t player_entry;
    uint64_t player_bet;
} params2_t;

typedef struct PACKED {
    id256_t game_id;
    uint64_t secret;
    id256_t salt;
} params3_t;

typedef struct PACKED {
    uint64_t secret;
    id256_t salt;
} commit_preimage_t;

_Static_assert(sizeof(game_t) == 80, "game_t size mismatch");
_Static_assert(sizeof(params1_t) == 32, "params1_t size mismatch");
_Static_assert(sizeof(params2_t) == 48, "params2_t size mismatch");
_Static_assert(sizeof(params3_t) == 72, "params3_t size mismatch");
_Static_assert(sizeof(commit_preimage_t) == 40, "commit_preimage_t size mismatch");
_Static_assert(
    _Alignof(game_t) >= _Alignof(uint64_t),
    "game_t alignment must allow uint64_t access");
_Static_assert(
    (offsetof(game_t, player_entry) % _Alignof(uint64_t)) == 0,
    "game_t.player_entry must be uint64_t-aligned");
_Static_assert(
    (offsetof(game_t, player_bet) % _Alignof(uint64_t)) == 0,
    "game_t.player_bet must be uint64_t-aligned");

int32_t hash256_eq(hash256_t* a, hash256_t* b) {
    if (a->words[0] == b->words[0] && a->words[1] == b->words[1] &&
        a->words[2] == b->words[2] && a->words[3] == b->words[3])
        return TRUE;
    else return FALSE;
}

int32_t addr_eq(addr_t* a, addr_t* b) {
    if (((uint8_t*)a)[0] == ((uint8_t*)b)[0] && ((uint8_t*)a)[1] == ((uint8_t*)b)[1] &&
        ((uint8_t*)a)[2] == ((uint8_t*)b)[2] && ((uint8_t*)a)[3] == ((uint8_t*)b)[3] &&
        ((uint8_t*)a)[4] == ((uint8_t*)b)[4] && ((uint8_t*)a)[5] == ((uint8_t*)b)[5] &&
        ((uint8_t*)a)[6] == ((uint8_t*)b)[6] && ((uint8_t*)a)[7] == ((uint8_t*)b)[7] &&
        ((uint8_t*)a)[8] == ((uint8_t*)b)[8] && ((uint8_t*)a)[9] == ((uint8_t*)b)[9] &&
        ((uint8_t*)a)[10] == ((uint8_t*)b)[10] && ((uint8_t*)a)[11] == ((uint8_t*)b)[11] &&
        ((uint8_t*)a)[12] == ((uint8_t*)b)[12] && ((uint8_t*)a)[13] == ((uint8_t*)b)[13] &&
        ((uint8_t*)a)[14] == ((uint8_t*)b)[14] && ((uint8_t*)a)[15] == ((uint8_t*)b)[15] &&
        ((uint8_t*)a)[16] == ((uint8_t*)b)[16] && ((uint8_t*)a)[17] == ((uint8_t*)b)[17] &&
        ((uint8_t*)a)[18] == ((uint8_t*)b)[18] && ((uint8_t*)a)[19] == ((uint8_t*)b)[19])
        return TRUE;
    else return FALSE;
}

__attribute__((export_name("entrypoint")))
int32_t entrypoint(int64_t opt) {
    addr_t contract_owner;
    addr_t contract_caller;

    getOwnerAddr((int32_t)&contract_owner);
    getCallerAddr((int32_t)&contract_caller);

    switch (opt) {
        case 1:  // create game
        {
            if (!addr_eq(&contract_caller, &contract_owner))
                return -11;
            if (!paramsPassed())
                return -12;

            params1_t params;
            int32_t got = getParams((int32_t)&params, sizeof(params1_t));
            if (got != sizeof(params1_t))
                return -13;

            game_t game;
            addr_t zero_addr = {0};
            game.commit = params.commit;
            game.accepted = FALSE;
            game.player = zero_addr;
            game.player_entry = 0;
            game.player_bet = 0;

            id256_t game_id;
            createSmartObject((int32_t)&game, sizeof(game_t), (int32_t)&game_id);

            break;
        }
        case 2:  // accept game & stake bets
        {
            if (addr_eq(&contract_caller, &contract_owner))
                return -21;
            if (!paramsPassed())
                return -22;

            params2_t params;
            int32_t got = getParams((int32_t)&params, sizeof(params2_t));
            if (got != sizeof(params2_t))
                return -23;

            game_t game;
            int32_t sz = getSmartObjectData((int32_t)&params.game_id, (int32_t)&game, sizeof(game_t));
            if (sz != sizeof(game_t))
                return -24;

            if (game.accepted)
                return -25;
            if (params.player_bet == 0 || params.player_bet > MAX_BET)
                return -26;

            lockCallerXRP((int64_t)params.player_bet);
            lockOwnerXRP((int64_t)params.player_bet);

            game.accepted = TRUE;
            game.accepted_timestamp = (uint32_t)getLedgerTimestamp();
            game.player = contract_caller;
            game.player_entry = params.player_entry;
            game.player_bet = params.player_bet;

            setSmartObject((int32_t)&params.game_id, (int32_t)&game, sizeof(game_t));

            break;
        }
        case 3:  // dealer reveal & settle
        {
            if (!addr_eq(&contract_caller, &contract_owner))
                return -31;
            if (!paramsPassed())
                return -32;

            params3_t params;
            int32_t got = getParams((int32_t)&params, sizeof(params3_t));
            if (got != sizeof(params3_t))
                return -33;

            game_t game;
            int32_t sz = getSmartObjectData((int32_t)&params.game_id, (int32_t)&game, sizeof(game_t));
            if (sz != sizeof(game_t))
                return -34;
            if (!game.accepted)
                return -35;

            uint32_t now = (uint32_t)getLedgerTimestamp();
            if (now > game.accepted_timestamp + REVEAL_TIMEOUT_DURATION)
                return -36;

            hash256_t commit_verif;
            commit_preimage_t preimage;
            preimage.secret = params.secret;
            preimage.salt = params.salt;
            sha256((int32_t)&preimage, sizeof(commit_preimage_t), (int32_t)&commit_verif);
            if (!hash256_eq(&game.commit, &commit_verif))
                return -37;

            uint64_t randomizer = params.secret ^ game.player_entry;
            uint64_t mixed = randomizer;
            mixed ^= mixed >> 32;
            mixed ^= mixed >> 16;
            mixed ^= mixed >> 8;
            mixed ^= mixed >> 4;
            mixed ^= mixed >> 2;
            mixed ^= mixed >> 1;
            addr_t winner = (mixed & 1ULL) ? game.player : contract_owner;
            int64_t payout = (int64_t)(game.player_bet * 2ULL);
            unlockXRP(payout, (int32_t)&winner);
            deleteSmartObject((int32_t)&params.game_id);
            break;
        }
        case 4:  // player timeout-claim
        {
            if (!paramsPassed())
                return -41;

            id256_t game_id;
            int32_t got = getParams((int32_t)&game_id, sizeof(id256_t));
            if (got != sizeof(id256_t))
                return -42;

            game_t game;
            int32_t sz = getSmartObjectData((int32_t)&game_id, (int32_t)&game, sizeof(game_t));
            if (sz != sizeof(game_t))
                return -43;
            if (!game.accepted)
                return -44;
            if (!addr_eq(&contract_caller, &game.player))
                return -45;

            uint32_t now = (uint32_t)getLedgerTimestamp();
            if (now <= game.accepted_timestamp + REVEAL_TIMEOUT_DURATION)
                return -46;

            int64_t payout = (int64_t)(game.player_bet * 2ULL);
            unlockXRP(payout, (int32_t)&contract_caller);
            deleteSmartObject((int32_t)&game_id);

            break;
        }
        default:
        {
            return -999;
        }
    }

    return 0;
}
