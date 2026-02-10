#include <xrpld/app/tx/detail/ContractCall.h>
#include <xrpld/ledger/View.h>

#include <xrpl/beast/utility/Zero.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/UintTypes.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/basics/Blob.h>
#include <xrpl/basics/Log.h>
#include <algorithm>
#include <cstring>
#include <limits>
#include <optional>
#include <string>
#include <unordered_map>

#include <wasmtime.h>

#include <xrpl/protocol/smart_contract_abi.h>

namespace ripple {
namespace {

// TODO: check if necessary
static_assert(sizeof(addr_t) == ADDR_SIZE, "addr_t size mismatch");
static_assert(sizeof(id256_t) == ID256_SIZE, "id256_t size mismatch");

void
logWasmtimeError(beast::Journal j, wasmtime_error_t* err)
{
    if (!err)
        return;

    wasm_name_t msg;
    wasmtime_error_message(err, &msg);
    JLOG(j.error()) << "Wasmtime error: " << std::string(msg.data, msg.size);
    wasm_name_delete(&msg);
    wasmtime_error_delete(err);
}

void
logWasmtimeTrap(beast::Journal j, wasm_trap_t* trap)
{
    if (!trap)
        return;

    wasm_name_t msg;
    wasm_trap_message(trap, &msg);
    JLOG(j.error()) << "Wasm trap: " << std::string(msg.data, msg.size);
    wasm_name_delete(&msg);
    wasm_trap_delete(trap);
}

TER
logWasmtimeFailure(beast::Journal j, wasmtime_error_t* err, wasm_trap_t* trap)
{
    if (!err && !trap)
        return tesSUCCESS;

    logWasmtimeError(j, err);
    logWasmtimeTrap(j, trap);
    return tecFAILED_PROCESSING;
}

wasm_trap_t*
makeTrap(char const* msg)
{
    return wasmtime_trap_new(msg, std::strlen(msg));
}

bool
nameEq(wasm_name_t const* n, char const* s)
{
    if (!n)
        return false;
    std::size_t len = std::strlen(s);
    return n->size == len && std::memcmp(n->data, s, len) == 0;
}

bool
policyCheck(bool cond, beast::Journal j, char const* msg)
{
    if (cond)
        return true;

    JLOG(j.error()) << "Smart contract policy violation: " << msg;
    return false;
}

wasm_engine_t*
getEngine()
{
    static wasm_engine_t* engine = []() { return wasm_engine_new(); }();
    return engine;
}

struct HostState
{
    explicit HostState(beast::Journal const& journal) : j(journal)
    {
    }

    struct GuardState
    {
        std::int32_t max = 0;
        std::int32_t count = 0;
    };

    beast::Journal const& j;
    wasmtime_context_t* ctx = nullptr;

    bool have_memory = false;
    wasmtime_memory_t memory{};

    ApplyView* view = nullptr;
    AccountID caller;
    AccountID owner;
    uint256 contractID;
    Blob params;
    bool paramsPassed = false;
    std::uint64_t opt = 0;
    TER callbackTer = tesSUCCESS;
    std::unordered_map<std::int32_t, GuardState> guards;
};

uint8_t* // get pointer to smart contract memory
memData(HostState* st)
{
    return wasmtime_memory_data(st->ctx, &st->memory);
}

std::size_t // get size of smart contract memory
memSize(HostState* st)
{
    return wasmtime_memory_data_size(st->ctx, &st->memory);
}

bool // is memory slice in smart contract memory within bounds?
memSliceOk(HostState* st, uint32_t ptr, uint32_t len)
{
    return static_cast<uint64_t>(ptr) + len <= memSize(st);
}

bool 
readId256(HostState* st, uint32_t ptr, uint256& out)
{
    if (!memSliceOk(st, ptr, ID256_SIZE))
        return false;

    out = uint256::fromVoid(memData(st) + ptr);
    return true;
}

bool
writeId256(HostState* st, uint32_t ptr, uint256 const& id)
{
    if (!memSliceOk(st, ptr, ID256_SIZE))
        return false;

    std::memcpy(memData(st) + ptr, id.data(), ID256_SIZE);
    return true;
}

TER // enough reserve for additional <add> SLEs?
checkReserve(
    HostState* st,
    AccountID const& owner,
    std::uint32_t add,
    STAmount const& debit)
{
    if (!st->view)
        return tefINTERNAL;

    auto ownerSle = st->view->peek(keylet::account(owner));
    if (!ownerSle)
        return tecNO_ENTRY;

    STAmount const balance = ownerSle->getFieldAmount(sfBalance);
    STAmount const newBalance = balance - debit;
    if (newBalance < beast::zero)
        return tecUNFUNDED_PAYMENT;

    STAmount const reserve = st->view->fees().accountReserve(
        ownerSle->getFieldU32(sfOwnerCount) + add);
    if (newBalance < reserve)
        return tecINSUFFICIENT_RESERVE;

    return tesSUCCESS;
}

TER // add SLE to owner dir
addToOwnerDir(
    HostState* st,
    AccountID const& owner,
    Keylet const& objKeylet,
    std::shared_ptr<SLE> const& sle,
    std::uint64_t* insertedPage = nullptr)
{
    auto const page = st->view->dirInsert(
        keylet::ownerDir(owner), objKeylet, describeOwnerDir(owner));
    if (!page)
        return tecDIR_FULL;

    if (insertedPage)
        *insertedPage = *page;

    sle->setFieldU64(sfOwnerNode, *page);
    st->view->update(sle);

    adjustOwnerCount(*st->view, st->view->peek(keylet::account(owner)), 1, st->j);
    return tesSUCCESS;
}

TER // remove SLE from owner dir
removeFromOwnerDir(
    HostState* st,
    AccountID const& owner,
    Keylet const& objKeylet,
    std::shared_ptr<SLE> const& sle)
{
    auto const page = sle->getFieldU64(sfOwnerNode);
    if (!st->view->dirRemove(keylet::ownerDir(owner), page, objKeylet.key, true))
        return tefBAD_LEDGER;

    adjustOwnerCount(*st->view, st->view->peek(keylet::account(owner)), -1, st->j);
    return tesSUCCESS;
}

std::optional<std::uint32_t>
nextOwnerDirIndex(HostState* st, AccountID const& owner)
{
    if (!st->view)
        return std::nullopt;

    auto const ownerSle = st->view->peek(keylet::account(owner));
    if (!ownerSle)
        return std::nullopt;

    auto const ownerCount = ownerSle->getFieldU32(sfOwnerCount);
    if (ownerCount == std::numeric_limits<std::uint32_t>::max())
        return std::nullopt;

    // Use the account's next owner-dir position as a deterministic per-account
    // sequence surrogate now that CONTRACT_DIR has been removed.
    return ownerCount + 1;
}

uint256
makeContractObjectID(
    HostState* st,
    AccountID const& owner,
    std::uint32_t ownerDirIndex)
{
    auto const closeTimeCount =
        st->view->parentCloseTime().time_since_epoch().count();
    auto const closeTime =
        static_cast<std::uint32_t>(std::max<std::int64_t>(0, closeTimeCount));
    auto const entropy =
        (static_cast<std::uint64_t>(closeTime) << 32) | ownerDirIndex;
    return sha512Half(st->contractID, owner, entropy);
}

wasm_trap_t*
cb_get_caller_addr(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    auto* st = reinterpret_cast<HostState*>(env);
    if (nargs != 1 || args[0].kind != WASMTIME_I32)
        return makeTrap("get_caller signature mismatch");
    if (nresults != 1 || results[0].kind != WASMTIME_I32)
        return makeTrap("get_caller returns i32");
    if (!st->have_memory)
        return makeTrap("guest memory not available");

    uint32_t a_ptr = static_cast<uint32_t>(args[0].of.i32);
    std::size_t msz = memSize(st);
    if (static_cast<uint64_t>(a_ptr) + ADDR_SIZE > msz)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    std::memcpy(memData(st) + a_ptr, st->caller.data(), ADDR_SIZE);
    results[0].of.i32 = 0;
    return nullptr;
}

wasm_trap_t*
cb_get_owner_addr(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    auto* st = reinterpret_cast<HostState*>(env);
    if (nargs != 1 || args[0].kind != WASMTIME_I32)
        return makeTrap("get_owner signature mismatch");
    if (nresults != 1 || results[0].kind != WASMTIME_I32)
        return makeTrap("get_owner returns i32");
    if (!st->have_memory)
        return makeTrap("guest memory not available");

    uint32_t a_ptr = static_cast<uint32_t>(args[0].of.i32);
    std::size_t msz = memSize(st);
    if (static_cast<uint64_t>(a_ptr) + ADDR_SIZE > msz)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    std::memcpy(memData(st) + a_ptr, st->owner.data(), ADDR_SIZE);
    results[0].of.i32 = 0;
    return nullptr;
}

wasm_trap_t*
cb_escrow_caller_xrp(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    auto* st = reinterpret_cast<HostState*>(env);
    if (nargs != 2 || args[0].kind != WASMTIME_I32 ||
        args[1].kind != WASMTIME_I32)
    {
        return makeTrap("escrowCallerXRP signature mismatch");
    }
    if (nresults != 1 || results[0].kind != WASMTIME_I32)
        return makeTrap("escrowCallerXRP returns i32");
    if (!st->have_memory)
        return makeTrap("guest memory not available");

    uint32_t id_ptr = static_cast<uint32_t>(args[0].of.i32);
    int32_t amount = args[1].of.i32;

    if (st->callbackTer != tesSUCCESS)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (amount <= 0 || !memSliceOk(st, id_ptr, ID256_SIZE))
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    AccountID const funder = st->caller;
    STAmount const amt{XRPAmount{amount}};

    auto contractSle =
        st->view->peek(keylet::smartContract(st->contractID));
    if (!contractSle)
    {
        st->callbackTer = tecNO_ENTRY;
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (TER const ter = checkReserve(st, funder, 1, amt);
        ter != tesSUCCESS)
    {
        st->callbackTer = ter;
        results[0].of.i32 = -1;
        return nullptr;
    }

    auto const ownerDirIndex = nextOwnerDirIndex(st, funder);
    if (!ownerDirIndex)
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }
    uint256 const escrowID = makeContractObjectID(st, funder, *ownerDirIndex);
    auto const escrowKeylet =
        keylet::smartEscrow(st->contractID, escrowID);
    if (st->view->exists(escrowKeylet))
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    contractSle->setFieldAmount(
        sfContractBalance,
        contractSle->getFieldAmount(sfContractBalance) + amt);
    st->view->update(contractSle);

    auto escrowSle = std::make_shared<SLE>(escrowKeylet);
    (*escrowSle)[sfSmartEscrowID] = escrowID;
    (*escrowSle)[sfContractID] = st->contractID;
    (*escrowSle)[sfAccount] = funder;
    escrowSle->setFieldAmount(sfAmount, amt);
    st->view->insert(escrowSle);
    if (TER const ter = addToOwnerDir(st, funder, escrowKeylet, escrowSle);
        ter != tesSUCCESS)
    {
        st->callbackTer = ter;
        results[0].of.i32 = -1;
        return nullptr;
    }

    auto funderSle = st->view->peek(keylet::account(funder));
    if (!funderSle)
    {
        st->callbackTer = tecNO_ENTRY;
        results[0].of.i32 = -1;
        return nullptr;
    }
    funderSle->setFieldAmount(
        sfBalance, funderSle->getFieldAmount(sfBalance) - amt);
    st->view->update(funderSle);

    if (!writeId256(st, id_ptr, escrowID))
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    results[0].of.i32 = 0;
    return nullptr;
}

wasm_trap_t*
cb_escrow_owner_xrp(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    auto* st = reinterpret_cast<HostState*>(env);
    if (nargs != 2 || args[0].kind != WASMTIME_I32 ||
        args[1].kind != WASMTIME_I32)
    {
        return makeTrap("escrowOwnerXRP signature mismatch");
    }
    if (nresults != 1 || results[0].kind != WASMTIME_I32)
        return makeTrap("escrowOwnerXRP returns i32");
    if (!st->have_memory)
        return makeTrap("guest memory not available");

    uint32_t id_ptr = static_cast<uint32_t>(args[0].of.i32);
    int32_t amount = args[1].of.i32;

    if (st->callbackTer != tesSUCCESS)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (amount <= 0 || !memSliceOk(st, id_ptr, ID256_SIZE))
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    AccountID const funder = st->owner;
    STAmount const amt{XRPAmount{amount}};

    auto contractSle =
        st->view->peek(keylet::smartContract(st->contractID));
    if (!contractSle)
    {
        st->callbackTer = tecNO_ENTRY;
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (TER const ter = checkReserve(st, funder, 1, amt);
        ter != tesSUCCESS)
    {
        st->callbackTer = ter;
        results[0].of.i32 = -1;
        return nullptr;
    }

    auto const ownerDirIndex = nextOwnerDirIndex(st, funder);
    if (!ownerDirIndex)
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }
    uint256 const escrowID = makeContractObjectID(st, funder, *ownerDirIndex);
    auto const escrowKeylet =
        keylet::smartEscrow(st->contractID, escrowID);
    if (st->view->exists(escrowKeylet))
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    contractSle->setFieldAmount(
        sfContractBalance,
        contractSle->getFieldAmount(sfContractBalance) + amt);
    st->view->update(contractSle);

    auto escrowSle = std::make_shared<SLE>(escrowKeylet);
    (*escrowSle)[sfSmartEscrowID] = escrowID;
    (*escrowSle)[sfContractID] = st->contractID;
    (*escrowSle)[sfAccount] = funder;
    escrowSle->setFieldAmount(sfAmount, amt);
    st->view->insert(escrowSle);
    if (TER const ter = addToOwnerDir(st, funder, escrowKeylet, escrowSle);
        ter != tesSUCCESS)
    {
        st->callbackTer = ter;
        results[0].of.i32 = -1;
        return nullptr;
    }

    auto funderSle = st->view->peek(keylet::account(funder));
    if (!funderSle)
    {
        st->callbackTer = tecNO_ENTRY;
        results[0].of.i32 = -1;
        return nullptr;
    }
    funderSle->setFieldAmount(
        sfBalance, funderSle->getFieldAmount(sfBalance) - amt);
    st->view->update(funderSle);

    if (!writeId256(st, id_ptr, escrowID))
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    results[0].of.i32 = 0;
    return nullptr;
}

wasm_trap_t*
cb_release_escrowed_xrp(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    auto* st = reinterpret_cast<HostState*>(env);
    if (nargs != 2 || args[0].kind != WASMTIME_I32 ||
        args[1].kind != WASMTIME_I32)
    {
        return makeTrap("releaseEscrowedXRP signature mismatch");
    }
    if (nresults != 1 || results[0].kind != WASMTIME_I32)
        return makeTrap("releaseEscrowedXRP returns i32");
    if (!st->have_memory)
        return makeTrap("guest memory not available");

    uint32_t id_ptr = static_cast<uint32_t>(args[0].of.i32);
    uint32_t dest_ptr = static_cast<uint32_t>(args[1].of.i32);

    if (st->callbackTer != tesSUCCESS)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    uint256 escrowID;
    if (!readId256(st, id_ptr, escrowID))
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (!memSliceOk(st, dest_ptr, ADDR_SIZE))
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    addr_t dest_addr{};
    std::memcpy(&dest_addr, memData(st) + dest_ptr, ADDR_SIZE);
    AccountID dest = AccountID::fromVoid(dest_addr.bytes);

    auto const escrowKeylet =
        keylet::smartEscrow(st->contractID, escrowID);
    auto escrowSle = st->view->peek(escrowKeylet);
    if (!escrowSle)
    {
        st->callbackTer = tecNO_ENTRY;
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (escrowSle->getFieldH256(sfContractID) != st->contractID)
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    STAmount const amt = escrowSle->getFieldAmount(sfAmount);
    if (!amt.native() || amt <= beast::zero)
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    auto contractSle =
        st->view->peek(keylet::smartContract(st->contractID));
    if (!contractSle)
    {
        st->callbackTer = tecNO_ENTRY;
        results[0].of.i32 = -1;
        return nullptr;
    }

    STAmount const contractBal = contractSle->getFieldAmount(sfContractBalance);
    if (contractBal < amt)
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    auto destSle = st->view->peek(keylet::account(dest));
    if (!destSle)
    {
        st->callbackTer = tecNO_DST;
        results[0].of.i32 = -1;
        return nullptr;
    }

    contractSle->setFieldAmount(sfContractBalance, contractBal - amt);
    st->view->update(contractSle);

    destSle->setFieldAmount(sfBalance, destSle->getFieldAmount(sfBalance) + amt);
    st->view->update(destSle);

    AccountID const owner = escrowSle->getAccountID(sfAccount);

    if (TER const ter =
            removeFromOwnerDir(st, owner, escrowKeylet, escrowSle);
        ter != tesSUCCESS)
    {
        st->callbackTer = ter;
        results[0].of.i32 = -1;
        return nullptr;
    }

    st->view->erase(escrowSle);

    results[0].of.i32 = 0;
    return nullptr;
}

wasm_trap_t*
cb_create_state(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    auto* st = reinterpret_cast<HostState*>(env);
    if (nargs != 3 || args[0].kind != WASMTIME_I32 ||
        args[1].kind != WASMTIME_I32 || args[2].kind != WASMTIME_I32)
    {
        return makeTrap("createState signature mismatch");
    }
    if (nresults != 1 || results[0].kind != WASMTIME_I32)
        return makeTrap("createState returns i32");
    if (!st->have_memory)
        return makeTrap("guest memory not available");

    uint32_t data_ptr = static_cast<uint32_t>(args[0].of.i32);
    int32_t data_len = args[1].of.i32;
    uint32_t id_ptr = static_cast<uint32_t>(args[2].of.i32);

    if (st->callbackTer != tesSUCCESS)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (data_len < 0 || !memSliceOk(st, id_ptr, ID256_SIZE) ||
        !memSliceOk(st, data_ptr, static_cast<uint32_t>(data_len)))
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    Blob data;
    data.assign(memData(st) + data_ptr,
                memData(st) + data_ptr + static_cast<uint32_t>(data_len));

    if (TER const ter =
            checkReserve(st, st->caller, 1, STAmount{XRPAmount{0}});
        ter != tesSUCCESS)
    {
        st->callbackTer = ter;
        results[0].of.i32 = -1;
        return nullptr;
    }

    auto const ownerDirIndex = nextOwnerDirIndex(st, st->caller);
    if (!ownerDirIndex)
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }
    uint256 const stateID = makeContractObjectID(st, st->caller, *ownerDirIndex);
    auto const stateKeylet =
        keylet::contractState(st->contractID, stateID);
    if (st->view->exists(stateKeylet))
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    auto stateSle = std::make_shared<SLE>(stateKeylet);
    (*stateSle)[sfContractStateID] = stateID;
    (*stateSle)[sfAccount] = st->caller;
    (*stateSle)[sfContractID] = st->contractID;
    stateSle->setFieldVL(sfContractStateData, data);
    st->view->insert(stateSle);
    if (TER const ter = addToOwnerDir(st, st->caller, stateKeylet, stateSle);
        ter != tesSUCCESS)
    {
        st->callbackTer = ter;
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (!writeId256(st, id_ptr, stateID))
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    results[0].of.i32 = 0;
    return nullptr;
}

wasm_trap_t*
cb_get_state(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    auto* st = reinterpret_cast<HostState*>(env);
    if (nargs != 3 || args[0].kind != WASMTIME_I32 ||
        args[1].kind != WASMTIME_I32 || args[2].kind != WASMTIME_I32)
    {
        return makeTrap("getState signature mismatch");
    }
    if (nresults != 1 || results[0].kind != WASMTIME_I32)
        return makeTrap("getState returns i32");
    if (!st->have_memory)
        return makeTrap("guest memory not available");

    uint32_t id_ptr = static_cast<uint32_t>(args[0].of.i32);
    uint32_t out_ptr = static_cast<uint32_t>(args[1].of.i32);
    int32_t out_len = args[2].of.i32;

    if (st->callbackTer != tesSUCCESS)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (out_len < 0 || !memSliceOk(st, out_ptr, static_cast<uint32_t>(out_len)))
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    uint256 stateID;
    if (!readId256(st, id_ptr, stateID))
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    auto const stateKeylet =
        keylet::contractState(st->contractID, stateID);
    auto stateSle = st->view->read(stateKeylet);
    if (!stateSle)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    auto const& data = stateSle->getFieldVL(sfContractStateData);
    if (data.size() > static_cast<std::size_t>(out_len))
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    std::memcpy(memData(st) + out_ptr, data.data(), data.size());
    results[0].of.i32 = static_cast<std::int32_t>(data.size());
    return nullptr;
}

wasm_trap_t*
cb_set_state(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    auto* st = reinterpret_cast<HostState*>(env);
    if (nargs != 3 || args[0].kind != WASMTIME_I32 ||
        args[1].kind != WASMTIME_I32 || args[2].kind != WASMTIME_I32)
    {
        return makeTrap("setState signature mismatch");
    }
    if (nresults != 1 || results[0].kind != WASMTIME_I32)
        return makeTrap("setState returns i32");
    if (!st->have_memory)
        return makeTrap("guest memory not available");

    uint32_t id_ptr = static_cast<uint32_t>(args[0].of.i32);
    uint32_t data_ptr = static_cast<uint32_t>(args[1].of.i32);
    int32_t data_len = args[2].of.i32;

    if (st->callbackTer != tesSUCCESS)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (data_len < 0 ||
        !memSliceOk(st, data_ptr, static_cast<uint32_t>(data_len)))
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    uint256 stateID;
    if (!readId256(st, id_ptr, stateID))
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    auto const stateKeylet =
        keylet::contractState(st->contractID, stateID);
    auto stateSle = st->view->peek(stateKeylet);
    if (!stateSle)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (stateSle->getAccountID(sfAccount) != st->caller)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    Blob data;
    data.assign(memData(st) + data_ptr,
                memData(st) + data_ptr + static_cast<uint32_t>(data_len));
    stateSle->setFieldVL(sfContractStateData, data);
    st->view->update(stateSle);

    results[0].of.i32 = 0;
    return nullptr;
}

wasm_trap_t*
cb_delete_state(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    auto* st = reinterpret_cast<HostState*>(env);
    if (nargs != 1 || args[0].kind != WASMTIME_I32)
        return makeTrap("deleteState signature mismatch");
    if (nresults != 1 || results[0].kind != WASMTIME_I32)
        return makeTrap("deleteState returns i32");
    if (!st->have_memory)
        return makeTrap("guest memory not available");

    uint32_t id_ptr = static_cast<uint32_t>(args[0].of.i32);

    if (st->callbackTer != tesSUCCESS)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    uint256 stateID;
    if (!readId256(st, id_ptr, stateID))
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    auto const stateKeylet =
        keylet::contractState(st->contractID, stateID);
    auto stateSle = st->view->peek(stateKeylet);
    if (!stateSle)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    AccountID const owner = stateSle->getAccountID(sfAccount);

    if (TER const ter = removeFromOwnerDir(st, owner, stateKeylet, stateSle);
        ter != tesSUCCESS)
    {
        st->callbackTer = ter;
        results[0].of.i32 = -1;
        return nullptr;
    }

    st->view->erase(stateSle);

    results[0].of.i32 = 0;
    return nullptr;
}

wasm_trap_t*
cb_get_params(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    auto* st = reinterpret_cast<HostState*>(env);
    if (nargs != 2 || args[0].kind != WASMTIME_I32 ||
        args[1].kind != WASMTIME_I32)
    {
        return makeTrap("getParams signature mismatch");
    }
    if (nresults != 1 || results[0].kind != WASMTIME_I32)
        return makeTrap("getParams returns i32");
    if (!st->have_memory)
        return makeTrap("guest memory not available");

    uint32_t out_ptr = static_cast<uint32_t>(args[0].of.i32);
    int32_t out_len = args[1].of.i32;

    if (!st->paramsPassed)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (out_len < 0 ||
        !memSliceOk(st, out_ptr, static_cast<uint32_t>(out_len)))
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (st->params.size() > static_cast<std::size_t>(out_len))
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    std::memcpy(memData(st) + out_ptr, st->params.data(), st->params.size());
    results[0].of.i32 = static_cast<std::int32_t>(st->params.size());
    return nullptr;
}

wasm_trap_t*
cb_params_passed(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    auto* st = reinterpret_cast<HostState*>(env);
    if (nargs != 0)
        return makeTrap("paramsPassed signature mismatch");
    if (nresults != 1 || results[0].kind != WASMTIME_I32)
        return makeTrap("paramsPassed returns i32");

    results[0].of.i32 = st->paramsPassed ? 1 : 0;
    return nullptr;
}

wasm_trap_t*
cb_loop_guard(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    if (nargs != 2 || args[0].kind != WASMTIME_I32 ||
        args[1].kind != WASMTIME_I32)
    {
        return makeTrap("_g signature mismatch");
    }
    if (nresults != 0)
        return makeTrap("_g returns void");

    auto* st = reinterpret_cast<HostState*>(env);
    std::int32_t id = args[0].of.i32;
    std::int32_t max_iters = args[1].of.i32;
    if (max_iters <= 0)
        return makeTrap("_g max_iters must be > 0");

    auto it = st->guards.find(id);
    if (it == st->guards.end())
    {
        st->guards.emplace(id, HostState::GuardState{max_iters, 1});
        return nullptr;
    }

    if (it->second.max != max_iters)
        return makeTrap("_g max_iters mismatch for id");
    if (it->second.count >= it->second.max)
        return makeTrap("_g exceeded max_iters");

    ++it->second.count;
    return nullptr;
}

bool
enforceImportPolicy(wasmtime_module_t const* module, beast::Journal j)
{
    wasm_importtype_vec_t imports;
    wasmtime_module_imports(module, &imports);

    bool ok = true;
    for (std::size_t i = 0; i < imports.size; ++i)
    {
        wasm_importtype_t const* it = imports.data[i];
        wasm_name_t const* mod = wasm_importtype_module(it);
        wasm_name_t const* name = wasm_importtype_name(it);

        ok = policyCheck(
            nameEq(mod, SC_HOST_MOD),
            j,
            "imports must come only from module \"host\"");
        if (!ok)
            break;

        bool allowed =
            nameEq(name, "getCallerAddr") || nameEq(name, "getOwnerAddr") ||
            nameEq(name, "escrowCallerXRP") || nameEq(name, "escrowOwnerXRP") ||
            nameEq(name, "releaseEscrowedXRP") || nameEq(name, "createState") ||
            nameEq(name, "getState") || nameEq(name, "deleteState") || 
            nameEq(name, "setState") || nameEq(name, "getParams") || 
            nameEq(name, "paramsPassed") || nameEq(name, "_g");
        ok = policyCheck(allowed, j, "import name not allowed");
        if (!ok)
            break;
    }

    wasm_importtype_vec_delete(&imports);
    return ok;
}

bool
enforceExportPolicy(wasmtime_module_t const* module, beast::Journal j)
{
    wasm_exporttype_vec_t exports;
    wasmtime_module_exports(module, &exports);

    std::size_t func_exports = 0;
    bool saw_entry = false;
    bool ok = true;

    for (std::size_t i = 0; i < exports.size; ++i)
    {
        wasm_exporttype_t const* et = exports.data[i];
        wasm_name_t const* name = wasm_exporttype_name(et);
        wasm_externtype_t const* extty = wasm_exporttype_type(et);
        wasm_externkind_t kind = wasm_externtype_kind(extty);

        if (kind == WASM_EXTERN_FUNC)
        {
            func_exports++;
            ok = policyCheck(
                nameEq(name, "entrypoint"),
                j,
                "only function export must be named \"entrypoint\"");
            if (!ok)
                break;
            saw_entry = true;
            continue;
        }

        ok = policyCheck(
            nameEq(name, "memory"), j, "non-function export not allowed");
        if (!ok)
            break;
    }

    if (ok)
        ok = policyCheck(
            func_exports == 1 && saw_entry,
            j,
            "module must export exactly one function named entrypoint");

    wasm_exporttype_vec_delete(&exports);
    return ok;
}

wasmtime_func_t
makeFunc(
    wasmtime_context_t* ctx,
    wasm_functype_t* ty,
    wasmtime_func_callback_t cb,
    void* env)
{
    wasmtime_func_t f;
    wasmtime_func_new(ctx, ty, cb, env, nullptr, &f);
    return f;
}

bool
defineFunc(
    wasmtime_linker_t* linker,
    wasmtime_context_t* ctx,
    char const* mod,
    char const* name,
    wasmtime_func_t const& func,
    beast::Journal j)
{
    wasmtime_extern_t ext;
    ext.kind = WASMTIME_EXTERN_FUNC;
    ext.of.func = func;

    if (auto* err = wasmtime_linker_define(
            linker,
            ctx,
            mod,
            std::strlen(mod),
            name,
            std::strlen(name),
            &ext);
        err)
    {
        logWasmtimeError(j, err);
        return false;
    }

    return true;
}

}  // namespace

NotTEC
ContractCall::preflight(PreflightContext const& ctx)
{
    if(!ctx.rules.enabled(featureSmartContracts))
        return temDISABLED;

    if (ctx.tx.getFlags() & tfUniversalMask)
        return temINVALID_FLAG;
    
    NotTEC const ret{preflight1(ctx)};
    if (!isTesSuccess(ret))
        return ret;

    return preflight2(ctx);
}

TxConsequences
ContractCall::makeTxConsequences(PreflightContext const& ctx)
{
    return TxConsequences{ctx.tx};
}

XRPAmount
ContractCall::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    XRPAmount fixedCost{beast::zero};
    auto const contractID = tx[sfContractID];
    if (auto const sleContract = view.read(keylet::smartContract(contractID)))
    {
        if (sleContract->isFieldPresent(sfContractCost))
        {
            auto const maxDrops =
                static_cast<std::uint64_t>(
                    std::numeric_limits<XRPAmount::value_type>::max());
            auto const costDrops = sleContract->getFieldU64(sfContractCost);
            auto const clampedDrops =
                costDrops > maxDrops ? maxDrops : costDrops;
            fixedCost = XRPAmount{
                static_cast<XRPAmount::value_type>(clampedDrops)};
        }
    }
    return Transactor::calculateBaseFee(view, tx) + fixedCost;
}

TER
ContractCall::preclaim(PreclaimContext const& ctx)
{
    auto const contractID = ctx.tx[sfContractID];
    auto const sleContract = ctx.view.read(keylet::smartContract(contractID));
    if(!sleContract)
        return tecNO_ENTRY;

    auto const caller = ctx.tx.getAccountID(sfAccount);
    auto const callerSle = ctx.view.read(keylet::account(caller));
    if (!callerSle)
        return terNO_ACCOUNT;

    return tesSUCCESS;
}

TER
ContractCall::doApply()
{
    auto const contractID = ctx_.tx[sfContractID];
    auto const sleContract = view().read(keylet::smartContract(contractID));
    if (!sleContract)
        return tecNO_ENTRY;

    auto const& code = sleContract->getFieldVL(sfContractCode);
    if (code.empty())
        return tecFAILED_PROCESSING;

    if (!sleContract->isFieldPresent(sfContractBalance))
    {
        auto contractSle = view().peek(keylet::smartContract(contractID));
        if (!contractSle)
            return tecNO_ENTRY;
        contractSle->setFieldAmount(sfContractBalance, STAmount{XRPAmount{0}});
        view().update(contractSle);
    }

    HostState st{j_};
    st.view = &view();
    st.caller = account_;
    st.owner = sleContract->getAccountID(sfAccount);
    st.contractID = contractID;
    if (ctx_.tx.isFieldPresent(sfContractParams))
    {
        st.params = ctx_.tx.getFieldVL(sfContractParams);
        st.paramsPassed = true;
    }
    if (ctx_.tx.isFieldPresent(sfContractOpt))
    {
        st.opt = ctx_.tx.getFieldU64(sfContractOpt);
    }

    wasm_engine_t* engine = getEngine();
    wasmtime_store_t* store = wasmtime_store_new(engine, &st, nullptr);
    wasmtime_context_t* wctx = wasmtime_store_context(store);
    st.ctx = wctx;

    wasmtime_linker_t* linker = nullptr;
    wasmtime_module_t* module = nullptr;

    auto cleanup = [&]() {
        if (linker)
            wasmtime_linker_delete(linker);
        if (module)
            wasmtime_module_delete(module);
        if (store)
            wasmtime_store_delete(store);
    };

    auto finish = [&](TER ter) {
        cleanup();
        return ter;
    };

    if (TER const ter =
            logWasmtimeFailure(j_, wasmtime_module_new(engine, code.data(), code.size(), &module), nullptr);
        ter != tesSUCCESS)
    {
        return finish(ter);
    }

    if (!enforceImportPolicy(module, j_) || !enforceExportPolicy(module, j_))
    {
        return finish(tecFAILED_PROCESSING);
    }

    linker = wasmtime_linker_new(engine);

    {
        wasm_valtype_t* p[1] = {wasm_valtype_new_i32()};
        wasm_valtype_t* r[1] = {wasm_valtype_new_i32()};
        wasm_valtype_vec_t params;
        wasm_valtype_vec_t results;
        wasm_valtype_vec_new(&params, 1, p);
        wasm_valtype_vec_new(&results, 1, r);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);

        wasmtime_func_t f = makeFunc(wctx, ty, cb_get_caller_addr, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "getCallerAddr", f, j_))
        {
            return finish(tecFAILED_PROCESSING);
        }
    }

    {
        wasm_valtype_t* p[1] = {wasm_valtype_new_i32()};
        wasm_valtype_t* r[1] = {wasm_valtype_new_i32()};
        wasm_valtype_vec_t params;
        wasm_valtype_vec_t results;
        wasm_valtype_vec_new(&params, 1, p);
        wasm_valtype_vec_new(&results, 1, r);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);

        wasmtime_func_t f = makeFunc(wctx, ty, cb_get_owner_addr, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "getOwnerAddr", f, j_))
        {
            return finish(tecFAILED_PROCESSING);
        }
    }

    {
        wasm_valtype_t* p[2] = {wasm_valtype_new_i32(), wasm_valtype_new_i64()};
        wasm_valtype_t* r[1] = {wasm_valtype_new_i32()};
        wasm_valtype_vec_t params;
        wasm_valtype_vec_t results;
        wasm_valtype_vec_new(&params, 2, p);
        wasm_valtype_vec_new(&results, 1, r);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);

        wasmtime_func_t f = makeFunc(wctx, ty, cb_escrow_caller_xrp, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "escrowCallerXRP", f, j_))
        {
            return finish(tecFAILED_PROCESSING);
        }
    }

    {
        wasm_valtype_t* p[2] = {wasm_valtype_new_i32(), wasm_valtype_new_i64()};
        wasm_valtype_t* r[1] = {wasm_valtype_new_i32()};
        wasm_valtype_vec_t params;
        wasm_valtype_vec_t results;
        wasm_valtype_vec_new(&params, 2, p);
        wasm_valtype_vec_new(&results, 1, r);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);

        wasmtime_func_t f = makeFunc(wctx, ty, cb_escrow_owner_xrp, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "escrowOwnerXRP", f, j_))
        {
            return finish(tecFAILED_PROCESSING);
        }
    }

    {
        wasm_valtype_t* p[2] = {wasm_valtype_new_i32(), wasm_valtype_new_i32()};
        wasm_valtype_t* r[1] = {wasm_valtype_new_i32()};
        wasm_valtype_vec_t params;
        wasm_valtype_vec_t results;
        wasm_valtype_vec_new(&params, 2, p);
        wasm_valtype_vec_new(&results, 1, r);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);

        wasmtime_func_t f =
            makeFunc(wctx, ty, cb_release_escrowed_xrp, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(
                linker, wctx, SC_HOST_MOD, "releaseEscrowedXRP", f, j_))
        {
            return finish(tecFAILED_PROCESSING);
        }
    }

    {
        wasm_valtype_t* p[3] = {
            wasm_valtype_new_i32(),
            wasm_valtype_new_i32(),
            wasm_valtype_new_i32()};
        wasm_valtype_t* r[1] = {wasm_valtype_new_i32()};
        wasm_valtype_vec_t params;
        wasm_valtype_vec_t results;
        wasm_valtype_vec_new(&params, 3, p);
        wasm_valtype_vec_new(&results, 1, r);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);

        wasmtime_func_t f = makeFunc(wctx, ty, cb_create_state, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "createState", f, j_))
        {
            return finish(tecFAILED_PROCESSING);
        }
    }

    {
        wasm_valtype_t* p[3] = {
            wasm_valtype_new_i32(),
            wasm_valtype_new_i32(),
            wasm_valtype_new_i32()};
        wasm_valtype_t* r[1] = {wasm_valtype_new_i32()};
        wasm_valtype_vec_t params;
        wasm_valtype_vec_t results;
        wasm_valtype_vec_new(&params, 3, p);
        wasm_valtype_vec_new(&results, 1, r);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);

        wasmtime_func_t f = makeFunc(wctx, ty, cb_get_state, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "getState", f, j_))
        {
            return finish(tecFAILED_PROCESSING);
        }
    }

    {
        wasm_valtype_t* p[3] = {
            wasm_valtype_new_i32(),
            wasm_valtype_new_i32(),
            wasm_valtype_new_i32()};
        wasm_valtype_t* r[1] = {wasm_valtype_new_i32()};
        wasm_valtype_vec_t params;
        wasm_valtype_vec_t results;
        wasm_valtype_vec_new(&params, 3, p);
        wasm_valtype_vec_new(&results, 1, r);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);

        wasmtime_func_t f = makeFunc(wctx, ty, cb_set_state, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "setState", f, j_))
        {
            return finish(tecFAILED_PROCESSING);
        }
    }

    {
        wasm_valtype_t* p[1] = {wasm_valtype_new_i32()};
        wasm_valtype_t* r[1] = {wasm_valtype_new_i32()};
        wasm_valtype_vec_t params;
        wasm_valtype_vec_t results;
        wasm_valtype_vec_new(&params, 1, p);
        wasm_valtype_vec_new(&results, 1, r);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);

        wasmtime_func_t f = makeFunc(wctx, ty, cb_delete_state, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "deleteState", f, j_))
        {
            return finish(tecFAILED_PROCESSING);
        }
    }

    {
        wasm_valtype_t* p[2] = {wasm_valtype_new_i32(), wasm_valtype_new_i32()};
        wasm_valtype_t* r[1] = {wasm_valtype_new_i32()};
        wasm_valtype_vec_t params;
        wasm_valtype_vec_t results;
        wasm_valtype_vec_new(&params, 2, p);
        wasm_valtype_vec_new(&results, 1, r);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);

        wasmtime_func_t f = makeFunc(wctx, ty, cb_get_params, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "getParams", f, j_))
        {
            return finish(tecFAILED_PROCESSING);
        }
    }

    {
        wasm_valtype_t* r[1] = {wasm_valtype_new_i32()};
        wasm_valtype_vec_t params;
        wasm_valtype_vec_t results;
        wasm_valtype_vec_new(&params, 0, nullptr);
        wasm_valtype_vec_new(&results, 1, r);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);

        wasmtime_func_t f = makeFunc(wctx, ty, cb_params_passed, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "paramsPassed", f, j_))
        {
            return finish(tecFAILED_PROCESSING);
        }
    }

    {
        wasm_valtype_t* p[2] = {wasm_valtype_new_i32(), wasm_valtype_new_i32()};
        wasm_valtype_vec_t params;
        wasm_valtype_vec_t results;
        wasm_valtype_vec_new(&params, 2, p);
        wasm_valtype_vec_new(&results, 0, nullptr);
        wasm_functype_t* ty = wasm_functype_new(&params, &results);

        wasmtime_func_t f = makeFunc(wctx, ty, cb_loop_guard, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "_g", f, j_))
        {
            return finish(tecFAILED_PROCESSING);
        }
    }

    wasmtime_instance_t instance;
    wasm_trap_t* trap = nullptr;
    if (TER const ter = logWasmtimeFailure(
            j_, wasmtime_linker_instantiate(linker, wctx, module, &instance, &trap), trap);
        ter != tesSUCCESS)
    {
        return finish(ter);
    }

    {
        wasmtime_extern_t ext;
        bool ok =
            wasmtime_instance_export_get(wctx, &instance, "memory", 6, &ext);
        if (!ok || ext.kind != WASMTIME_EXTERN_MEMORY)
        {
            JLOG(j_.error())
                << "Smart contract must export memory as \"memory\"";
            return finish(tecFAILED_PROCESSING);
        }
        st.memory = ext.of.memory;
        st.have_memory = true;
    }

    wasmtime_extern_t entry_ext;
    bool ok = wasmtime_instance_export_get(
        wctx, &instance, "entrypoint", 10, &entry_ext);
    if (!ok || entry_ext.kind != WASMTIME_EXTERN_FUNC)
    {
        JLOG(j_.error()) << "Smart contract entrypoint export missing";
        return finish(tecFAILED_PROCESSING);
    }

    wasmtime_func_t entry = entry_ext.of.func;
    wasmtime_val_t args[1];
    args[0].kind = WASMTIME_I64;
    args[0].of.i64 = static_cast<int64_t>(st.opt);

    wasmtime_val_t results[1];
    results[0].kind = WASMTIME_I32;

    if (TER const ter =
            logWasmtimeFailure(
                j_, wasmtime_func_call(wctx, &entry, args, 1, results, 1, &trap), trap);
        ter != tesSUCCESS)
    {
        return finish(ter);
    }

    if (st.callbackTer != tesSUCCESS)
    {
        return finish(st.callbackTer);
    }

    if (results[0].of.i32 != 0)
    {
        JLOG(j_.error())
            << "Smart contract entrypoint returned non-zero: "
            << results[0].of.i32;
        return finish(tecFAILED_PROCESSING);
    }

    return finish(tesSUCCESS);
}

}
