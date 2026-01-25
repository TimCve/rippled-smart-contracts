#include <xrpld/app/tx/detail/ContractCall.h>

#include <wasmtime.h>

#include <xrpl/basics/Log.h>
#include <xrpl/protocol/AccountID.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/protocol/smart_contract_abi.h>
#include <xrpld/ledger/View.h>

#include <cstring>
#include <string>

namespace ripple {
namespace {

static_assert(sizeof(addr_t) == ADDR_SIZE, "addr_t size mismatch");

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

wasm_trap_t*
useFuel(wasmtime_context_t* ctx, uint64_t amount, beast::Journal j)
{
    uint64_t fuel = 0;
    if (auto* err = wasmtime_context_get_fuel(ctx, &fuel); err)
    {
        logWasmtimeError(j, err);
        return makeTrap("fuel error");
    }

    if (fuel < amount)
        return makeTrap("out of fuel");

    if (auto* err = wasmtime_context_set_fuel(ctx, fuel - amount); err)
    {
        logWasmtimeError(j, err);
        return makeTrap("fuel error");
    }

    return nullptr;
}

struct HostState
{
    explicit HostState(beast::Journal const& journal) : j(journal)
    {
    }

    beast::Journal const& j;
    wasmtime_context_t* ctx = nullptr;

    bool have_memory = false;
    wasmtime_memory_t memory{};

    ApplyView* view = nullptr;
    AccountID caller;
    AccountID owner;
    TER callbackTer = tesSUCCESS;
};

uint8_t*
memData(HostState* st)
{
    return wasmtime_memory_data(st->ctx, &st->memory);
}

std::size_t
memSize(HostState* st)
{
    return wasmtime_memory_data_size(st->ctx, &st->memory);
}

wasm_trap_t*
cb_get_caller(
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
    if (auto trap = useFuel(wasmtime_caller_context(caller), 100, st->j);
        trap)
    {
        return trap;
    }

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
cb_get_owner(
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
    if (auto trap = useFuel(wasmtime_caller_context(caller), 100, st->j);
        trap)
    {
        return trap;
    }

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
cb_pay(
    void* env,
    wasmtime_caller_t* caller,
    wasmtime_val_t const* args,
    std::size_t nargs,
    wasmtime_val_t* results,
    std::size_t nresults)
{
    auto* st = reinterpret_cast<HostState*>(env);
    if (nargs != 2 || args[0].kind != WASMTIME_I32 ||
        args[1].kind != WASMTIME_I64)
    {
        return makeTrap("pay signature mismatch");
    }
    if (nresults != 1 || results[0].kind != WASMTIME_I32)
        return makeTrap("pay returns i32");
    if (!st->have_memory)
        return makeTrap("guest memory not available");

    uint32_t a_ptr = static_cast<uint32_t>(args[0].of.i32);
    int64_t amount = args[1].of.i64;

    if (auto trap = useFuel(wasmtime_caller_context(caller), 250, st->j);
        trap)
    {
        return trap;
    }

    if (st->callbackTer != tesSUCCESS)
    {
        results[0].of.i32 = -1;
        return nullptr;
    }

    std::size_t msz = memSize(st);
    if (static_cast<uint64_t>(a_ptr) + ADDR_SIZE > msz)
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    if (amount <= 0)
    {
        st->callbackTer = tecFAILED_PROCESSING;
        results[0].of.i32 = -1;
        return nullptr;
    }

    addr_t payee_addr{};
    std::memcpy(&payee_addr, memData(st) + a_ptr, ADDR_SIZE);
    AccountID payee = AccountID::fromVoid(payee_addr.bytes);

    STAmount xrpAmount{XRPAmount{amount}};
    if (TER const ter = transferXRP(*st->view, st->owner, payee, xrpAmount, st->j);
        ter != tesSUCCESS)
    {
        st->callbackTer = ter;
        results[0].of.i32 = -1;
        return nullptr;
    }

    results[0].of.i32 = 0;
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
            nameEq(name, "get_caller") || nameEq(name, "get_owner") ||
            nameEq(name, "pay");
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

TER
ContractCall::preclaim(PreclaimContext const& ctx)
{
    auto const contractAddress = ctx.tx[sfContractAddress];
    auto const sleContract = ctx.view.read(keylet::smartContract(contractAddress));
    if(!sleContract)
        return tecNO_ENTRY;

    return tesSUCCESS;
}

TER
ContractCall::doApply()
{
    auto const contractAddress = ctx_.tx[sfContractAddress];
    auto const sleContract = view().read(keylet::smartContract(contractAddress));
    if (!sleContract)
        return tecNO_ENTRY;

    auto const& code = sleContract->getFieldVL(sfContractCode);
    if (code.empty())
        return tecFAILED_PROCESSING;

    HostState st{j_};
    st.view = &view();
    st.caller = account_;
    st.owner = sleContract->getAccountID(sfAccount);

    wasm_config_t* config = wasm_config_new();
    wasmtime_config_consume_fuel_set(config, true);

    wasm_engine_t* engine = wasm_engine_new_with_config(config);
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
        if (engine)
            wasm_engine_delete(engine);
    };

    constexpr uint64_t kFuelBudget = 50'000;
    if (TER const ter =
            logWasmtimeFailure(j_, wasmtime_context_set_fuel(wctx, kFuelBudget), nullptr);
        ter != tesSUCCESS)
    {
        cleanup();
        return ter;
    }

    if (TER const ter =
            logWasmtimeFailure(j_, wasmtime_module_new(engine, code.data(), code.size(), &module), nullptr);
        ter != tesSUCCESS)
    {
        cleanup();
        return ter;
    }

    if (!enforceImportPolicy(module, j_) || !enforceExportPolicy(module, j_))
    {
        cleanup();
        return tecFAILED_PROCESSING;
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

        wasmtime_func_t f = makeFunc(wctx, ty, cb_get_caller, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "get_caller", f, j_))
        {
            cleanup();
            return tecFAILED_PROCESSING;
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

        wasmtime_func_t f = makeFunc(wctx, ty, cb_get_owner, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "get_owner", f, j_))
        {
            cleanup();
            return tecFAILED_PROCESSING;
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

        wasmtime_func_t f = makeFunc(wctx, ty, cb_pay, &st);
        wasm_functype_delete(ty);
        if (!defineFunc(linker, wctx, SC_HOST_MOD, "pay", f, j_))
        {
            cleanup();
            return tecFAILED_PROCESSING;
        }
    }

    wasmtime_instance_t instance;
    wasm_trap_t* trap = nullptr;
    if (TER const ter = logWasmtimeFailure(
            j_, wasmtime_linker_instantiate(linker, wctx, module, &instance, &trap), trap);
        ter != tesSUCCESS)
    {
        cleanup();
        return ter;
    }

    {
        wasmtime_extern_t ext;
        bool ok =
            wasmtime_instance_export_get(wctx, &instance, "memory", 6, &ext);
        if (!ok || ext.kind != WASMTIME_EXTERN_MEMORY)
        {
            JLOG(j_.error())
                << "Smart contract must export memory as \"memory\"";
            cleanup();
            return tecFAILED_PROCESSING;
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
        cleanup();
        return tecFAILED_PROCESSING;
    }

    wasmtime_func_t entry = entry_ext.of.func;
    wasmtime_val_t args[1];
    args[0].kind = WASMTIME_I32;
    args[0].of.i32 = 0;

    wasmtime_val_t results[1];
    results[0].kind = WASMTIME_I32;

    if (TER const ter =
            logWasmtimeFailure(
                j_, wasmtime_func_call(wctx, &entry, args, 1, results, 1, &trap), trap);
        ter != tesSUCCESS)
    {
        cleanup();
        return ter;
    }

    if (st.callbackTer != tesSUCCESS)
    {
        cleanup();
        return st.callbackTer;
    }

    if (results[0].of.i32 != 0)
    {
        JLOG(j_.error())
            << "Smart contract entrypoint returned non-zero: "
            << results[0].of.i32;
        cleanup();
        return tecFAILED_PROCESSING;
    }

    cleanup();
    return tesSUCCESS;
}

}
