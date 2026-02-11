#include <xrpld/app/tx/detail/ContractDeploy.h>
#include <xrpld/ledger/View.h>

#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/digest.h>
#include <xrpl/basics/Log.h>
#include <unordered_map>
#include <unordered_set>
#include <stdexcept>
#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <binaryen-c.h>

#include <xrpl/protocol/smart_contract_abi.h>

namespace ripple {
namespace {

bool
isAllDigits(std::string const& s)
{
    return !s.empty() &&
        std::all_of(s.begin(), s.end(), [](unsigned char c) {
            return std::isdigit(c) != 0;
        });
}

bool
isNonEmptyCStr(char const* s)
{
    return s && s[0] != '\0';
}

std::string
normalizeFunctionName(std::string name)
{
    if (!name.empty() && name.front() == '$')
        name.erase(name.begin());
    return name;
}

std::string
readToken(std::string const& text, std::size_t& pos)
{
    while (pos < text.size() &&
           std::isspace(static_cast<unsigned char>(text[pos])))
        ++pos;

    if (pos >= text.size())
        return {};

    char const c = text[pos];
    if (c == '(' || c == ')')
    {
        ++pos;
        return std::string(1, c);
    }

    if (c == '"')
    {
        std::size_t start = pos++;
        bool escaped = false;
        while (pos < text.size())
        {
            char const ch = text[pos++];
            if (escaped)
            {
                escaped = false;
                continue;
            }
            if (ch == '\\')
            {
                escaped = true;
                continue;
            }
            if (ch == '"')
                break;
        }
        return text.substr(start, pos - start);
    }

    std::size_t const start = pos;
    while (pos < text.size() &&
           !std::isspace(static_cast<unsigned char>(text[pos])) &&
           text[pos] != '(' && text[pos] != ')')
    {
        ++pos;
    }
    return text.substr(start, pos - start);
}

std::size_t
findMatchingParen(std::string const& text, std::size_t openPos)
{
    std::size_t depth = 0;
    bool inString = false;
    bool escaped = false;

    for (std::size_t i = openPos; i < text.size(); ++i)
    {
        char const c = text[i];
        if (inString)
        {
            if (escaped)
            {
                escaped = false;
                continue;
            }
            if (c == '\\')
            {
                escaped = true;
                continue;
            }
            if (c == '"')
                inString = false;
            continue;
        }

        if (c == '"')
        {
            inString = true;
            continue;
        }

        if (c == '(')
            ++depth;
        else if (c == ')')
        {
            if (depth == 0)
                return std::string::npos;
            --depth;
            if (depth == 0)
                return i;
        }
    }
    return std::string::npos;
}

// Shared host-ABI import policy and metering table.
constexpr std::array<std::pair<char const*, std::uint64_t>, 13>
    kHostImportCosts{{
        {"_g", 1},
        {"getCallerAddr", 20},
        {"getOwnerAddr", 20},
        {"getLedgerTimestamp", 20},
        {"lockCallerXRP", 80},
        {"lockOwnerXRP", 80},
        {"unlockXRP", 80},
        {"createSmartObject", 150},
        {"getSmartObject", 100},
        {"setSmartObject", 150},
        {"deleteSmartObject", 120},
        {"getParams", 30},
        {"paramsPassed", 10},
    }};

class ModuleHandle
{
    BinaryenModuleRef module_ = nullptr;

public:
    ModuleHandle(void const* data, std::size_t size)
    {
        module_ = BinaryenModuleRead(
            const_cast<char*>(static_cast<char const*>(data)), size);
        if (!module_)
            throw std::runtime_error("BinaryenModuleRead failed");
        if (!BinaryenModuleValidate(module_))
            throw std::runtime_error(
                "Invalid wasm (BinaryenModuleValidate failed)");
    }

    ~ModuleHandle()
    {
        if (module_)
            BinaryenModuleDispose(module_);
    }

    BinaryenModuleRef
    get() const
    {
        return module_;
    }

    // Binaryen allocates text with malloc; mirror that lifetime here.
    std::string
    toText() const
    {
        char* txt = BinaryenModuleAllocateAndWriteText(module_);
        if (!txt)
            throw std::runtime_error("BinaryenModuleAllocateAndWriteText failed");
        std::string out = txt;
        std::free(txt);
        return out;
    }
};

BinaryenFunctionRef
getFunctionByNameOrIndex(BinaryenModuleRef m, std::string const& nameOrIndex)
{
    if (BinaryenFunctionRef f = BinaryenGetFunction(m, nameOrIndex.c_str()))
        return f;
    if (isAllDigits(nameOrIndex))
    {
        unsigned long idx = std::stoul(nameOrIndex);
        BinaryenIndex n = BinaryenGetNumFunctions(m);
        if (idx >= n)
            throw std::runtime_error(
                "Function index out of range: " + nameOrIndex);
        return BinaryenGetFunctionByIndex(m, static_cast<BinaryenIndex>(idx));
    }
    return nullptr;
}

struct CostModel
{
    std::uint64_t base = 1;
    std::uint64_t internalCallOverhead = 2;

    std::unordered_map<std::string, std::uint64_t> importCost;

    std::string guardMod = SC_HOST_MOD;
    std::string guardBase = "_g";

    std::uint64_t
    costImported(std::string const& mod, std::string const& baseName) const
    {
        std::string key = mod + "." + baseName;
        auto it = importCost.find(key);
        if (it == importCost.end())
        {
            std::string msg =
                "Imported function has no declared cost: " + key +
                "\nKnown keys:\n";
            for (auto const& kv : importCost)
                msg += "  - " + kv.first + "\n";
            throw std::runtime_error(msg);
        }
        return it->second;
    }
};

CostModel
makeCostModel()
{
    CostModel cm;
    std::string const mod = SC_HOST_MOD;
    for (auto const& [name, cost] : kHostImportCosts)
        cm.importCost.emplace(mod + "." + name, cost);
    return cm;
}

std::unordered_set<std::string>
makeAllowedHostImports()
{
    std::unordered_set<std::string> allowed;
    allowed.reserve(kHostImportCosts.size());
    for (auto const& import : kHostImportCosts)
        allowed.emplace(import.first);
    return allowed;
}

struct FuncInfo
{
    BinaryenFunctionRef ref = nullptr;
    bool isImport = false;
    std::string importModule;
    std::string importBase;
    std::string canonicalName;
};

FuncInfo
getFuncInfo(BinaryenModuleRef m, std::string const& funcNameOrIndex)
{
    FuncInfo out;
    out.ref = getFunctionByNameOrIndex(m, funcNameOrIndex);
    if (!out.ref)
        throw std::runtime_error("Missing function: " + funcNameOrIndex);

    out.canonicalName = BinaryenFunctionGetName(out.ref);

    char const* imod = BinaryenFunctionImportGetModule(out.ref);
    char const* ibase = BinaryenFunctionImportGetBase(out.ref);
    if (isNonEmptyCStr(imod) && isNonEmptyCStr(ibase))
    {
        out.isImport = true;
        out.importModule = imod;
        out.importBase = ibase;
    }
    return out;
}

// Computes conservative worst-case execution cost for a validated module.
class Analyzer
{
private:
    BinaryenModuleRef m;
    CostModel cm;

    enum class Mark
    {
        White,
        Gray,
        Black
    };
    std::unordered_map<std::string, Mark> marks;
    std::unordered_map<std::string, std::uint64_t> memo;

public:
    Analyzer(BinaryenModuleRef mod, CostModel model)
        : m(mod), cm(std::move(model))
    {
    }

private:
    struct Outcomes
    {
        bool canContinue = false;
        std::uint64_t continueCost = 0;
        bool canExit = false;
        std::uint64_t exitCost = 0;
    };

    struct IterOut
    {
        bool canContinue = false;
        std::uint64_t continueCost = 0;
        Outcomes bubble;
    };

    struct LabelFrame
    {
        std::string name;
        bool isLoop = false;
        std::uint64_t kExit = 0;
        Outcomes out;
        IterOut iterOut;
    };

    static std::uint64_t
    worst(std::uint64_t a, std::uint64_t b)
    {
        return a > b ? a : b;
    }

    static std::uint64_t
    scalarFromOutcomes(Outcomes const& o)
    {
        if (o.canContinue && o.canExit)
            return worst(o.continueCost, o.exitCost);
        if (o.canContinue)
            return o.continueCost;
        if (o.canExit)
            return o.exitCost;
        return 0;
    }

    static Outcomes
    addCost(Outcomes const& o, std::uint64_t add)
    {
        Outcomes r = o;
        if (r.canContinue)
            r.continueCost += add;
        if (r.canExit)
            r.exitCost += add;
        return r;
    }

    static Outcomes
    mergeMax(Outcomes const& a, Outcomes const& b)
    {
        Outcomes r;
        if (a.canContinue || b.canContinue)
        {
            r.canContinue = true;
            std::uint64_t av = a.canContinue ? a.continueCost : 0;
            std::uint64_t bv = b.canContinue ? b.continueCost : 0;
            r.continueCost = worst(av, bv);
        }
        if (a.canExit || b.canExit)
        {
            r.canExit = true;
            std::uint64_t av = a.canExit ? a.exitCost : 0;
            std::uint64_t bv = b.canExit ? b.exitCost : 0;
            r.exitCost = worst(av, bv);
        }
        return r;
    }

    static Outcomes
    exitOnly(std::uint64_t cost)
    {
        Outcomes o;
        o.canExit = true;
        o.exitCost = cost;
        return o;
    }

    static Outcomes
    continueOnly(std::uint64_t cost)
    {
        Outcomes o;
        o.canContinue = true;
        o.continueCost = cost;
        return o;
    }

    static Outcomes
    flattenIterOut(IterOut const& o)
    {
        Outcomes r = o.bubble;
        if (o.canContinue)
        {
            Outcomes c = continueOnly(o.continueCost);
            r = mergeMax(r, c);
        }
        return r;
    }

    static IterOut
    iterFromOutcomes(Outcomes const& o)
    {
        IterOut r;
        r.bubble = o;
        return r;
    }

    static IterOut
    addCostIter(IterOut const& o, std::uint64_t add)
    {
        IterOut r = o;
        if (r.canContinue)
            r.continueCost += add;
        r.bubble = addCost(r.bubble, add);
        return r;
    }

    static IterOut
    mergeMaxIter(IterOut const& a, IterOut const& b)
    {
        IterOut r;
        if (a.canContinue || b.canContinue)
        {
            r.canContinue = true;
            std::uint64_t av = a.canContinue ? a.continueCost : 0;
            std::uint64_t bv = b.canContinue ? b.continueCost : 0;
            r.continueCost = worst(av, bv);
        }
        r.bubble = mergeMax(a.bubble, b.bubble);
        return r;
    }

    static IterOut
    iterContinueOnly(std::uint64_t cost)
    {
        IterOut r;
        r.canContinue = true;
        r.continueCost = cost;
        return r;
    }

public:
    std::uint64_t
    costFunctionWorst(std::string const& funcNameOrIndex)
    {
        FuncInfo fi0 = getFuncInfo(m, funcNameOrIndex);
        std::string const& cname = fi0.canonicalName;

        auto it = memo.find(cname);
        if (it != memo.end())
            return it->second;

        auto& mark = marks[cname];
        if (mark == Mark::Gray)
            throw std::runtime_error("Recursion detected at: " + cname);
        if (mark == Mark::Black)
            return memo[cname];

        mark = Mark::Gray;

        if (fi0.isImport)
        {
            std::uint64_t c = cm.costImported(fi0.importModule, fi0.importBase);
            memo[cname] = c;
            mark = Mark::Black;
            return c;
        }

        BinaryenExpressionRef body = BinaryenFunctionGetBody(fi0.ref);
        std::vector<LabelFrame> stack;
        std::uint64_t cost = costExpr(body, 0, stack);

        memo[cname] = cost;
        mark = Mark::Black;
        return cost;
    }

private:
    static std::vector<BinaryenExpressionRef>
    blockChildren(BinaryenExpressionRef b)
    {
        std::vector<BinaryenExpressionRef> kids;
        BinaryenIndex n = BinaryenBlockGetNumChildren(b);
        kids.reserve(n);
        for (BinaryenIndex i = 0; i < n; i++)
            kids.push_back(BinaryenBlockGetChildAt(b, i));
        return kids;
    }

    std::uint64_t
    resolveTargetK(
        std::string const& tgt,
        std::vector<LabelFrame> const& stack,
        bool& targetIsLoop)
    {
        if (isAllDigits(tgt))
        {
            std::size_t depth = static_cast<std::size_t>(std::stoul(tgt));
            if (depth >= stack.size())
                throw std::runtime_error("br depth out of range: " + tgt);
            LabelFrame const& f = stack[stack.size() - 1 - depth];
            targetIsLoop = f.isLoop;
            return f.kExit;
        }

        for (auto it = stack.rbegin(); it != stack.rend(); ++it)
        {
            if (it->name == tgt)
            {
                targetIsLoop = it->isLoop;
                return it->kExit;
            }
        }
        throw std::runtime_error("Branch target label not found: '" + tgt + "'");
    }

    std::size_t
    resolveTargetIndex(
        std::string const& tgt,
        std::vector<LabelFrame> const& stack)
    {
        if (isAllDigits(tgt))
        {
            std::size_t depth = static_cast<std::size_t>(std::stoul(tgt));
            if (depth >= stack.size())
                throw std::runtime_error("br depth out of range: " + tgt);
            return stack.size() - 1 - depth;
        }

        for (std::size_t i = stack.size(); i-- > 0;)
        {
            if (stack[i].name == tgt)
                return i;
        }
        throw std::runtime_error("Branch target label not found: '" + tgt + "'");
    }

    IterOut
    costLoopBodyIter(
        BinaryenExpressionRef e,
        IterOut const& k,
        std::vector<LabelFrame>& stack,
        std::size_t loopDepth)
    {
        if (!e)
            return k;

        auto id = BinaryenExpressionGetId(e);
        std::uint64_t const node = cm.base;

        if (id == BinaryenBlockId())
        {
            std::string name = "";
            if (char const* nm = BinaryenBlockGetName(e))
                name = nm;

            Outcomes kOut = flattenIterOut(k);
            LabelFrame frame{
                name,
                false,
                scalarFromOutcomes(kOut),
                kOut,
                k};
            stack.push_back(frame);

            auto kids = blockChildren(e);
            IterOut acc = k;
            for (std::size_t i = kids.size(); i-- > 0;)
            {
                acc = costLoopBodyIter(kids[i], acc, stack, loopDepth);
            }

            stack.pop_back();
            return addCostIter(acc, node);
        }

        if (id == BinaryenIfId())
        {
            Outcomes kOut = flattenIterOut(k);
            stack.push_back(
                LabelFrame{"", false, scalarFromOutcomes(kOut), kOut, k});

            auto cond = BinaryenIfGetCondition(e);
            auto t = BinaryenIfGetIfTrue(e);
            auto f = BinaryenIfGetIfFalse(e);

            std::uint64_t condCost = costExpr(cond, 0, stack);
            IterOut tOut = costLoopBodyIter(t, k, stack, loopDepth);
            IterOut fOut = f ? costLoopBodyIter(f, k, stack, loopDepth) : k;

            stack.pop_back();
            return addCostIter(mergeMaxIter(tOut, fOut), node + condCost);
        }

        if (id == BinaryenLoopId())
        {
            Outcomes loopOut = costLoopOutcomes(e, flattenIterOut(k), stack);
            return addCostIter(iterFromOutcomes(loopOut), 0);
        }

        if (id == BinaryenBreakId())
        {
            std::string tgt = "";
            if (char const* nm = BinaryenBreakGetName(e))
                tgt = nm;

            auto cond = BinaryenBreakGetCondition(e);
            auto val = BinaryenBreakGetValue(e);

            std::uint64_t valCost = val ? costExpr(val, 0, stack) : 0;
            std::uint64_t condCost = cond ? costExpr(cond, 0, stack) : 0;
            std::uint64_t baseCost = node + valCost + condCost;

            std::size_t idx = resolveTargetIndex(tgt, stack);

            IterOut takeOut;
            if (idx == loopDepth)
            {
                takeOut = iterContinueOnly(0);
            }
            else if (idx > loopDepth)
            {
                takeOut = stack[idx].iterOut;
            }
            else
            {
                takeOut = iterFromOutcomes(stack[idx].out);
            }

            if (!cond)
            {
                return addCostIter(takeOut, baseCost);
            }

            IterOut taken = addCostIter(takeOut, baseCost);
            IterOut notTaken = addCostIter(k, baseCost);
            return mergeMaxIter(taken, notTaken);
        }

        if (id == BinaryenSwitchId())
        {
            auto cnd = BinaryenSwitchGetCondition(e);
            auto val = BinaryenSwitchGetValue(e);

            std::uint64_t cCost = cnd ? costExpr(cnd, 0, stack) : 0;
            std::uint64_t vCost = val ? costExpr(val, 0, stack) : 0;

            IterOut best;
            BinaryenIndex n = BinaryenSwitchGetNumNames(e);
            for (BinaryenIndex i = 0; i < n; i++)
            {
                std::string tgt = BinaryenSwitchGetNameAt(e, i);
                std::size_t idx = resolveTargetIndex(tgt, stack);
                IterOut takeOut;
                if (idx == loopDepth)
                {
                    takeOut = iterContinueOnly(0);
                }
                else if (idx > loopDepth)
                {
                    takeOut = stack[idx].iterOut;
                }
                else
                {
                    takeOut = iterFromOutcomes(stack[idx].out);
                }
                best = mergeMaxIter(best, takeOut);
            }
            std::string def = BinaryenSwitchGetDefaultName(e);
            if (!def.empty())
            {
                std::size_t idx = resolveTargetIndex(def, stack);
                IterOut takeOut;
                if (idx == loopDepth)
                {
                    takeOut = iterContinueOnly(0);
                }
                else if (idx > loopDepth)
                {
                    takeOut = stack[idx].iterOut;
                }
                else
                {
                    takeOut = iterFromOutcomes(stack[idx].out);
                }
                best = mergeMaxIter(best, takeOut);
            }

            return addCostIter(best, node + cCost + vCost);
        }

        if (id == BinaryenReturnId())
        {
            auto v = BinaryenReturnGetValue(e);
            std::uint64_t vCost = v ? costExpr(v, 0, stack) : 0;
            return iterFromOutcomes(exitOnly(node + vCost));
        }

        std::uint64_t scalar = costExpr(e, 0, stack);
        return addCostIter(k, scalar);
    }

    Outcomes
    costLoopOutcomes(
        BinaryenExpressionRef e,
        Outcomes const& k,
        std::vector<LabelFrame>& stack)
    {
        std::string loopName = "";
        if (char const* nm = BinaryenLoopGetName(e))
            loopName = nm;

        auto body = BinaryenLoopGetBody(e);
        std::uint32_t N = extractLoopGuardOrFail(body);

        IterOut endIter = iterFromOutcomes(k);

        stack.push_back(LabelFrame{
            loopName,
            true,
            scalarFromOutcomes(k),
            continueOnly(0),
            endIter});
        std::size_t loopDepth = stack.size() - 1;

        IterOut bodyOut = costLoopBodyIter(body, endIter, stack, loopDepth);

        stack.pop_back();

        Outcomes res = bodyOut.bubble;
        if (bodyOut.canContinue)
        {
            res = addCost(res, (static_cast<std::uint64_t>(N) - 1) *
                                   bodyOut.continueCost);
        }
        res = addCost(res, cm.base);
        return res;
    }

    Outcomes
    costExprOutcomes(
        BinaryenExpressionRef e,
        Outcomes const& k,
        std::vector<LabelFrame>& stack,
        std::size_t loopDepth)
    {
        if (!e)
            return k;

        auto id = BinaryenExpressionGetId(e);
        std::uint64_t const node = cm.base;

        if (id == BinaryenBlockId())
        {
            std::string name = "";
            if (char const* nm = BinaryenBlockGetName(e))
                name = nm;

            LabelFrame frame{
                name,
                false,
                scalarFromOutcomes(k),
                k,
                iterFromOutcomes(k)};
            stack.push_back(frame);

            auto kids = blockChildren(e);
            Outcomes acc = k;
            for (std::size_t i = kids.size(); i-- > 0;)
            {
                acc = costExprOutcomes(kids[i], acc, stack, loopDepth);
            }

            stack.pop_back();
            return addCost(acc, node);
        }

        if (id == BinaryenIfId())
        {
            stack.push_back(LabelFrame{
                "", false, scalarFromOutcomes(k), k, iterFromOutcomes(k)});

            auto cond = BinaryenIfGetCondition(e);
            auto t = BinaryenIfGetIfTrue(e);
            auto f = BinaryenIfGetIfFalse(e);

            std::uint64_t condCost = costExpr(cond, 0, stack);
            Outcomes tOut = costExprOutcomes(t, k, stack, loopDepth);
            Outcomes fOut = f ? costExprOutcomes(f, k, stack, loopDepth) : k;

            stack.pop_back();
            return addCost(mergeMax(tOut, fOut), node + condCost);
        }

        if (id == BinaryenLoopId())
            return costLoopOutcomes(e, k, stack);

        if (id == BinaryenBreakId())
        {
            std::string tgt = "";
            if (char const* nm = BinaryenBreakGetName(e))
                tgt = nm;

            auto cond = BinaryenBreakGetCondition(e);
            auto val = BinaryenBreakGetValue(e);

            std::uint64_t valCost = val ? costExpr(val, 0, stack) : 0;
            std::uint64_t condCost = cond ? costExpr(cond, 0, stack) : 0;
            std::uint64_t baseCost = node + valCost + condCost;

            std::size_t idx = resolveTargetIndex(tgt, stack);

            Outcomes takeOut =
                (idx == loopDepth) ? continueOnly(0) : stack[idx].out;

            if (!cond)
                return addCost(takeOut, baseCost);

            Outcomes taken = addCost(takeOut, baseCost);
            Outcomes notTaken = addCost(k, baseCost);
            return mergeMax(taken, notTaken);
        }

        if (id == BinaryenSwitchId())
        {
            auto cnd = BinaryenSwitchGetCondition(e);
            auto val = BinaryenSwitchGetValue(e);

            std::uint64_t cCost = cnd ? costExpr(cnd, 0, stack) : 0;
            std::uint64_t vCost = val ? costExpr(val, 0, stack) : 0;

            Outcomes best;
            BinaryenIndex n = BinaryenSwitchGetNumNames(e);
            for (BinaryenIndex i = 0; i < n; i++)
            {
                std::string tgt = BinaryenSwitchGetNameAt(e, i);
                std::size_t idx = resolveTargetIndex(tgt, stack);
                Outcomes takeOut =
                    (idx == loopDepth) ? continueOnly(0) : stack[idx].out;
                best = mergeMax(best, takeOut);
            }
            std::string def = BinaryenSwitchGetDefaultName(e);
            if (!def.empty())
            {
                std::size_t idx = resolveTargetIndex(def, stack);
                Outcomes takeOut =
                    (idx == loopDepth) ? continueOnly(0) : stack[idx].out;
                best = mergeMax(best, takeOut);
            }

            return addCost(best, node + cCost + vCost);
        }

        if (id == BinaryenReturnId())
        {
            auto v = BinaryenReturnGetValue(e);
            std::uint64_t vCost = v ? costExpr(v, 0, stack) : 0;
            return exitOnly(node + vCost);
        }

        std::uint64_t scalar = costExpr(e, 0, stack);
        return addCost(k, scalar);
    }

    std::uint32_t
    extractLoopGuardOrFail(BinaryenExpressionRef loopBody)
    {
        BinaryenExpressionRef first = nullptr;
        auto id = BinaryenExpressionGetId(loopBody);

        if (id == BinaryenBlockId())
        {
            BinaryenIndex n = BinaryenBlockGetNumChildren(loopBody);
            for (BinaryenIndex i = 0; i < n; i++)
            {
                auto c = BinaryenBlockGetChildAt(loopBody, i);
                if (BinaryenExpressionGetId(c) != BinaryenNopId())
                {
                    first = c;
                    break;
                }
            }
        }
        else
        {
            first = loopBody;
        }

        if (!first || BinaryenExpressionGetId(first) != BinaryenCallId())
            throw std::runtime_error(
                "Loop guard missing: first non-nop in loop is not a call");

        std::string target = BinaryenCallGetTarget(first);
        FuncInfo fi = getFuncInfo(m, target);

        if (!fi.isImport || fi.importModule != cm.guardMod ||
            fi.importBase != cm.guardBase)
        {
            throw std::runtime_error(
                "Loop guard missing: expected " + cm.guardMod + "." +
                cm.guardBase);
        }

        if (BinaryenCallGetNumOperands(first) != 2)
        {
            throw std::runtime_error(
                "_g must have exactly 2 operands (id, i32.const max_iters)");
        }

        auto op1 = BinaryenCallGetOperandAt(first, 1);
        if (BinaryenExpressionGetId(op1) != BinaryenConstId())
        {
            throw std::runtime_error("_g max_iters must be i32.const");
        }

        std::int32_t n = BinaryenConstGetValueI32(op1);
        if (n <= 0)
            throw std::runtime_error("_g max_iters must be > 0");
        return static_cast<std::uint32_t>(n);
    }

    std::uint64_t
    costExpr(
        BinaryenExpressionRef e,
        std::uint64_t k,
        std::vector<LabelFrame>& stack)
    {
        if (!e)
            return k;

        auto id = BinaryenExpressionGetId(e);
        std::uint64_t const node = cm.base;

        if (id == BinaryenBlockId())
        {
            std::string name = "";
            if (char const* nm = BinaryenBlockGetName(e))
                name = nm;

            stack.push_back(LabelFrame{
                name,
                false,
                k,
                exitOnly(k),
                iterFromOutcomes(exitOnly(k))});

            auto kids = blockChildren(e);
            std::uint64_t acc = k;
            for (std::size_t i = kids.size(); i-- > 0;)
            {
                acc = costExpr(kids[i], acc, stack);
            }

            stack.pop_back();
            return node + acc;
        }

        if (id == BinaryenIfId())
        {
            stack.push_back(LabelFrame{
                "", false, k, exitOnly(k), iterFromOutcomes(exitOnly(k))});

            auto cond = BinaryenIfGetCondition(e);
            auto t = BinaryenIfGetIfTrue(e);
            auto f = BinaryenIfGetIfFalse(e);

            std::uint64_t condCost = costExpr(cond, 0, stack);
            std::uint64_t tCost = costExpr(t, k, stack);
            std::uint64_t fCost = f ? costExpr(f, k, stack) : k;

            stack.pop_back();
            return node + condCost + worst(tCost, fCost);
        }

        if (id == BinaryenLoopId())
        {
            std::string loopName = "";
            if (char const* nm = BinaryenLoopGetName(e))
                loopName = nm;

            auto body = BinaryenLoopGetBody(e);
            std::uint32_t N = extractLoopGuardOrFail(body);

            Outcomes endOut = exitOnly(k);
            stack.push_back(LabelFrame{
                loopName,
                true,
                k,
                continueOnly(0),
                iterFromOutcomes(endOut)});
            std::size_t loopDepth = stack.size() - 1;

            Outcomes bodyOut = costExprOutcomes(body, endOut, stack, loopDepth);

            stack.pop_back();

            if (bodyOut.canContinue)
            {
                if (bodyOut.canExit)
                {
                    return node +
                        (static_cast<std::uint64_t>(N) - 1) *
                            bodyOut.continueCost +
                        bodyOut.exitCost;
                }
                return node +
                    static_cast<std::uint64_t>(N) * bodyOut.continueCost + k;
            }
            if (bodyOut.canExit)
                return node + bodyOut.exitCost;
            return node + k;
        }

        if (id == BinaryenBreakId())
        {
            std::string tgt = "";
            if (char const* nm = BinaryenBreakGetName(e))
                tgt = nm;

            auto cond = BinaryenBreakGetCondition(e);
            auto val = BinaryenBreakGetValue(e);

            std::uint64_t valCost = val ? costExpr(val, 0, stack) : 0;
            std::uint64_t condCost = cond ? costExpr(cond, 0, stack) : 0;

            bool targetIsLoop = false;
            std::uint64_t kTargetExit = resolveTargetK(tgt, stack, targetIsLoop);
            std::uint64_t takeK = targetIsLoop ? 0 : kTargetExit;

            if (!cond)
                return node + valCost + takeK;

            return node + valCost + condCost + worst(takeK, k);
        }

        if (id == BinaryenSwitchId())
        {
            auto cnd = BinaryenSwitchGetCondition(e);
            auto val = BinaryenSwitchGetValue(e);

            std::uint64_t cCost = cnd ? costExpr(cnd, 0, stack) : 0;
            std::uint64_t vCost = val ? costExpr(val, 0, stack) : 0;

            std::uint64_t best = 0;
            BinaryenIndex n = BinaryenSwitchGetNumNames(e);
            for (BinaryenIndex i = 0; i < n; i++)
            {
                std::string tgt = BinaryenSwitchGetNameAt(e, i);
                bool isLoop = false;
                std::uint64_t kExit = resolveTargetK(tgt, stack, isLoop);
                std::uint64_t takeK = isLoop ? 0 : kExit;
                best = worst(best, takeK);
            }
            std::string def = BinaryenSwitchGetDefaultName(e);
            if (!def.empty())
            {
                bool isLoop = false;
                std::uint64_t kExit = resolveTargetK(def, stack, isLoop);
                std::uint64_t takeK = isLoop ? 0 : kExit;
                best = worst(best, takeK);
            }

            return node + cCost + vCost + best;
        }

        if (id == BinaryenReturnId())
        {
            auto v = BinaryenReturnGetValue(e);
            std::uint64_t vCost = v ? costExpr(v, 0, stack) : 0;
            return node + vCost;
        }

        if (id == BinaryenCallId())
        {
            std::string target = BinaryenCallGetTarget(e);

            std::uint64_t ops = 0;
            BinaryenIndex n = BinaryenCallGetNumOperands(e);
            for (BinaryenIndex i = 0; i < n; i++)
            {
                ops += costExpr(BinaryenCallGetOperandAt(e, i), 0, stack);
            }

            FuncInfo fi = getFuncInfo(m, target);
            std::uint64_t callCost = 0;
            if (fi.isImport)
            {
                callCost = cm.costImported(fi.importModule, fi.importBase);
            }
            else
            {
                callCost = cm.internalCallOverhead +
                    costFunctionWorst(fi.canonicalName);
            }

            return node + ops + callCost + k;
        }

        if (id == BinaryenSelectId())
        {
            auto t = BinaryenSelectGetIfTrue(e);
            auto f = BinaryenSelectGetIfFalse(e);
            auto c = BinaryenSelectGetCondition(e);

            std::uint64_t tCost = costExpr(t, 0, stack);
            std::uint64_t fCost = costExpr(f, 0, stack);
            std::uint64_t cCost = costExpr(c, 0, stack);
            return node + tCost + fCost + cCost + k;
        }

        // Recurse through common scalar wrappers so nested calls are metered.
        if (id == BinaryenUnaryId())
        {
            auto v = BinaryenUnaryGetValue(e);
            return node + costExpr(v, 0, stack) + k;
        }

        if (id == BinaryenBinaryId())
        {
            auto l = BinaryenBinaryGetLeft(e);
            auto r = BinaryenBinaryGetRight(e);
            return node + costExpr(l, 0, stack) + costExpr(r, 0, stack) + k;
        }

        if (id == BinaryenLocalSetId())
        {
            auto v = BinaryenLocalSetGetValue(e);
            return node + costExpr(v, 0, stack) + k;
        }

        if (id == BinaryenGlobalSetId())
        {
            auto v = BinaryenGlobalSetGetValue(e);
            return node + costExpr(v, 0, stack) + k;
        }

        if (id == BinaryenLoadId())
        {
            auto p = BinaryenLoadGetPtr(e);
            return node + costExpr(p, 0, stack) + k;
        }

        if (id == BinaryenStoreId())
        {
            auto p = BinaryenStoreGetPtr(e);
            auto v = BinaryenStoreGetValue(e);
            return node + costExpr(p, 0, stack) + costExpr(v, 0, stack) + k;
        }

        if (id == BinaryenDropId())
        {
            auto v = BinaryenDropGetValue(e);
            return node + costExpr(v, 0, stack) + k;
        }

        if (id == BinaryenRefIsNullId())
        {
            auto v = BinaryenRefIsNullGetValue(e);
            return node + costExpr(v, 0, stack) + k;
        }

        if (id == BinaryenTableGetId())
        {
            auto i = BinaryenTableGetGetIndex(e);
            return node + costExpr(i, 0, stack) + k;
        }

        if (id == BinaryenTableSetId())
        {
            auto i = BinaryenTableSetGetIndex(e);
            auto v = BinaryenTableSetGetValue(e);
            return node + costExpr(i, 0, stack) + costExpr(v, 0, stack) + k;
        }

        return node + k;
    }
};

std::string
getEntrypointFunctionCanonicalName(BinaryenModuleRef m)
{
    BinaryenIndex n = BinaryenGetNumExports(m);
    std::size_t funcExports = 0;
    bool sawEntry = false;
    std::string entryValue;

    for (BinaryenIndex i = 0; i < n; ++i)
    {
        BinaryenExportRef ex = BinaryenGetExportByIndex(m, i);
        auto kind = BinaryenExportGetKind(ex);
        char const* exportNameC = BinaryenExportGetName(ex);
        std::string exportName = exportNameC ? exportNameC : "";

        if (kind == BinaryenExternalFunction())
        {
            funcExports++;
            if (exportName != "entrypoint")
            {
                throw std::runtime_error(
                    "only function export must be named \"entrypoint\"");
            }
            if (sawEntry)
            {
                throw std::runtime_error(
                    "module must export exactly one function named entrypoint");
            }
            sawEntry = true;
            char const* entryValueC = BinaryenExportGetValue(ex);
            if (!entryValueC || entryValueC[0] == '\0')
                throw std::runtime_error("Export has empty function value");
            entryValue = entryValueC;
            continue;
        }

        if (exportName != "memory")
        {
            throw std::runtime_error("non-function export not allowed");
        }
    }

    if (funcExports != 1 || !sawEntry)
    {
        throw std::runtime_error(
            "module must export exactly one function named entrypoint");
    }

    BinaryenFunctionRef f = getFunctionByNameOrIndex(m, entryValue);
    if (!f)
        throw std::runtime_error(
            "Export refers to missing function: " + entryValue);
    return std::string(BinaryenFunctionGetName(f));
}

void
validateImportPolicy(BinaryenModuleRef m)
{
    auto const allowed = makeAllowedHostImports();
    BinaryenIndex const n = BinaryenGetNumFunctions(m);
    for (BinaryenIndex i = 0; i < n; ++i)
    {
        BinaryenFunctionRef f = BinaryenGetFunctionByIndex(m, i);
        char const* imod = BinaryenFunctionImportGetModule(f);
        char const* ibase = BinaryenFunctionImportGetBase(f);
        bool const hasImport = isNonEmptyCStr(imod) || isNonEmptyCStr(ibase);
        if (!hasImport)
            continue;

        if (!(isNonEmptyCStr(imod) && isNonEmptyCStr(ibase)))
            throw std::runtime_error("Malformed function import declaration");

        if (std::string_view{imod} != std::string_view{SC_HOST_MOD})
            throw std::runtime_error(
                "imports must come only from module \"host\"");

        if (allowed.find(ibase) == allowed.end())
            throw std::runtime_error(
                "import name not allowed: " + std::string(ibase));
    }
}

void
validateFeaturePolicy(BinaryenModuleRef m)
{
    BinaryenFeatures const enabled = BinaryenModuleGetFeatures(m);
    // Reject feature groups that introduce non-determinism or dynamic
    // execution/memory behavior we do not meter in contracts.
    // In particular, TailCall covers return_call* and BulkMemory covers
    // memory.copy/fill/init, table.copy/init, data.drop, and elem.drop.
    std::array<std::pair<BinaryenFeatures, char const*>, 9> const disallowed{{
        {BinaryenFeatureAtomics(), "atomics"},
        {BinaryenFeatureRelaxedAtomics(), "relaxed atomics"},
        {BinaryenFeatureSharedEverything(), "shared memory"},
        {BinaryenFeatureSIMD128(), "SIMD"},
        {BinaryenFeatureRelaxedSIMD(), "relaxed SIMD"},
        {BinaryenFeatureExceptionHandling(), "exception handling"},
        {BinaryenFeatureTailCall(), "tail calls"},
        {BinaryenFeatureBulkMemory(), "bulk memory"},
        {BinaryenFeatureBulkMemoryOpt(), "bulk memory optimization"},
    }};

    for (auto const& [feature, name] : disallowed)
    {
        if ((enabled & feature) != 0)
            throw std::runtime_error(
                "wasm feature not allowed for deterministic contracts: " +
                std::string(name));
    }
}

void
validateNoStartFunction(BinaryenModuleRef m)
{
    if (BinaryenGetStart(m) != nullptr)
        throw std::runtime_error(
            "start function is not allowed for deterministic contracts");
}

void
validateNoBannedInstructions(std::string const& wat)
{
    constexpr std::array<std::string_view, 7> bannedExact{
        "memory.grow",
        "call_indirect",
        "call_ref",
        "table.grow",
        "shared",
        "f32",
        "f64"};
    constexpr std::array<std::string_view, 2> bannedPrefixes{
        "f32.", "f64."};
    std::size_t pos = 0;
    while (pos < wat.size())
    {
        std::string const token = readToken(wat, pos);
        if (token.empty())
            break;

        for (auto const needle : bannedExact)
        {
            if (token == needle)
            {
                throw std::runtime_error(
                    "banned instruction detected: " + std::string(needle));
            }
        }

        for (auto const prefix : bannedPrefixes)
        {
            if (token.rfind(prefix, 0) == 0)
            {
                throw std::runtime_error(
                    "banned instruction detected: " + std::string(token));
            }
        }
    }
}

std::unordered_set<std::string>
collectInternalFunctions(BinaryenModuleRef m)
{
    std::unordered_set<std::string> out;
    BinaryenIndex const n = BinaryenGetNumFunctions(m);
    out.reserve(n);

    for (BinaryenIndex i = 0; i < n; ++i)
    {
        BinaryenFunctionRef f = BinaryenGetFunctionByIndex(m, i);
        char const* imod = BinaryenFunctionImportGetModule(f);
        char const* ibase = BinaryenFunctionImportGetBase(f);
        if (isNonEmptyCStr(imod) && isNonEmptyCStr(ibase))
            continue;
        out.emplace(normalizeFunctionName(BinaryenFunctionGetName(f)));
    }
    return out;
}

std::unordered_map<std::string, std::unordered_set<std::string>>
buildDirectCallGraph(
    BinaryenModuleRef m,
    std::string const& wat,
    std::unordered_set<std::string> const& internalFns)
{
    std::unordered_map<std::string, std::unordered_set<std::string>> graph;
    graph.reserve(internalFns.size());
    for (auto const& f : internalFns)
        graph.emplace(f, std::unordered_set<std::string>{});

    std::size_t pos = 0;
    while ((pos = wat.find("(func", pos)) != std::string::npos)
    {
        std::size_t const end = findMatchingParen(wat, pos);
        if (end == std::string::npos)
            throw std::runtime_error("failed to parse function body");

        std::size_t headerCursor = pos + 5;
        std::string const funcName =
            normalizeFunctionName(readToken(wat, headerCursor));
        if (internalFns.find(funcName) == internalFns.end())
        {
            pos = end + 1;
            continue;
        }

        std::size_t cursor = pos;
        while (cursor < end)
        {
            std::string const tok = readToken(wat, cursor);
            if (tok.empty())
                break;
            if (tok != "(")
                continue;

            std::string const op = readToken(wat, cursor);
            if (op != "call")
                continue;

            std::string target = normalizeFunctionName(readToken(wat, cursor));
            if (target.empty())
                continue;

            if (isAllDigits(target))
                target = normalizeFunctionName(getFuncInfo(m, target).canonicalName);

            if (internalFns.find(target) != internalFns.end())
                graph[funcName].emplace(std::move(target));
        }

        pos = end + 1;
    }

    return graph;
}

void
validateNoRecursion(
    std::unordered_map<std::string, std::unordered_set<std::string>> const& graph)
{
    enum class Visit
    {
        white,
        gray,
        black
    };

    std::unordered_map<std::string, Visit> marks;
    marks.reserve(graph.size());
    for (auto const& [f, _] : graph)
        marks.emplace(f, Visit::white);

    auto dfs = [&](auto&& self, std::string const& f) -> void {
        Visit& v = marks[f];
        if (v == Visit::gray)
            throw std::runtime_error("Recursion detected at: " + f);
        if (v == Visit::black)
            return;

        v = Visit::gray;
        if (auto const it = graph.find(f); it != graph.end())
        {
            for (auto const& callee : it->second)
                self(self, callee);
        }
        v = Visit::black;
    };

    for (auto const& [f, _] : graph)
    {
        if (marks[f] == Visit::white)
            dfs(dfs, f);
    }
}

void
validateContractDeterminism(void const* data, std::size_t size)
{
    // Preflight-only policy scan: imports/exports, banned opcodes, recursion.
    ModuleHandle const module{data, size};
    BinaryenModuleRef const m = module.get();

    validateImportPolicy(m);
    validateFeaturePolicy(m);
    validateNoStartFunction(m);
    std::string const entrypoint =
        normalizeFunctionName(getEntrypointFunctionCanonicalName(m));

    std::string const wat = module.toText();
    validateNoBannedInstructions(wat);

    auto const internalFns = collectInternalFunctions(m);
    if (internalFns.find(entrypoint) == internalFns.end())
        throw std::runtime_error("entrypoint must be an internal function");

    validateNoRecursion(buildDirectCallGraph(m, wat, internalFns));
}

struct MeterResult
{
    std::string entrypoint;
    std::uint64_t cost = 0;
};

MeterResult
meterContract(void const* data, std::size_t size)
{
    // Metering runs only in doApply; preflight performs policy validation above.
    ModuleHandle const module{data, size};
    BinaryenModuleRef const m = module.get();
    std::string const entrypoint = getEntrypointFunctionCanonicalName(m);
    Analyzer az(m, makeCostModel());
    std::uint64_t worst = az.costFunctionWorst(entrypoint);

    return MeterResult{entrypoint, worst};
}

bool
tryMeterContract(
    void const* data,
    std::size_t size,
    std::uint64_t& outCost,
    std::string& outError)
{
    try
    {
        MeterResult res = meterContract(data, size);
        outCost = res.cost;
        return true;
    }
    catch (std::exception const& e)
    {
        outError = e.what();
        return false;
    }
}

bool
tryValidateContractDeterminism(
    void const* data,
    std::size_t size,
    std::string& outError)
{
    try
    {
        validateContractDeterminism(data, size);
        return true;
    }
    catch (std::exception const& e)
    {
        outError = e.what();
        return false;
    }
}

}  // namespace
}  // namespace ripple

namespace ripple {

NotTEC
ContractDeploy::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureSmartContracts))
        return temDISABLED;

    if (ctx.tx.getFlags() & tfUniversalMask)
        return temINVALID_FLAG;

    NotTEC const ret{preflight1(ctx)};
    if (!isTesSuccess(ret))
        return ret;

    if (!ctx.tx.isFieldPresent(sfContractCode) ||
        ctx.tx.getFieldVL(sfContractCode).empty())
        return temMALFORMED;

    {
        auto const& code = ctx.tx.getFieldVL(sfContractCode);
        std::string err;
        if (!tryValidateContractDeterminism(code.data(), code.size(), err))
        {
            JLOG(ctx.j.warn())
                << "Smart contract policy validation failed: " << err;
            return temMALFORMED;
        }
    }

    return preflight2(ctx);
}

TER
ContractDeploy::preclaim(PreclaimContext const& ctx)
{
    return tesSUCCESS;
}

XRPAmount
ContractDeploy::calculateBaseFee(ReadView const& view, STTx const& tx)
{
    XRPAmount const baseFee = Transactor::calculateBaseFee(view, tx);
    std::size_t const codeSize =
        tx.isFieldPresent(sfContractCode) ? tx.getFieldVL(sfContractCode).size()
                                          : 0;

    auto const maxDrops =
        static_cast<std::uint64_t>(
            std::numeric_limits<XRPAmount::value_type>::max());
    auto const baseDrops = static_cast<std::uint64_t>(baseFee.drops());
    auto const codeDrops = static_cast<std::uint64_t>(codeSize);

    if (codeDrops > maxDrops - baseDrops)
    {
        return XRPAmount{
            static_cast<XRPAmount::value_type>(maxDrops)};
    }

    return XRPAmount{
        static_cast<XRPAmount::value_type>(baseDrops + codeDrops)};
}

TER
ContractDeploy::doApply()
{
    auto const sleOwner = ctx_.view().peek(keylet::account(account_));
    if (!sleOwner)
        return tefINTERNAL;

    {
        STAmount const reserve{
            view().fees().accountReserve(sleOwner->getFieldU32(sfOwnerCount) + 1)};

        if (mPriorBalance < reserve)
            return tecINSUFFICIENT_RESERVE;
    }

    auto const contractID = sha512Half(ctx_.tx.getTransactionID());
    Keylet const contractKeylet = keylet::smartContract(contractID);

    auto sleContract = std::make_shared<SLE>(contractKeylet);
    (*sleContract)[sfAccount] = account_;
    (*sleContract)[sfContractID] = contractID;
    auto const& code = ctx_.tx.getFieldVL(sfContractCode);
    std::uint64_t contractCost = 0;
    std::string meterError;
    if (!tryMeterContract(code.data(), code.size(), contractCost, meterError))
    {
        JLOG(ctx_.journal.error())
            << "Smart contract meter failed: " << meterError;
        return tecFAILED_PROCESSING;
    }
    sleContract->setFieldVL(sfContractCode, code);
    sleContract->setFieldU64(
        sfContractCost, contractCost);
    (*sleContract)[sfContractBalance] = STAmount{XRPAmount{0}};

    ctx_.view().insert(sleContract);

    auto page = ctx_.view().dirInsert(
        keylet::ownerDir(account_), contractKeylet.key, describeOwnerDir(account_));
    if (!page)
        return tecDIR_FULL;
    (*sleContract)[sfOwnerNode] = *page;

    adjustOwnerCount(ctx_.view(), sleOwner, 1, ctx_.journal);
    ctx_.view().update(sleOwner);

    JLOG(ctx_.journal.trace())
        << "Smart contract deployed with ID " << to_string(contractID);

    return tesSUCCESS;
}

}
