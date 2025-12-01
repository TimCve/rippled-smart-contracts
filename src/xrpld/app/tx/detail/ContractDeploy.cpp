#include <xrpld/app/tx/detail/ContractDeploy.h>
#include <xrpld/app/tx/detail/SmartContractJson.h>

#include <xrpl/basics/Log.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/digest.h>
#include <xrpld/ledger/View.h>

namespace ripple {

namespace {

uint256
deriveContractID(STTx const& tx, AccountID const& owner)
{
    if (auto const provided = tx[~sfContractAddress])
        return *provided;

    Blob const name = tx.getFieldVL(sfContractName);
    return sha512Half(owner, tx.getSeqProxy().value(), Slice{name.data(), name.size()});
}

}  // namespace

NotTEC
ContractDeploy::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureSmartContracts))
        return temDISABLED;

    if (ctx.tx.getFlags() & tfUniversalMask)
        return temINVALID_FLAG;

    if (auto const ret = preflight1(ctx); !isTesSuccess(ret))
        return ret;

    if (!ctx.tx.isFieldPresent(sfContractCode) ||
        ctx.tx.getFieldVL(sfContractCode).empty())
        return temMALFORMED;

    if (auto const name = ctx.tx[~sfContractName])
    {
        if (name->size() > 128)
            return temMALFORMED;
    }

    auto const code = ctx.tx.getFieldVL(sfContractCode);
    if (code.size() > 4096)
        return temMALFORMED;

    auto const json = SmartContractJson::parse(code, ctx.j);
    if (!json || !SmartContractJson::parseDropContract(*json, ctx.j))
        return temMALFORMED;

    return preflight2(ctx);
}

TER
ContractDeploy::preclaim(PreclaimContext const& ctx)
{
    auto const contractID = deriveContractID(ctx.tx, ctx.tx[sfAccount]);
    if (ctx.view.exists(keylet::smartContract(contractID)))
        return tecDUPLICATE;
    return tesSUCCESS;
}

TER
ContractDeploy::doApply()
{
    auto const contractID = deriveContractID(ctx_.tx, account_);
    auto const contractKeylet = keylet::smartContract(contractID);

    if (ctx_.view().exists(contractKeylet))
        return tecDUPLICATE;

    auto const sleAccount = ctx_.view().peek(keylet::account(account_));
    if (!sleAccount)
        return tefINTERNAL;

    auto const reserve =
        ctx_.view().fees().accountReserve((*sleAccount)[sfOwnerCount] + 1);
    STAmount const balance((*sleAccount)[sfBalance]);
    if (balance.xrp() < reserve)
        return tecINSUFFICIENT_RESERVE;

    auto const json = SmartContractJson::parse(
        ctx_.tx.getFieldVL(sfContractCode), ctx_.journal);
    if (!json || !SmartContractJson::parseDropContract(*json, ctx_.journal))
        return temMALFORMED;

    auto sleContract = std::make_shared<SLE>(contractKeylet);
    (*sleContract)[sfAccount] = account_;
    (*sleContract)[sfContractAddress] = contractID;
    sleContract->setFieldVL(sfContractCode, ctx_.tx.getFieldVL(sfContractCode));
    if (auto const name = ctx_.tx[~sfContractName])
        (*sleContract)[sfContractName] = *name;

    ctx_.view().insert(sleContract);

    auto page = ctx_.view().dirInsert(
        keylet::ownerDir(account_), contractKeylet.key, describeOwnerDir(account_));
    if (!page)
        return tecDIR_FULL;
    (*sleContract)[sfOwnerNode] = *page;

    adjustOwnerCount(ctx_.view(), sleAccount, 1, ctx_.journal);
    ctx_.view().update(sleAccount);

    JLOG(ctx_.journal.trace())
        << "Smart contract deployed with id " << to_string(contractID);

    return tesSUCCESS;
}

}  // namespace ripple
