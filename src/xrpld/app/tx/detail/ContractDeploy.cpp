#include <xrpld/app/tx/detail/ContractDeploy.h>

#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/digest.h>
#include <xrpld/ledger/View.h>
#include <xrpl/basics/Log.h>

#include <limits>

namespace ripple {

NotTEC
ContractDeploy::preflight(PreflightContext const& ctx)
{
    if(!ctx.rules.enabled(featureSmartContracts))
        return temDISABLED;
    
    if (ctx.tx.getFlags() & tfUniversalMask)
        return temINVALID_FLAG;

    NotTEC const ret{preflight1(ctx)};
    if (!isTesSuccess(ret))
        return ret;

    if (!ctx.tx.isFieldPresent(sfContractCode) ||
        ctx.tx.getFieldVL(sfContractCode).empty())
        return temMALFORMED;

    return preflight2(ctx);
}

TER
ContractDeploy::preclaim(PreclaimContext const& ctx)
{
    return tesSUCCESS;
}

// 1 drop of XRP per byte of code
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

    auto const contractAddress = sha512Half(ctx_.tx.getTransactionID());
    Keylet const contractKeylet = keylet::smartContract(contractAddress);

    auto sleContract = std::make_shared<SLE>(contractKeylet);
    (*sleContract)[sfAccount] = account_;
    (*sleContract)[sfContractAddress] = contractAddress;
    auto const& code = ctx_.tx.getFieldVL(sfContractCode);
    sleContract->setFieldVL(sfContractCode, code);
    sleContract->setFieldU64(
        sfContractCost, static_cast<std::uint64_t>(code.size()));
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
        << "Smart contract deployed with address " << to_string(contractAddress);

    return tesSUCCESS;
}

}
