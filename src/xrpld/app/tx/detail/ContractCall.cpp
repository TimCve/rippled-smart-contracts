#include <xrpld/app/tx/detail/ContractCall.h>

#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/digest.h>
#include <xrpld/ledger/View.h>
#include <xrpl/basics/Log.h>

namespace ripple {

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
    return tesSUCCESS;
}

}
