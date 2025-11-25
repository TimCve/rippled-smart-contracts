#include <xrpld/app/tx/detail/MyCustomTx.h>
#include <xrpl/basics/Log.h>
#include <xrpl/protocol/Feature.h>

namespace ripple {

NotTEC MyCustomTx::preflight(PreflightContext const& ctx)
{
    // Check if amendment is enabled
    if (!ctx.rules.enabled(featureMyCustomTx))
        return temDISABLED;

    // Perform base class preflight checks
    auto const ret = preflight1(ctx);
    if (!isTesSuccess(ret))
        return ret;

    // Validate custom field format
    if (!ctx.tx.isFieldPresent(sfCustomField))
        return temMALFORMED;

    // auto const customValue = ctx.tx[sfCustomField];
    // if (customValue < 0 || customValue > 1000000)
    //     return temBAD_AMOUNT;

    // Additional validation...

    return preflight2(ctx);
}

TER MyCustomTx::preclaim(PreclaimContext const& ctx)
{
    // Get account IDs
    AccountID const src = ctx.tx[sfAccount];
    AccountID const dst = ctx.tx[sfDestination];

    // Verify destination account exists
    auto const sleDst = ctx.view.read(keylet::account(dst));
    if (!sleDst)
        return tecNO_DST;

    // Check source account has sufficient balance
    auto const sleSrc = ctx.view.read(keylet::account(src));
    if (!sleSrc)
        return terNO_ACCOUNT;

    auto const balance = (*sleSrc)[sfBalance];
    auto const fee = ctx.tx[sfFee];
    
    if (balance < fee)
        return tecUNFUNDED;

    // Additional state-based validation...

    return tesSUCCESS;
}

TER MyCustomTx::doApply()
{
    // Pay transaction fee
    // auto const result = payFee();
    // if (result != tesSUCCESS)
    //     return result;

    // Get transaction fields
    auto const dst = ctx_.tx[sfDestination];
    auto const customValue = ctx_.tx[sfCustomField];

    // Perform custom logic
    // Example: Create a new ledger object
    auto const sleNew = std::make_shared<SLE>(
        keylet::myCustomSLE(account_, ctx_.tx.getSeqProxy().value()));
    
    sleNew->setAccountID(sfAccount, account_);
    sleNew->setAccountID(sfDestination, dst);
    sleNew->setFieldVL(sfCustomField, customValue);

    // Insert into ledger
    view().insert(sleNew);

    // Log the operation
    JLOG(j_.trace()) << "MyCustomTx applied successfully";

    return tesSUCCESS;
}

} // namespace ripple