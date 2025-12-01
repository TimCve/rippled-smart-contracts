#include <xrpld/app/tx/detail/ContractCall.h>

#include <xrpl/basics/Log.h>
#include <xrpl/protocol/Feature.h>
#include <xrpl/protocol/Indexes.h>
#include <xrpl/protocol/STAmount.h>
#include <xrpl/protocol/TxFlags.h>
#include <xrpl/protocol/digest.h>
#include <xrpld/ledger/View.h>

namespace ripple {

namespace {

std::optional<DropContractSpec>
loadDropSpec(
    ReadView const& view,
    uint256 const& contractID,
    beast::Journal const& j)
{
    auto const sleContract = view.read(keylet::smartContract(contractID));
    if (!sleContract)
        return std::nullopt;

    auto const json =
        SmartContractJson::parse(sleContract->getFieldVL(sfContractCode), j);
    if (!json)
        return std::nullopt;

    return SmartContractJson::parseDropContract(*json, j);
}

std::optional<DropContractSpec>
loadStateSpec(
    ReadView const& view,
    uint256 const& contractID,
    uint256 const& stateID,
    beast::Journal const& j)
{
    auto const state = view.read(keylet::contractState(contractID, stateID));
    if (!state)
        return std::nullopt;

    auto const json =
        SmartContractJson::parse(state->getFieldVL(sfContractState), j);
    if (!json)
        return std::nullopt;

    return SmartContractJson::parseDropState(*json, j);
}

uint256
deriveStateID(STTx const& tx, uint256 const& contractID)
{
    if (auto const provided = tx[~sfContractStateID])
        return *provided;
    return sha512Half(contractID, tx.getSeqProxy().value());
}

}  // namespace

NotTEC
ContractCall::preflight(PreflightContext const& ctx)
{
    if (!ctx.rules.enabled(featureSmartContracts))
        return temDISABLED;

    if (ctx.tx.getFlags() & tfUniversalMask)
        return temINVALID_FLAG;

    if (auto const ret = preflight1(ctx); !isTesSuccess(ret))
        return ret;

    if (!ctx.tx.isFieldPresent(sfContractAddress))
        return temMALFORMED;

    if (auto const params = ctx.tx[~sfContractParams])
    {
        if (!params->empty())
            return temMALFORMED;
    }

    return preflight2(ctx);
}

TER
ContractCall::preclaim(PreclaimContext const& ctx)
{
    auto const contractID = ctx.tx[sfContractAddress];
    auto const spec = loadDropSpec(ctx.view, contractID, ctx.j);
    if (!spec)
        return tecNO_ENTRY;

    auto const sleAccount = ctx.view.read(keylet::account(ctx.tx[sfAccount]));
    if (!sleAccount)
        return terNO_ACCOUNT;

    if (!ctx.tx[~sfContractStateID])
    {
        auto const reserve =
            ctx.view.fees().accountReserve((*sleAccount)[sfOwnerCount] + 1);
        STAmount const balance((*sleAccount)[sfBalance]);
        if (balance.xrp() < reserve + spec->amount)
            return tecUNFUNDED;
    }
    else
    {
        auto const stateID = *ctx.tx[~sfContractStateID];
        auto const state = ctx.view.read(keylet::contractState(contractID, stateID));
        if (!state)
            return tecNO_ENTRY;

        auto const stateSpec = loadStateSpec(ctx.view, contractID, stateID, ctx.j);

        if (!stateSpec || stateSpec->recipient != ctx.tx[sfAccount])
            return tecNO_PERMISSION;
    }

    return tesSUCCESS;
}

TER
ContractCall::doApply()
{
    auto const contractID = ctx_.tx[sfContractAddress];
    auto const spec = loadDropSpec(ctx_.view(), contractID, ctx_.journal);
    if (!spec)
        return tecNO_ENTRY;

    auto const stateProvided = ctx_.tx[~sfContractStateID];
    if (!stateProvided)
    {
        auto const stateID = deriveStateID(ctx_.tx, contractID);
        auto const stateKeylet = keylet::contractState(contractID, stateID);
        if (ctx_.view().exists(stateKeylet))
            return tecDUPLICATE;

        auto const sleAccount = ctx_.view().peek(keylet::account(account_));
        if (!sleAccount)
            return tefINTERNAL;

        auto const reserve =
            ctx_.view().fees().accountReserve((*sleAccount)[sfOwnerCount] + 1);
        STAmount const balance((*sleAccount)[sfBalance]);
        auto const xrpBalance = balance.xrp();
        if (xrpBalance < reserve + spec->amount)
            return tecUNFUNDED;

        auto stateSle = std::make_shared<SLE>(stateKeylet);
        (*stateSle)[sfAccount] = account_;
        (*stateSle)[sfContractAddress] = contractID;
        (*stateSle)[sfContractStateID] = stateID;
        (*stateSle)[sfContractRecipient] = spec->recipient;
        (*stateSle)[sfAmount] = STAmount(spec->amount);
        stateSle->setFieldVL(
            sfContractState,
            SmartContractJson::serialize(SmartContractJson::buildDropState(*spec)));

        ctx_.view().insert(stateSle);

        auto page = ctx_.view().dirInsert(
            keylet::ownerDir(account_), stateKeylet.key, describeOwnerDir(account_));
        if (!page)
            return tecDIR_FULL;
        (*stateSle)[sfOwnerNode] = *page;

        adjustOwnerCount(ctx_.view(), sleAccount, 1, ctx_.journal);
        STAmount const newBalance =
            STAmount((*sleAccount)[sfBalance]) - STAmount(spec->amount);
        (*sleAccount)[sfBalance] = newBalance;
        ctx_.view().update(sleAccount);

        JLOG(ctx_.journal.trace())
            << "ContractCall created state " << to_string(stateID);
        return tesSUCCESS;
    }

    auto const stateID = *stateProvided;
    auto stateSle = ctx_.view().peek(keylet::contractState(contractID, stateID));
    if (!stateSle)
        return tecNO_ENTRY;

    STAmount const storedAmount((*stateSle)[sfAmount]);
    if (!isXRP(storedAmount) || storedAmount.xrp() == XRPAmount{0})
        return tecNO_ENTRY;

    auto const stateSpec =
        loadStateSpec(ctx_.view(), contractID, stateID, ctx_.journal);
    if (!stateSpec || stateSpec->recipient != account_ ||
        stateSpec->amount != storedAmount.xrp())
        return tecNO_PERMISSION;

    auto const recipientSle = ctx_.view().peek(keylet::account(account_));
    if (!recipientSle)
        return tefINTERNAL;

    STAmount const updatedBalance =
        STAmount((*recipientSle)[sfBalance]) + storedAmount;
    (*recipientSle)[sfBalance] = updatedBalance;
    ctx_.view().update(recipientSle);

    AccountID const owner = (*stateSle)[sfAccount];
    auto ownerSle = ctx_.view().peek(keylet::account(owner));
    if (ownerSle)
    {
        adjustOwnerCount(ctx_.view(), ownerSle, -1, ctx_.journal);
        ctx_.view().update(ownerSle);
    }

    if (!ctx_.view().dirRemove(
            keylet::ownerDir(owner),
            (*stateSle)[sfOwnerNode],
            stateSle->key(),
            true))
        return tefBAD_LEDGER;

    ctx_.view().erase(stateSle);

    JLOG(ctx_.journal.trace())
        << "ContractCall claimed state " << to_string(stateID);

    return tesSUCCESS;
}

}  // namespace ripple
