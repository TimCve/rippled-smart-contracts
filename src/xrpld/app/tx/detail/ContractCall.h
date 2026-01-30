#ifndef RIPPLE_TX_DETAIL_CONTRACTCALL_H_INCLUDED
#define RIPPLE_TX_DETAIL_CONTRACTCALL_H_INCLUDED

#include <xrpld/app/tx/detail/Transactor.h>

namespace ripple {

class ContractCall : public Transactor
{
public:
    static constexpr ConsequencesFactoryType ConsequencesFactory{Custom};

    explicit ContractCall(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    static NotTEC
    preflight(PreflightContext const& ctx);

    static TxConsequences
    makeTxConsequences(PreflightContext const& ctx);

    static XRPAmount
    calculateBaseFee(ReadView const& view, STTx const& tx);

    static TER
    preclaim(PreclaimContext const& ctx);

    TER
    doApply() override;
};

}  // namespace ripple

#endif
