#ifndef RIPPLE_TX_DETAIL_CONTRACTDEPLOY_H_INCLUDED
#define RIPPLE_TX_DETAIL_CONTRACTDEPLOY_H_INCLUDED

#include <xrpld/app/tx/detail/Transactor.h>

namespace ripple {

class ContractDeploy : public Transactor
{
public:
    static constexpr ConsequencesFactoryType ConsequencesFactory{Normal};

    explicit ContractDeploy(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    static NotTEC
    preflight(PreflightContext const& ctx);

    static TER
    preclaim(PreclaimContext const& ctx);

    static XRPAmount
    calculateBaseFee(ReadView const& view, STTx const& tx);

    TER
    doApply() override;
};

}  // namespace ripple

#endif
