#ifndef RIPPLE_TX_DETAIL_CONTRACTCALL_H_INCLUDED
#define RIPPLE_TX_DETAIL_CONTRACTCALL_H_INCLUDED

#include <xrpld/app/tx/detail/Transactor.h>
#include <xrpld/app/tx/detail/SmartContractJson.h>

namespace ripple {

class ContractCall : public Transactor
{
public:
    static ConsequencesFactoryType const ConsequencesFactory = Normal;

    explicit ContractCall(ApplyContext& ctx) : Transactor(ctx)
    {
    }

    static NotTEC
    preflight(PreflightContext const& ctx);

    static TER
    preclaim(PreclaimContext const& ctx);

    TER
    doApply() override;

private:
    std::optional<DropContractSpec>
    fetchDropSpec() const;
};

}  // namespace ripple

#endif
