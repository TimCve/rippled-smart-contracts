#ifndef RIPPLE_TX_MYCUSTOMTX_H_INCLUDED
#define RIPPLE_TX_MYCUSTOMTX_H_INCLUDED

#include <xrpld/app/tx/detail/Transactor.h>

namespace ripple {

class MyCustomTx : public Transactor
{
public:
    static constexpr ConsequencesFactoryType ConsequencesFactory{Normal};

    explicit MyCustomTx(ApplyContext& ctx) : Transactor(ctx) {}

    static NotTEC preflight(PreflightContext const& ctx);
    static TER preclaim(PreclaimContext const& ctx);
    TER doApply() override;
};

} // namespace ripple

#endif