#pragma once
#include <openvpn/common/options.hpp>

// Helper-only extension: transfers no raw profile, logs or arbitrary PUSH fields.
// The pinned TunProp overlay calls this before standard builder conversion.
class SzuDomainOptionCapture {
public:
    virtual ~SzuDomainOptionCapture() = default;
    virtual bool capture_domain_options(const openvpn::OptionList &) = 0;
};
