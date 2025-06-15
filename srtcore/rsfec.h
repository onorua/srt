/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2019 Haivision Systems Inc.
 *
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 * This file implements a Reed-Solomon FEC filter using libfec.
 */

#ifndef INC_SRT_RSFEC_H
#define INC_SRT_RSFEC_H

#include "srt.h"
#include "packetfilter_api.h"
#include <memory> // For std::unique_ptr

namespace srt {

class RSFecFilter : public SrtPacketFilterBase
{
    // Forward-declare the private implementation class (PIMPL)
    struct Impl;
    std::unique_ptr<Impl> pimpl;

public:
    // CRITICAL FIX: Add the required static member for the framework.
    static const size_t EXTRA_SIZE = 0;

    static const char defaultConfig[];
    static bool verifyConfig(const SrtFilterConfig& cfg, std::string& w_error);

    RSFecFilter(const SrtFilterInitializer& init, std::vector<SrtPacket>& provided, const std::string& confstr);
    // The destructor must be declared here but defined in the .cpp file
    ~RSFecFilter() override;

    void feedSource(CPacket& pkt) override;
    bool packControlPacket(SrtPacket& pkt, int32_t seq) override;
    bool receive(const CPacket& pkt, loss_seqs_t& loss) override;

    SRT_ARQLevel arqLevel() override { return SRT_ARQ_NEVER; }
};

} // namespace srt

#endif // INC_SRT_RSFEC_H