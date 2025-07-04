/*
 * SRT - Secure, Reliable, Transport
 * Copyright (c) 2019 Haivision Systems Inc.
 * 
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 * 
 */

#include "platform_sys.h"

#include <string>
#include <map>
#include <vector>
#include <deque>
#include <iterator>
#include <cstdio>

#include "packetfilter.h"
#include "packetfilter_builtin.h"
#include "core.h"
#include "packet.h"
#include "logging.h"

using namespace std;
using namespace srt_logging;
using namespace srt::sync;

namespace srt {
bool PacketFilter::Internal::ParseConfig(const string& s, SrtFilterConfig& w_config, PacketFilter::Factory** ppf)
{
    if (!SrtParseConfig(s, (w_config)))
        return false;

    PacketFilter::Factory* fac = find(w_config.type);
    if (!fac)
        return false;

    if (ppf)
        *ppf = fac;
    // Extract characteristic data
    w_config.extra_size = fac->ExtraSize();

    return true;
}

bool ParseFilterConfig(const std::string& s, SrtFilterConfig& w_config)
{
    return PacketFilter::internal().ParseConfig(s, (w_config), NULL);
}

// Parameters are passed by value because they need to be potentially modicied inside.
bool PacketFilter::Internal::CheckFilterCompat(SrtFilterConfig& w_agent, const SrtFilterConfig& peer_in)
{
    PacketFilter::Factory* fac = find(w_agent.type);
    if (!fac)
        return false;

    SrtFilterConfig defaults;
    if (!ParseConfig(fac->defaultConfig(), (defaults)))
    {
        return false;
    }

    // Make a copy so that modifications can be done. This is only required for internal checks.
    SrtFilterConfig peer = peer_in;
    set<string> keys;
    // Extract all keys to identify also unspecified parameters on both sides
    // Note that theoretically for FEC it could simply check for the "cols" parameter
    // that is the only mandatory one, but this is a procedure for packet filters in
    // general and every filter may define its own set of parameters and mandatory rules.
    for (map<string, string>::iterator x = w_agent.parameters.begin(); x != w_agent.parameters.end(); ++x)
    {
        keys.insert(x->first);
        if (peer.parameters.count(x->first) == 0)
            peer.parameters[x->first] = x->second;
    }
    for (map<string, string>::iterator x = peer.parameters.begin(); x != peer.parameters.end(); ++x)
    {
        keys.insert(x->first);
        if (w_agent.parameters.count(x->first) == 0)
            w_agent.parameters[x->first] = x->second;
    }

    HLOGC(cnlog.Debug, log << "CheckFilterCompat: re-filled: AGENT:" << Printable(w_agent.parameters)
            << " PEER:" << Printable(peer.parameters));

    // Complete nonexistent keys with default values
    for (map<string, string>::iterator x = defaults.parameters.begin(); x != defaults.parameters.end(); ++x)
    {
        if (!w_agent.parameters.count(x->first))
            w_agent.parameters[x->first] = x->second;
        if (!peer.parameters.count(x->first))
            peer.parameters[x->first] = x->second;
    }

    for (set<string>::iterator x = keys.begin(); x != keys.end(); ++x)
    {
        // Note: operator[] will insert an element with default value
        // if it doesn't exist. This will inject the empty string as value,
        // which is acceptable.
        if (w_agent.parameters[*x] != peer.parameters[*x])
        {
            LOGC(cnlog.Error, log << "Packet Filter (" << defaults.type << "): collision on '" << (*x)
                    << "' parameter (agent:" << w_agent.parameters[*x] << " peer:" << (peer.parameters[*x]) << ")");
            return false;
        }
    }

    // Mandatory parameters will be checked when trying to create the filter object.

    return true;
}

struct SortBySequence
{
    bool operator()(const CUnit* u1, const CUnit* u2)
    {
        int32_t s1 = u1->m_Packet.getSeqNo();
        int32_t s2 = u2->m_Packet.getSeqNo();

        return CSeqNo::seqcmp(s1, s2) < 0;
    }
};

void PacketFilter::receive(CUnit* unit, std::vector<CUnit*>& w_incoming, loss_seqs_t& w_loss_seqs)
{
    const CPacket& rpkt = unit->m_Packet;

    if (m_filter->receive(rpkt, w_loss_seqs))
    {
        // For the sake of rebuilding MARK THIS UNIT GOOD, otherwise the
        // unit factory will supply it from getNextAvailUnit() as if it were not in use.
        unit->m_bTaken = true;
        HLOGC(pflog.Debug, log << "FILTER: PASSTHRU current packet %" << unit->m_Packet.getSeqNo());
        w_incoming.push_back(unit);
    }
    else
    {
        // Packet not to be passthru, update stats
        ScopedLock lg(m_parent->m_StatsLock);
        m_parent->m_stats.rcvr.recvdFilterExtra.count(1);
    }

    // w_loss_seqs enters empty into this function and can be only filled here. XXX ASSERT?
    for (loss_seqs_t::iterator i = w_loss_seqs.begin();
            i != w_loss_seqs.end(); ++i)
    {
        // Sequences here are low-high, if there happens any negative distance
        // here, simply skip and report IPE.
        int dist = CSeqNo::seqoff(i->first, i->second) + 1;
        if (dist > 0)
        {
            ScopedLock lg(m_parent->m_StatsLock);
            m_parent->m_stats.rcvr.lossFilter.count(dist);
        }
        else
        {
            LOGC(pflog.Error, log << "FILTER: IPE: loss record: invalid loss: %"
                    << i->first << " - %" << i->second);
        }
    }

    // Pack first recovered packets, if any.
    if (!m_provided.empty())
    {
        HLOGC(pflog.Debug, log << "FILTER: inserting REBUILT packets (" << m_provided.size() << "):");

        size_t nsupply = m_provided.size();
        InsertRebuilt(w_incoming, m_unitq);

        ScopedLock lg(m_parent->m_StatsLock);
        m_parent->m_stats.rcvr.suppliedByFilter.count((uint32_t)nsupply);
    }

    // Now that all units have been filled as they should be,
    // SET THEM ALL FREE. This is because now it's up to the 
    // buffer to decide as to whether it wants them or not.
    // Wanted units will be set GOOD flag, unwanted will remain
    // with FREE and therefore will be returned at the next
    // call to getNextAvailUnit().
    unit->m_bTaken = false;
    for (vector<CUnit*>::iterator i = w_incoming.begin(); i != w_incoming.end(); ++i)
    {
        CUnit* u = *i;
        u->m_bTaken = false;
    }

    // Packets must be sorted by sequence number, ascending, in order
    // not to challenge the SRT's contiguity checker.
    sort(w_incoming.begin(), w_incoming.end(), SortBySequence());

    // For now, report immediately the irrecoverable packets
    // from the row.

    // Later, the `irrecover_row` or `irrecover_col` will be
    // reported only, depending on level settings. For example,
    // with default LATELY level, packets will be reported as
    // irrecoverable only when they are irrecoverable in the
    // vertical group.

    // With "always", do not report any losses, SRT will simply check
    // them itself.

    return;

}

bool PacketFilter::packControlPacket(int32_t seq, int kflg, CPacket& w_packet)
{
    bool have = m_filter->packControlPacket(m_sndctlpkt, seq);
    if (!have)
        return false;

    // Now this should be repacked back to CPacket.
    // The header must be copied, it's always part of CPacket.
    uint32_t* hdr = w_packet.getHeader();
    memcpy((hdr), m_sndctlpkt.hdr, SRT_PH_E_SIZE * sizeof(*hdr));

    // The buffer can be assigned.
    w_packet.m_pcData = m_sndctlpkt.buffer;
    w_packet.setLength(m_sndctlpkt.length);

    // This sets only the Packet Boundary flags, while all other things:
    // - Order
    // - Rexmit
    // - Crypto
    // - Message Number
    // will be set to 0/false
    w_packet.set_msgflags(SRT_MSGNO_CONTROL | MSGNO_PACKET_BOUNDARY::wrap(PB_SOLO));

    // ... and then fix only the Crypto flags
    w_packet.setMsgCryptoFlags(EncryptionKeySpec(kflg));

    // Don't set the ID, it will be later set for any kind of packet.
    // Write the timestamp clip into the timestamp field.
    return true;
}


void PacketFilter::InsertRebuilt(vector<CUnit*>& incoming, CUnitQueue* uq)
{
    if (m_provided.empty())
        return;

    for (vector<SrtPacket>::iterator i = m_provided.begin(); i != m_provided.end(); ++i)
    {
        CUnit* u = uq->getNextAvailUnit();
        if (!u)
        {
            LOGC(pflog.Error, log << "FILTER: LOCAL STORAGE DEPLETED. Can't return rebuilt packets.");
            break;
        }

        // LOCK the unit as taken because otherwise the next
        // call to getNextAvailUnit will return THE SAME UNIT.
        u->m_bTaken = true;
        // After returning from this function, all units will be
        // set back to FREE so that the buffer can decide whether
        // it wants them or not.

        CPacket& packet = u->m_Packet;

        memcpy((packet.getHeader()), i->hdr, CPacket::HDR_SIZE);
        memcpy((packet.m_pcData), i->buffer, i->length);
        packet.setLength(i->length);

        HLOGC(pflog.Debug, log << "FILTER: PROVIDING rebuilt packet %" << packet.getSeqNo());

        incoming.push_back(u);
    }

    m_provided.clear();
}

// Placement here is necessary in order to mark the location to
// store the PacketFilter::Factory class characteristic object.
PacketFilter::Factory::~Factory()
{
}

#if HAVE_CXX11

PacketFilter::Internal& PacketFilter::internal()
{
    static PacketFilter::Internal instance;
    return instance;
}

#else // !HAVE_CXX11

static pthread_once_t s_PacketFactoryOnce = PTHREAD_ONCE_INIT;

static PacketFilter::Internal *getInstance()
{
    static PacketFilter::Internal instance;
    return &instance;
}

PacketFilter::Internal& PacketFilter::internal()
{
    // We don't want lock each time, pthread_once can be faster than mutex.
    pthread_once(&s_PacketFactoryOnce, reinterpret_cast<void (*)()>(getInstance));
    return *getInstance();
}

#endif

PacketFilter::Internal::Internal()
{
    // Add here builtin packet filters and mark them
    // as builtin. This will disallow users to register
    // external filters with the same name.

    m_filters["fec"] = new PacketFilter::Creator<FECFilterBuiltin>;
    m_builtin_filters.insert("fec");

    m_filters["rsfec"] = new PacketFilter::Creator<RSFECFilter>;
    m_builtin_filters.insert("rsfec");
}

bool PacketFilter::configure(CUDT* parent, CUnitQueue* uq, const std::string& confstr)
{
    m_parent = parent;

    SrtFilterConfig cfg;
    if (!internal().ParseConfig(confstr, (cfg)))
        return false;

    // Extract the "type" key from parameters, or use
    // builtin if lacking.
    PacketFilter::Factory *factory = internal().find(cfg.type);
    if (factory == NULL)
        return false;

    SrtFilterInitializer init;
    init.socket_id = parent->socketID();
    init.snd_isn = parent->sndSeqNo();
    init.rcv_isn = parent->rcvSeqNo();

    // XXX This is a formula for a full "SRT payload" part that undergoes transmission,
    // might be nice to have this formula as something more general.
    init.payload_size = parent->OPT_PayloadSize() + parent->getAuthTagSize();
    init.rcvbuf_size = parent->m_config.iRcvBufSize;

    HLOGC(pflog.Debug, log << "PFILTER: @" << init.socket_id << " payload size="
            << init.payload_size << " rcvbuf size=" << init.rcvbuf_size);

    // Found a filter, so call the creation function
    m_filter = factory->Create(init, m_provided, confstr);
    if (!m_filter)
        return false;

    m_unitq = uq;

    // The filter should have pinned in all events
    // that are of its interest. It's stated that
    // it's ready after creation.
    return true;
}

bool PacketFilter::correctConfig(const SrtFilterConfig& conf)
{
    // Check if type is specified in parameters (legacy support)
    const string* pname = map_getp(conf.parameters, "type");

    string filter_type;
    if (pname)
    {
        filter_type = *pname;
    }
    else
    {
        // Use the type field from the config structure
        filter_type = conf.type;
    }

    if (filter_type.empty())
        return true; // default, parameters ignored

    if (filter_type == "adaptive")
        return true;

    PacketFilter::Factory *factory = internal().find(filter_type);
    if (factory == NULL)
        return false;

    return true;
}

PacketFilter::~PacketFilter()
{
    delete m_filter;
}

} // namespace srt
