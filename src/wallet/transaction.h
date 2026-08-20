// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// CWalletTx and its TxState, ported from Bitcoin Core's wallet/transaction.h.
// This is scheme-agnostic (no elliptic-curve / descriptor coupling), so it is a
// faithful port; Lattica adaptations are minor: the confirmation state is driven
// by the wallet's own block feed rather than interfaces::Chain (so the chain-
// dependent updateState() is dropped), and CWalletTx serialization carries the
// clean Lattica fields (no legacy wallet.dat backward-compat dummies / CMerkleTx,
// since Lattica has no pre-existing wallet files).

#ifndef LATTICA_WALLET_TRANSACTION_H
#define LATTICA_WALLET_TRANSACTION_H

#include <attributes.h>
#include <consensus/amount.h>
#include <primitives/transaction.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/strencodings.h>

#include <cassert>
#include <cstdint>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <variant>
#include <vector>

namespace interfaces {
class Chain;
} // namespace interfaces

namespace wallet {

//! State of transaction confirmed in a block.
struct TxStateConfirmed {
    uint256 confirmed_block_hash;
    int confirmed_block_height;
    int position_in_block;

    explicit TxStateConfirmed(const uint256& block_hash, int height, int index) : confirmed_block_hash(block_hash), confirmed_block_height(height), position_in_block(index) {}
    std::string toString() const { return strprintf("Confirmed (block=%s, height=%i, index=%i)", confirmed_block_hash.ToString(), confirmed_block_height, position_in_block); }
};

//! State of transaction added to mempool.
struct TxStateInMempool {
    std::string toString() const { return strprintf("InMempool"); }
};

//! State of rejected transaction that conflicts with a confirmed block.
struct TxStateBlockConflicted {
    uint256 conflicting_block_hash;
    int conflicting_block_height;

    explicit TxStateBlockConflicted(const uint256& block_hash, int height) : conflicting_block_hash(block_hash), conflicting_block_height(height) {}
    std::string toString() const { return strprintf("BlockConflicted (block=%s, height=%i)", conflicting_block_hash.ToString(), conflicting_block_height); }
};

//! State of transaction not confirmed or conflicting with a known block and not
//! in the mempool. May be abandoned, never broadcast, or otherwise inactive.
struct TxStateInactive {
    bool abandoned;

    explicit TxStateInactive(bool abandoned = false) : abandoned(abandoned) {}
    std::string toString() const { return strprintf("Inactive (abandoned=%i)", abandoned); }
};

//! State of transaction loaded in an unrecognized state, with serialized hash
//! and index values preserved. Treated as inactive by default.
struct TxStateUnrecognized {
    uint256 block_hash;
    int index;

    TxStateUnrecognized(const uint256& block_hash, int index) : block_hash(block_hash), index(index) {}
    std::string toString() const { return strprintf("Unrecognized (block=%s, index=%i)", block_hash.ToString(), index); }
};

//! All possible CWalletTx states
using TxState = std::variant<TxStateConfirmed, TxStateInMempool, TxStateBlockConflicted, TxStateInactive, TxStateUnrecognized>;

//! Subset of states transaction sync logic is implemented to handle.
using SyncTxState = std::variant<TxStateConfirmed, TxStateInMempool, TxStateInactive>;

//! Try to interpret deserialized TxStateUnrecognized data as a recognized state.
static inline TxState TxStateInterpretSerialized(TxStateUnrecognized data)
{
    if (data.block_hash == uint256::ZERO) {
        if (data.index == 0) return TxStateInactive{};
    } else if (data.block_hash == uint256::ONE) {
        if (data.index == -1) return TxStateInactive{/*abandoned=*/true};
    } else if (data.index >= 0) {
        return TxStateConfirmed{data.block_hash, /*height=*/-1, data.index};
    } else if (data.index == -1) {
        return TxStateBlockConflicted{data.block_hash, /*height=*/-1};
    }
    return data;
}

//! Get TxState serialized block hash. Inverse of TxStateInterpretSerialized.
static inline uint256 TxStateSerializedBlockHash(const TxState& state)
{
    if (auto* s = std::get_if<TxStateInactive>(&state)) return s->abandoned ? uint256::ONE : uint256::ZERO;
    if (std::get_if<TxStateInMempool>(&state)) return uint256::ZERO;
    if (auto* s = std::get_if<TxStateConfirmed>(&state)) return s->confirmed_block_hash;
    if (auto* s = std::get_if<TxStateBlockConflicted>(&state)) return s->conflicting_block_hash;
    if (auto* s = std::get_if<TxStateUnrecognized>(&state)) return s->block_hash;
    assert(false);
}

//! Get TxState serialized block index. Inverse of TxStateInterpretSerialized.
static inline int TxStateSerializedIndex(const TxState& state)
{
    if (auto* s = std::get_if<TxStateInactive>(&state)) return s->abandoned ? -1 : 0;
    if (std::get_if<TxStateInMempool>(&state)) return 0;
    if (auto* s = std::get_if<TxStateConfirmed>(&state)) return s->position_in_block;
    if (std::get_if<TxStateBlockConflicted>(&state)) return -1;
    if (auto* s = std::get_if<TxStateUnrecognized>(&state)) return s->index;
    assert(false);
}

//! Return TxState or SyncTxState as a string for logging or debugging.
template <typename T>
std::string TxStateString(const T& state)
{
    return std::visit([](const auto& s) { return s.toString(); }, state);
}

typedef std::map<std::string, std::string> mapValue_t;

/** Cachable amount subdivided into avoid-reuse and all balances (ported from Core). */
struct CachableAmount
{
    std::optional<CAmount> m_avoid_reuse_value;
    std::optional<CAmount> m_all_value;
    inline void Reset()
    {
        m_avoid_reuse_value.reset();
        m_all_value.reset();
    }
    void Set(bool avoid_reuse, CAmount value)
    {
        if (avoid_reuse) m_avoid_reuse_value = value;
        else m_all_value = value;
    }
    CAmount Get(bool avoid_reuse)
    {
        if (avoid_reuse) { assert(m_avoid_reuse_value.has_value()); return m_avoid_reuse_value.value(); }
        assert(m_all_value.has_value());
        return m_all_value.value();
    }
    bool IsCached(bool avoid_reuse)
    {
        if (avoid_reuse) return m_avoid_reuse_value.has_value();
        return m_all_value.has_value();
    }
};

/**
 * A transaction with a bunch of additional info that only the owner cares about.
 */
class CWalletTx
{
public:
    mapValue_t mapValue;
    std::vector<std::pair<std::string, std::string>> vOrderForm;
    unsigned int nTimeReceived{0}; //!< time received by this node
    int64_t nOrderPos{-1};         //!< position in ordered transaction list

    CTransactionRef tx;
    TxState m_state;

    //! Set of mempool transactions that conflict directly with the transaction,
    //! or that conflict with an ancestor transaction.
    std::set<Txid> mempool_conflicts;

    //! Smart timestamp (block-time-adjusted); 0 until computed. GetTxTime prefers it.
    unsigned int nTimeSmart{0};
    //! For a TRUC (v3) parent, the txid of its single in-mempool child, if any.
    //! Used by spend.cpp to avoid spending other outputs of a TRUC parent.
    std::optional<Txid> truc_child_in_mempool;

    //! Cached credit/debit amounts (lazily filled by receive.cpp). mutable because
    //! they are recomputed on demand without changing the logical tx.
    enum AmountType { DEBIT, CREDIT, AMOUNTTYPE_ENUM_ELEMENTS };
    mutable CachableAmount m_amounts[AMOUNTTYPE_ENUM_ELEMENTS];
    //! True while all m_amounts caches are empty (cheap MarkDirty fast-path).
    mutable bool m_is_cache_empty{true};
    mutable bool fChangeCached{false};
    mutable CAmount nChangeCached{0};
    mutable std::optional<bool> m_cached_from_me{std::nullopt};

    CWalletTx(CTransactionRef arg, const TxState& state) : tx(std::move(arg)), m_state(state) {}

    //! Invalidate the cached amounts so they are recomputed next access.
    void MarkDirty()
    {
        m_amounts[DEBIT].Reset();
        m_amounts[CREDIT].Reset();
        fChangeCached = false;
        nChangeCached = 0;
        m_cached_from_me = std::nullopt;
        m_is_cache_empty = true;
    }

    void SetTx(CTransactionRef arg) { tx = std::move(arg); }

    template <typename Stream>
    void Serialize(Stream& s) const
    {
        const uint256 serialized_hash = TxStateSerializedBlockHash(m_state);
        const int serialized_index = TxStateSerializedIndex(m_state);
        // nTimeSmart rides along inside mapValue (backward-compatible: readers
        // that lack the key simply leave nTimeSmart at 0).
        mapValue_t mapValueCopy = mapValue;
        if (nTimeSmart) mapValueCopy["timesmart"] = strprintf("%u", nTimeSmart);
        s << TX_WITH_WITNESS(tx) << serialized_hash << serialized_index << mapValueCopy << vOrderForm << nTimeReceived << nOrderPos;
    }

    template <typename Stream>
    void Unserialize(Stream& s)
    {
        uint256 serialized_hash;
        int serialized_index;
        s >> TX_WITH_WITNESS(tx) >> serialized_hash >> serialized_index >> mapValue >> vOrderForm >> nTimeReceived >> nOrderPos;
        m_state = TxStateInterpretSerialized({serialized_hash, serialized_index});
        if (auto it = mapValue.find("timesmart"); it != mapValue.end()) {
            nTimeSmart = static_cast<unsigned int>(LocaleIndependentAtoi<int64_t>(it->second));
            mapValue.erase(it);
        }
    }

    template <typename T> const T* state() const { return std::get_if<T>(&m_state); }
    template <typename T> T* state() { return std::get_if<T>(&m_state); }

    bool isAbandoned() const { return state<TxStateInactive>() && state<TxStateInactive>()->abandoned; }
    bool isMempoolConflicted() const { return !mempool_conflicts.empty(); }
    bool isBlockConflicted() const { return state<TxStateBlockConflicted>(); }
    bool isInactive() const { return state<TxStateInactive>(); }
    bool isConfirmed() const { return state<TxStateConfirmed>(); }
    bool InMempool() const;
    bool isUnconfirmed() const { return !isAbandoned() && !isBlockConflicted() && !isMempoolConflicted() && !isConfirmed(); }
    const Txid& GetHash() const LIFETIMEBOUND { return tx->GetHash(); }
    const Wtxid& GetWitnessHash() const LIFETIMEBOUND { return tx->GetWitnessHash(); }
    bool IsCoinBase() const { return tx->IsCoinBase(); }
    //! Best-known wall-clock time of the transaction: the smart time if computed,
    //! otherwise the time it was first received.
    int64_t GetTxTime() const;

    //! Whether two wallet transactions spend the same inputs (ignoring signatures).
    bool IsEquivalentTo(const CWalletTx& tx) const;
    //! Re-derive this tx's confirmed/conflicted block height from the chain, and
    //! mark it inactive if the block was reorged out (used on wallet (re)attach).
    void updateState(interfaces::Chain& chain);

    void CopyFrom(const CWalletTx&);
};

/** A reference to a specific output of a wallet transaction. */
class WalletTXO
{
private:
    const CWalletTx& m_wtx;
    const CTxOut& m_output;

public:
    WalletTXO(const CWalletTx& wtx, const CTxOut& output) : m_wtx(wtx), m_output(output) {}

    const CWalletTx& GetWalletTx() const { return m_wtx; }
    const CTxOut& GetTxOut() const { return m_output; }
};

} // namespace wallet

#endif // LATTICA_WALLET_TRANSACTION_H
