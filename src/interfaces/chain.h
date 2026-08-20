// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.
//
// interfaces::Chain — the node/wallet boundary, ported from Bitcoin Core's
// interfaces/chain.h. The interface lets a client (the wallet) read chain state,
// receive block/mempool notifications, and submit transactions.
//
// Lattica ports a FAITHFUL-BUT-SCOPED surface: every method we keep has Core's
// exact signature, but the methods that in Core back onto subsystems Lattica has
// not built are omitted rather than declared-and-faked. Omitted (see the note at
// the end of the class): the BIP158 block-filter queries, the fee estimator
// (estimateSmartFee/estimateMaxBlocks), CPFP bump-fee calculation, the settings.json
// (*RwSetting / getSetting*) family, the RPC plumbing (handleRpc/rpcEnableDeprecated),
// and context() (no node::NodeContext). MakeChain therefore takes explicit
// chainstate/mempool/signals references instead of a NodeContext.

#ifndef LATTICA_INTERFACES_CHAIN_H
#define LATTICA_INTERFACES_CHAIN_H

#include <common/settings.h>
#include <consensus/amount.h>
#include <kernel/chain.h> // IWYU pragma: export  (interfaces::BlockInfo, kernel::ChainstateRole)
#include <node/types.h>
#include <policy/feerate.h>
#include <primitives/transaction.h>
#include <util/result.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

class CBlock;
class CBlockPolicyEstimator;
class CBlockUndo;
class CRPCCommand;
class ChainstateManager;
class CScheduler;
class CTxMemPool;
class Coin;
class ValidationSignals;
class uint256;
enum class MemPoolRemovalReason;
struct bilingual_str;
struct CBlockLocator;
struct FeeCalculation;
namespace kernel {
struct ChainstateRole;
} // namespace kernel
namespace node {
struct NodeContext;
} // namespace node

namespace interfaces {

class Handler;

//! Result of updateRwSetting: WRITE persists settings.json now, SKIP_WRITE leaves
//! the in-memory change unwritten.
enum class SettingsAction { WRITE, SKIP_WRITE };

//! Callback to mutate a persistent rw setting in place; returns whether to write.
using SettingsUpdate = std::function<std::optional<SettingsAction>(common::SettingsValue&)>;

//! Helper for findBlock to selectively return pieces of block data. If block is
//! found, data will be returned by setting specified output variables. If block
//! is not found, output variables will keep their previous values.
class FoundBlock
{
public:
    FoundBlock& hash(uint256& hash) { m_hash = &hash; return *this; }
    FoundBlock& height(int& height) { m_height = &height; return *this; }
    FoundBlock& time(int64_t& time) { m_time = &time; return *this; }
    FoundBlock& maxTime(int64_t& max_time) { m_max_time = &max_time; return *this; }
    FoundBlock& mtpTime(int64_t& mtp_time) { m_mtp_time = &mtp_time; return *this; }
    //! Return whether block is in the active (most-work) chain.
    FoundBlock& inActiveChain(bool& in_active_chain) { m_in_active_chain = &in_active_chain; return *this; }
    //! Return locator if block is in the active chain.
    FoundBlock& locator(CBlockLocator& locator) { m_locator = &locator; return *this; }
    //! Return next block in the active chain if current block is in the active chain.
    FoundBlock& nextBlock(const FoundBlock& next_block) { m_next_block = &next_block; return *this; }
    //! Read block data from disk. If the block exists but doesn't have data
    //! (for example due to pruning), the CBlock variable will be set to null.
    FoundBlock& data(CBlock& data) { m_data = &data; return *this; }

    uint256* m_hash = nullptr;
    int* m_height = nullptr;
    int64_t* m_time = nullptr;
    int64_t* m_max_time = nullptr;
    int64_t* m_mtp_time = nullptr;
    bool* m_in_active_chain = nullptr;
    CBlockLocator* m_locator = nullptr;
    const FoundBlock* m_next_block = nullptr;
    CBlock* m_data = nullptr;
    mutable bool found = false;
};

//! Interface giving clients (wallet processes, maybe other analysis tools in
//! the future) ability to access to the chain state, receive notifications,
//! and submit transactions.
class Chain
{
public:
    virtual ~Chain() = default;

    //! Get current chain height, not including genesis block (returns 0 if
    //! chain only contains genesis block, nullopt if chain does not contain
    //! any blocks)
    virtual std::optional<int> getHeight() = 0;

    //! Get block hash. Height must be valid or this function will abort.
    virtual uint256 getBlockHash(int height) = 0;

    //! Check that the block is available on disk (i.e. has not been
    //! pruned), and contains transactions.
    virtual bool haveBlockOnDisk(int height) = 0;

    //! Return height of the highest block on chain in common with the locator,
    //! which will either be the original block used to create the locator,
    //! or one of its ancestors.
    virtual std::optional<int> findLocatorFork(const CBlockLocator& locator) = 0;

    //! Return whether node has the block and optionally return block metadata
    //! or contents.
    virtual bool findBlock(const uint256& hash, const FoundBlock& block={}) = 0;

    //! Find first block in the chain with timestamp >= the given time
    //! and height >= than the given height, return false if there is no block
    //! with a high enough timestamp and height. Optionally return block
    //! information.
    virtual bool findFirstBlockWithTimeAndHeight(int64_t min_time, int min_height, const FoundBlock& block={}) = 0;

    //! Find ancestor of block at specified height and optionally return
    //! ancestor information.
    virtual bool findAncestorByHeight(const uint256& block_hash, int ancestor_height, const FoundBlock& ancestor_out={}) = 0;

    //! Return whether block descends from a specified ancestor, and
    //! optionally return ancestor information.
    virtual bool findAncestorByHash(const uint256& block_hash,
        const uint256& ancestor_hash,
        const FoundBlock& ancestor_out={}) = 0;

    //! Find most recent common ancestor between two blocks and optionally
    //! return block information.
    virtual bool findCommonAncestor(const uint256& block_hash1,
        const uint256& block_hash2,
        const FoundBlock& ancestor_out={},
        const FoundBlock& block1_out={},
        const FoundBlock& block2_out={}) = 0;

    //! Look up unspent output information. Returns coins in the mempool and in
    //! the current chain UTXO set. Iterates through all the keys in the map and
    //! populates the values.
    virtual void findCoins(std::map<COutPoint, Coin>& coins) = 0;

    //! Estimate fraction of total transactions verified if blocks up to
    //! the specified block hash are verified.
    virtual double guessVerificationProgress(const uint256& block_hash) = 0;

    //! Return true if data is available for all blocks in the specified range
    //! of blocks. This checks all blocks that are ancestors of block_hash in
    //! the height range from min_height to max_height, inclusive.
    virtual bool hasBlocks(const uint256& block_hash, int min_height = 0, std::optional<int> max_height = {}) = 0;

    //! Check if transaction is in mempool.
    virtual bool isInMempool(const Txid& txid) = 0;

    //! Check if transaction has descendants in mempool.
    virtual bool hasDescendantsInMempool(const Txid& txid) = 0;

    //! Process a local transaction, optionally adding it to the mempool and
    //! optionally broadcasting it to the network.
    //! @param[in] tx Transaction to process.
    //! @param[in] max_tx_fee Don't add the transaction to the mempool or
    //! broadcast it if its fee is higher than this.
    //! @param[in] broadcast_method Whether to add the transaction to the
    //! mempool and how/whether to broadcast it.
    //! @param[out] err_string Set if an error occurs.
    //! @return False if the transaction could not be added due to the fee or for another reason.
    virtual bool broadcastTransaction(const CTransactionRef& tx,
                                      const CAmount& max_tx_fee,
                                      node::TxBroadcast broadcast_method,
                                      std::string& err_string) = 0;

    //! Mempool minimum fee.
    virtual CFeeRate mempoolMinFee() = 0;

    //! Relay current minimum fee (from -minrelaytxfee and -incrementalrelayfee settings).
    virtual CFeeRate relayMinFee() = 0;

    //! Relay incremental fee setting (-incrementalrelayfee), reflecting cost of relay.
    virtual CFeeRate relayIncrementalFee() = 0;

    //! Relay dust fee setting (-dustrelayfee), reflecting lowest rate it's economical to spend.
    virtual CFeeRate relayDustFee() = 0;

    //! Estimate smart fee. Delegates to the node's CBlockPolicyEstimator; returns
    //! an unset CFeeRate (0) when no estimator is configured, in which case the
    //! wallet falls back to its own feerate.
    virtual CFeeRate estimateSmartFee(int num_blocks, bool conservative, FeeCalculation* calc = nullptr) = 0;

    //! Fee estimation further than this many blocks in the future is impossible.
    virtual unsigned int estimateMaxBlocks() = 0;

    //! Calculate mempool ancestor and cluster counts for the given transaction.
    virtual void getTransactionAncestry(const Txid& txid, size_t& ancestors, size_t& cluster_count, size_t* ancestorsize = nullptr, CAmount* ancestorfees = nullptr) = 0;

    //! Get the node's package limits.
    //! Currently only returns the ancestor and descendant count limits, but could be enhanced to
    //! return more policy settings.
    virtual void getPackageLimits(unsigned int& limit_ancestor_count, unsigned int& limit_descendant_count) = 0;

    //! Check if transaction will pass the mempool's chain limits.
    virtual util::Result<void> checkChainLimits(const CTransactionRef& tx) = 0;

    //! For each outpoint, calculate the fee-bumping cost to spend it at the target feerate,
    //! including bumping its unconfirmed mempool ancestors (CPFP). Outpoints unavailable from
    //! the mempool get a bump fee of 0. See node::MiniMiner.
    virtual std::map<COutPoint, CAmount> calculateIndividualBumpFees(const std::vector<COutPoint>& outpoints, const CFeeRate& target_feerate) = 0;

    //! Calculate the combined bump fee for an input set, counting shared ancestry once.
    virtual std::optional<CAmount> calculateCombinedBumpFee(const std::vector<COutPoint>& outpoints, const CFeeRate& target_feerate) = 0;

    //! Check if any block has been pruned.
    virtual bool havePruned() = 0;

    //! Get the current prune height.
    virtual std::optional<int> getPruneHeight() = 0;

    //! Check if the node is ready to broadcast transactions.
    virtual bool isReadyToBroadcast() = 0;

    //! Check if in IBD.
    virtual bool isInitialBlockDownload() = 0;

    //! Check if shutdown requested.
    virtual bool shutdownRequested() = 0;

    //! Send init message.
    virtual void initMessage(const std::string& message) = 0;

    //! Send init warning.
    virtual void initWarning(const bilingual_str& message) = 0;

    //! Send init error.
    virtual void initError(const bilingual_str& message) = 0;

    //! Send progress indicator.
    virtual void showProgress(const std::string& title, int progress, bool resume_possible) = 0;

    //! Chain notifications.
    class Notifications
    {
    public:
        virtual ~Notifications() = default;
        virtual void transactionAddedToMempool(const CTransactionRef& tx) {}
        virtual void transactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason) {}
        virtual void blockConnected(const kernel::ChainstateRole& role, const BlockInfo& block) {}
        virtual void blockDisconnected(const BlockInfo& block) {}
        virtual void updatedBlockTip() {}
        virtual void chainStateFlushed(const kernel::ChainstateRole& role, const CBlockLocator& locator) {}
    };

    //! Options specifying which chain notifications are required.
    struct NotifyOptions
    {
        //! Include undo data with block connected notifications.
        bool connect_undo_data = false;
        //! Include block data with block disconnected notifications.
        bool disconnect_data = false;
        //! Include undo data with block disconnected notifications.
        bool disconnect_undo_data = false;
    };

    //! Register handler for notifications.
    //! Some notifications are asynchronous and may still execute after the handler is disconnected.
    //! Use waitForNotifications() after the handler is disconnected to ensure all pending notifications
    //! have been processed.
    virtual std::unique_ptr<Handler> handleNotifications(std::shared_ptr<Notifications> notifications) = 0;

    //! Wait for pending notifications to be processed unless block hash points to the current
    //! chain tip.
    virtual void waitForNotificationsIfTipChanged(const uint256& old_tip) = 0;

    //! Wait for all pending notifications up to this point to be processed
    virtual void waitForNotifications() = 0;

    //! Synchronously send transactionAddedToMempool notifications about all
    //! current mempool transactions to the specified handler and return after
    //! the last one is sent.
    virtual void requestMempoolTransactions(Notifications& notifications) = 0;

    //! Return true if an assumed-valid snapshot is in use. Note that this
    //! returns true even after the snapshot is validated, until the next node
    //! restart.
    virtual bool hasAssumedValidChain() = 0;

    //! Get the node context, if this Chain is backed by one. The wallet-facing MakeChain
    //! (chainstate + mempool + signal bus, no aggregated NodeContext) returns nullptr; the
    //! background index/P2P subsystems that need the full node reach it through here once a
    //! NodeContext-backed Chain is wired by node init.
    virtual node::NodeContext* context() { return nullptr; }

    //! Register handler for RPC. Command is not copied, so reference needs to
    //! remain valid until Handler is disconnected.
    virtual std::unique_ptr<Handler> handleRpc(const CRPCCommand& command) = 0;

    //! Return <datadir>/settings.json setting value.
    virtual common::SettingsValue getSetting(const std::string& arg) = 0;

    //! Return <datadir>/settings.json or -<arg> setting value as a list, parsing
    //! comma-separated string lists into multiple values where applicable.
    virtual std::vector<common::SettingsValue> getSettingsList(const std::string& arg) = 0;

    //! Return <datadir>/settings.json read-write setting value.
    virtual common::SettingsValue getRwSetting(const std::string& name) = 0;

    //! Updates a setting in <datadir>/settings.json. Depending on the action
    //! returned by the update function, this will either WRITE or SKIP_WRITE.
    virtual bool updateRwSetting(const std::string& name, const SettingsUpdate& update_settings_func) = 0;

    //! Replace a setting in <datadir>/settings.json with a new value.
    virtual bool overwriteRwSetting(const std::string& name, common::SettingsValue value, SettingsAction action = SettingsAction::WRITE) = 0;

    //! Delete a given setting in <datadir>/settings.json.
    virtual bool deleteRwSettings(const std::string& name, SettingsAction action = SettingsAction::WRITE) = 0;

    // --- Methods in Core's interfaces::Chain that Lattica omits, because they ---
    // --- back onto subsystems not (yet) ported. Each is omitted, not faked:    ---
    //   hasBlockFilterIndex / blockFilterMatchesAny  -- no BIP158 block filter index
    //   rpcEnableDeprecated                           -- no RPC server
    //   isRBFOptIn                                    -- RBF opt-in query, not referenced
    //                                                    by the spend layer
};

//! Interface to let node manage chain clients (wallets, or maybe tools for
//! monitoring and analysis in the future).
class ChainClient
{
public:
    virtual ~ChainClient() = default;

    //! Register rpcs.
    virtual void registerRpcs() = 0;

    //! Check for errors before loading.
    virtual bool verify() = 0;

    //! Load saved state.
    virtual bool load() = 0;

    //! Start client execution and provide a scheduler.
    virtual void start(CScheduler& scheduler) = 0;

    //! Shut down client.
    virtual void stop() = 0;

    //! Set mock time.
    virtual void setMockTime(int64_t time) = 0;

    //! Mock the scheduler to fast forward in time.
    virtual void schedulerMockForward(std::chrono::seconds delta_seconds) = 0;
};

//! Return implementation of the Chain interface backed by the given chainstate,
//! mempool and validation-signal bus. (Core's MakeChain takes a node::NodeContext;
//! Lattica passes the pieces explicitly, as it has no aggregated NodeContext.)
//! `fee_estimator` is optional: when null, estimateSmartFee returns an unset feerate
//! and the wallet falls back to its own configured feerate.
std::unique_ptr<Chain> MakeChain(ChainstateManager& chainman, CTxMemPool& mempool, ValidationSignals& signals, CBlockPolicyEstimator* fee_estimator = nullptr);

//! Return a Chain backed by the full node context. Unlike the explicit-pieces
//! overload, the resulting Chain answers context() with this NodeContext, which the
//! index and P2P subsystems wired by node init rely on.
std::unique_ptr<Chain> MakeChain(node::NodeContext& node);

} // namespace interfaces

#endif // LATTICA_INTERFACES_CHAIN_H
