// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <lattica-build-config.h> // IWYU pragma: keep

#include <banman.h>
#include <blockfilter.h>
#include <chain.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <common/settings.h>
#include <consensus/amount.h>
#include <consensus/merkle.h>
#include <consensus/validation.h>
#ifdef ENABLE_EXTERNAL_SIGNER
#include <external_signer.h>
#endif
#include <httprpc.h>
#include <index/blockfilterindex.h>
#include <init.h>
#include <interfaces/chain.h>
#include <interfaces/handler.h>
#include <interfaces/mining.h>
#include <interfaces/node.h>
#include <interfaces/rpc.h>
#include <interfaces/types.h>
#include <kernel/chain.h>
#include <kernel/context.h>
#include <kernel/mempool_entry.h>
#include <kernel/mempool_limits.h>
#include <kernel/mempool_removal_reason.h>
#include <key.h>
#include <logging.h>
#include <mapport.h>
#include <net.h>
#include <net_processing.h>
#include <net_types.h>
#include <netaddress.h>
#include <netbase.h>
#include <node/blockstorage.h>
#include <node/coin.h>
#include <node/context.h>
#include <node/interface_ui.h>
#include <node/kernel_notifications.h>
#include <node/miner.h>
#include <node/mini_miner.h>
#include <node/mining_args.h>
#include <node/mining_types.h>
#include <node/transaction.h>
#include <node/types.h>
#include <node/warnings.h>
#include <policy/feerate.h>
#include <policy/fees/block_policy_estimator.h>
#include <policy/policy.h>
#include <policy/rbf.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <rpc/blockchain.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <sync.h>
#include <txmempool.h>
#include <uint256.h>
#include <univalue.h>
#include <util/btcsignals.h>
#include <util/check.h>
#include <util/result.h>
#include <util/signalinterrupt.h>
#include <util/string.h>
#include <util/time.h>
#include <util/translation.h>
#include <validation.h>
#include <validationinterface.h>

#include <any>
#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

using interfaces::BlockRef;
using interfaces::BlockTemplate;
using interfaces::BlockTip;
using interfaces::Chain;
using interfaces::FoundBlock;
using interfaces::Handler;
using interfaces::MakeSignalHandler;
using interfaces::Mining;
using interfaces::Node;
using interfaces::Rpc;
using interfaces::WalletLoader;
using kernel::ChainstateRole;
using node::BlockAssembler;
using node::BlockCreateOptions;
using node::BlockWaitOptions;
using node::CoinbaseTx;
using util::Join;

namespace node {
// All members of the classes in this namespace are intentionally public, as the
// classes themselves are private.
namespace {
#ifdef ENABLE_EXTERNAL_SIGNER
class ExternalSignerImpl : public interfaces::ExternalSigner
{
public:
    ExternalSignerImpl(::ExternalSigner signer) : m_signer(std::move(signer)) {}
    std::string getName() override { return m_signer.m_name; }
    ::ExternalSigner m_signer;
};
#endif

class NodeImpl : public Node
{
public:
    explicit NodeImpl(NodeContext& context) { setContext(&context); }
    void initLogging() override { InitLogging(args()); }
    void initParameterInteraction() override { InitParameterInteraction(args()); }
    bilingual_str getWarnings() override { return Join(Assert(m_context->warnings)->GetMessages(), Untranslated("<hr />")); }
    int getExitStatus() override { return Assert(m_context)->exit_status.load(); }
    BCLog::CategoryMask getLogCategories() override { return LogInstance().GetCategoryMask(); }
    bool baseInitialize() override
    {
        if (!AppInitBasicSetup(args(), Assert(context())->exit_status)) return false;
        if (!AppInitParameterInteraction(args())) return false;

        m_context->warnings = std::make_unique<node::Warnings>();
        m_context->kernel = std::make_unique<kernel::Context>();
        if (!AppInitSanityChecks(*m_context->kernel)) return false;

        if (!AppInitLockDirectories()) return false;
        if (!AppInitInterfaces(*m_context)) return false;

        return true;
    }
    bool appInitMain(interfaces::BlockAndHeaderTipInfo* tip_info) override
    {
        if (AppInitMain(*m_context, tip_info)) return true;
        // Error during initialization, set exit status before continue
        m_context->exit_status.store(EXIT_FAILURE);
        return false;
    }
    void appShutdown() override
    {
        Shutdown(*m_context);
    }
    void startShutdown() override
    {
        NodeContext& ctx{*Assert(m_context)};
        if (!(Assert(ctx.shutdown_request))()) {
            LogError("Failed to send shutdown signal\n");
        }
        Interrupt(*m_context);
    }
    bool shutdownRequested() override { return ShutdownRequested(*Assert(m_context)); };
    bool isSettingIgnored(const std::string& name) override
    {
        bool ignored = false;
        args().LockSettings([&](common::Settings& settings) {
            if (auto* options = common::FindKey(settings.command_line_options, name)) {
                ignored = !options->empty();
            }
        });
        return ignored;
    }
    common::SettingsValue getPersistentSetting(const std::string& name) override { return args().GetPersistentSetting(name); }
    void updateRwSetting(const std::string& name, const common::SettingsValue& value) override
    {
        args().LockSettings([&](common::Settings& settings) {
            if (value.isNull()) {
                settings.rw_settings.erase(name);
            } else {
                settings.rw_settings[name] = value;
            }
        });
        args().WriteSettingsFile();
    }
    void forceSetting(const std::string& name, const common::SettingsValue& value) override
    {
        args().LockSettings([&](common::Settings& settings) {
            if (value.isNull()) {
                settings.forced_settings.erase(name);
            } else {
                settings.forced_settings[name] = value;
            }
        });
    }
    void resetSettings() override
    {
        args().WriteSettingsFile(/*errors=*/nullptr, /*backup=*/true);
        args().LockSettings([&](common::Settings& settings) {
            settings.rw_settings.clear();
        });
        args().WriteSettingsFile();
    }
    void mapPort(bool enable) override { StartMapPort(enable); }
    std::optional<Proxy> getProxy(Network net) override { return GetProxy(net); }
    size_t getNodeCount(ConnectionDirection flags) override
    {
        return m_context->connman ? m_context->connman->GetNodeCount(flags) : 0;
    }
    bool getNodesStats(NodesStats& stats) override
    {
        stats.clear();

        if (m_context->connman) {
            std::vector<CNodeStats> stats_temp;
            m_context->connman->GetNodeStats(stats_temp);

            stats.reserve(stats_temp.size());
            for (auto& node_stats_temp : stats_temp) {
                stats.emplace_back(std::move(node_stats_temp), false, CNodeStateStats());
            }

            // Try to retrieve the CNodeStateStats for each node.
            if (m_context->peerman) {
                TRY_LOCK(::cs_main, lockMain);
                if (lockMain) {
                    for (auto& node_stats : stats) {
                        std::get<1>(node_stats) =
                            m_context->peerman->GetNodeStateStats(std::get<0>(node_stats).nodeid, std::get<2>(node_stats));
                    }
                }
            }
            return true;
        }
        return false;
    }
    bool getBanned(banmap_t& banmap) override
    {
        if (m_context->banman) {
            m_context->banman->GetBanned(banmap);
            return true;
        }
        return false;
    }
    bool ban(const CNetAddr& net_addr, int64_t ban_time_offset) override
    {
        if (m_context->banman) {
            m_context->banman->Ban(net_addr, ban_time_offset);
            return true;
        }
        return false;
    }
    bool unban(const CSubNet& ip) override
    {
        if (m_context->banman) {
            m_context->banman->Unban(ip);
            return true;
        }
        return false;
    }
    bool disconnectByAddress(const CNetAddr& net_addr) override
    {
        if (m_context->connman) {
            return m_context->connman->DisconnectNode(net_addr);
        }
        return false;
    }
    bool disconnectById(NodeId id) override
    {
        if (m_context->connman) {
            return m_context->connman->DisconnectNode(id);
        }
        return false;
    }
    std::vector<std::unique_ptr<interfaces::ExternalSigner>> listExternalSigners() override
    {
#ifdef ENABLE_EXTERNAL_SIGNER
        std::vector<ExternalSigner> signers = {};
        const std::string command = args().GetArg("-signer", "");
        if (command == "") return {};
        ExternalSigner::Enumerate(command, signers, Params().GetChainTypeString());
        std::vector<std::unique_ptr<interfaces::ExternalSigner>> result;
        result.reserve(signers.size());
        for (auto& signer : signers) {
            result.emplace_back(std::make_unique<ExternalSignerImpl>(std::move(signer)));
        }
        return result;
#else
        // This result is indistinguishable from a successful call that returns
        // no signers. For the current GUI this doesn't matter, because the wallet
        // creation dialog disables the external signer checkbox in both
        // cases. The return type could be changed to std::optional<std::vector>
        // (or something that also includes error messages) if this distinction
        // becomes important.
        return {};
#endif // ENABLE_EXTERNAL_SIGNER
    }
    int64_t getTotalBytesRecv() override { return m_context->connman ? m_context->connman->GetTotalBytesRecv() : 0; }
    int64_t getTotalBytesSent() override { return m_context->connman ? m_context->connman->GetTotalBytesSent() : 0; }
    size_t getMempoolSize() override { return m_context->mempool ? m_context->mempool->size() : 0; }
    size_t getMempoolDynamicUsage() override { return m_context->mempool ? m_context->mempool->DynamicMemoryUsage() : 0; }
    size_t getMempoolMaxUsage() override { return m_context->mempool ? m_context->mempool->m_opts.max_size_bytes : 0; }
    bool getHeaderTip(int& height, int64_t& block_time) override
    {
        LOCK(::cs_main);
        auto best_header = chainman().m_best_header;
        if (best_header) {
            height = best_header->nHeight;
            block_time = best_header->GetBlockTime();
            return true;
        }
        return false;
    }
    std::map<CNetAddr, LocalServiceInfo> getNetLocalAddresses() override
    {
        if (m_context->connman)
            return m_context->connman->getNetLocalAddresses();
        else
            return {};
    }
    int getNumBlocks() override
    {
        LOCK(::cs_main);
        return chainman().ActiveChain().Height();
    }
    uint256 getBestBlockHash() override
    {
        const CBlockIndex* tip = WITH_LOCK(::cs_main, return chainman().ActiveChain().Tip());
        return tip ? tip->GetBlockHash() : chainman().GetParams().GenesisBlock().GetHash();
    }
    int64_t getLastBlockTime() override
    {
        LOCK(::cs_main);
        if (chainman().ActiveChain().Tip()) {
            return chainman().ActiveChain().Tip()->GetBlockTime();
        }
        return chainman().GetParams().GenesisBlock().GetBlockTime(); // Genesis block's time of current network
    }
    double getVerificationProgress() override
    {
        LOCK(chainman().GetMutex());
        return chainman().GuessVerificationProgress(chainman().ActiveTip());
    }
    bool isInitialBlockDownload() override
    {
        return chainman().IsInitialBlockDownload();
    }
    bool isLoadingBlocks() override { return chainman().m_blockman.LoadingBlocks(); }
    void setNetworkActive(bool active) override
    {
        if (m_context->connman) {
            m_context->connman->SetNetworkActive(active);
        }
    }
    bool getNetworkActive() override { return m_context->connman && m_context->connman->GetNetworkActive(); }
    CFeeRate getDustRelayFee() override
    {
        if (!m_context->mempool) return CFeeRate{DUST_RELAY_TX_FEE};
        return m_context->mempool->m_opts.dust_relay_feerate;
    }
    UniValue executeRpc(const std::string& command, const UniValue& params, const std::string& uri) override
    {
        JSONRPCRequest req;
        req.context = m_context;
        req.params = params;
        req.strMethod = command;
        req.URI = uri;
        return ::tableRPC.execute(req);
    }
    std::vector<std::string> listRpcCommands() override { return ::tableRPC.listCommands(); }
    std::optional<Coin> getUnspentOutput(const COutPoint& output) override
    {
        LOCK(::cs_main);
        return chainman().ActiveChainstate().CoinsTip().GetCoin(output);
    }
    TransactionError broadcastTransaction(CTransactionRef tx, CAmount max_tx_fee, std::string& err_string) override
    {
        return BroadcastTransaction(*m_context,
                                    std::move(tx),
                                    err_string,
                                    max_tx_fee,
                                    TxBroadcast::MEMPOOL_AND_BROADCAST_TO_ALL,
                                    /*wait_callback=*/false);
    }
    WalletLoader& walletLoader() override
    {
        return *Assert(m_context->wallet_loader);
    }
    std::unique_ptr<Handler> handleInitMessage(InitMessageFn fn) override
    {
        return MakeSignalHandler(::uiInterface.InitMessage.connect(fn));
    }
    std::unique_ptr<Handler> handleMessageBox(MessageBoxFn fn) override
    {
        return MakeSignalHandler(::uiInterface.ThreadSafeMessageBox.connect(fn));
    }
    std::unique_ptr<Handler> handleQuestion(QuestionFn fn) override
    {
        return MakeSignalHandler(::uiInterface.ThreadSafeQuestion.connect(fn));
    }
    std::unique_ptr<Handler> handleShowProgress(ShowProgressFn fn) override
    {
        return MakeSignalHandler(::uiInterface.ShowProgress.connect(fn));
    }
    std::unique_ptr<Handler> handleInitWallet(InitWalletFn fn) override
    {
        return MakeSignalHandler(::uiInterface.InitWallet.connect(fn));
    }
    std::unique_ptr<Handler> handleNotifyNumConnectionsChanged(NotifyNumConnectionsChangedFn fn) override
    {
        return MakeSignalHandler(::uiInterface.NotifyNumConnectionsChanged.connect(fn));
    }
    std::unique_ptr<Handler> handleNotifyNetworkActiveChanged(NotifyNetworkActiveChangedFn fn) override
    {
        return MakeSignalHandler(::uiInterface.NotifyNetworkActiveChanged.connect(fn));
    }
    std::unique_ptr<Handler> handleNotifyAlertChanged(NotifyAlertChangedFn fn) override
    {
        return MakeSignalHandler(::uiInterface.NotifyAlertChanged.connect(fn));
    }
    std::unique_ptr<Handler> handleBannedListChanged(BannedListChangedFn fn) override
    {
        return MakeSignalHandler(::uiInterface.BannedListChanged.connect(fn));
    }
    std::unique_ptr<Handler> handleNotifyBlockTip(NotifyBlockTipFn fn) override
    {
        return MakeSignalHandler(::uiInterface.NotifyBlockTip.connect([fn](SynchronizationState sync_state, const CBlockIndex& block, double verification_progress) {
            fn(sync_state, BlockTip{block.nHeight, block.GetBlockTime(), block.GetBlockHash()}, verification_progress);
        }));
    }
    std::unique_ptr<Handler> handleNotifyHeaderTip(NotifyHeaderTipFn fn) override
    {
        return MakeSignalHandler(
            ::uiInterface.NotifyHeaderTip.connect([fn](SynchronizationState sync_state, int64_t height, int64_t timestamp, bool presync) {
                fn(sync_state, BlockTip{(int)height, timestamp, uint256{}}, presync);
            }));
    }
    NodeContext* context() override { return m_context; }
    void setContext(NodeContext* context) override
    {
        m_context = context;
    }
    ArgsManager& args() { return *Assert(Assert(m_context)->args); }
    ChainstateManager& chainman() { return *Assert(m_context->chainman); }
    NodeContext* m_context{nullptr};
};

// NOLINTNEXTLINE(misc-no-recursion)
bool FillBlock(const CBlockIndex* index, const FoundBlock& block, UniqueLock<RecursiveMutex>& lock, const CChain& active, const BlockManager& blockman) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    if (!index) return false;
    if (block.m_hash) *block.m_hash = index->GetBlockHash();
    if (block.m_height) *block.m_height = index->nHeight;
    if (block.m_time) *block.m_time = index->GetBlockTime();
    if (block.m_max_time) *block.m_max_time = index->GetBlockTimeMax();
    if (block.m_mtp_time) *block.m_mtp_time = index->GetMedianTimePast();
    if (block.m_in_active_chain) *block.m_in_active_chain = active[index->nHeight] == index;
    if (block.m_locator) { *block.m_locator = GetLocator(index); }
    if (block.m_next_block) FillBlock(active[index->nHeight] == index ? active[index->nHeight + 1] : nullptr, *block.m_next_block, lock, active, blockman);
    if (block.m_data) {
        REVERSE_LOCK(lock, cs_main);
        if (!blockman.ReadBlock(*block.m_data, *index)) block.m_data->SetNull();
    }
    block.found = true;
    return true;
}


class BlockTemplateImpl : public BlockTemplate
{
public:
    explicit BlockTemplateImpl(BlockCreateOptions create_options,
                               std::unique_ptr<CBlockTemplate> block_template,
                               const NodeContext& node) : m_create_options(std::move(create_options)),
                                                          m_block_template(std::move(block_template)),
                                                          m_node(node)
    {
        assert(m_block_template);
    }

    CBlockHeader getBlockHeader() override
    {
        return m_block_template->block;
    }

    CBlock getBlock() override
    {
        return m_block_template->block;
    }

    std::vector<CAmount> getTxFees() override
    {
        return m_block_template->vTxFees;
    }

    std::vector<int64_t> getTxSigops() override
    {
        return m_block_template->vTxSigOpsCost;
    }

    CoinbaseTx getCoinbaseTx() override
    {
        return m_block_template->m_coinbase_tx;
    }

    std::vector<uint256> getCoinbaseMerklePath() override
    {
        return TransactionMerklePath(m_block_template->block, 0);
    }

    bool submitSolution(uint32_t version, uint32_t timestamp, uint32_t nonce, CTransactionRef coinbase) override
    {
        AddMerkleRootAndCoinbase(m_block_template->block, std::move(coinbase), version, timestamp, nonce);
        std::string reason;
        std::string debug;
        return SubmitBlock(chainman(), std::make_shared<const CBlock>(m_block_template->block), /*new_block=*/nullptr, reason, debug);
    }

    std::unique_ptr<BlockTemplate> waitNext(BlockWaitOptions options) override
    {
        auto new_template = WaitAndCreateNewBlock(chainman(),
                                                  notifications(),
                                                  m_node.mempool.get(),
                                                  m_block_template,
                                                  /*wait_options=*/options,
                                                  /*create_options=*/m_create_options,
                                                  /*interrupt_wait=*/m_interrupt_wait);
        if (new_template) return std::make_unique<BlockTemplateImpl>(m_create_options, std::move(new_template), m_node);
        return nullptr;
    }

    void interruptWait() override
    {
        InterruptWait(notifications(), m_interrupt_wait);
    }

    const BlockCreateOptions m_create_options;

    const std::unique_ptr<CBlockTemplate> m_block_template;

    bool m_interrupt_wait{false};
    ChainstateManager& chainman() { return *Assert(m_node.chainman); }
    KernelNotifications& notifications() { return *Assert(m_node.notifications); }
    const NodeContext& m_node;
};


class MinerImpl : public Mining
{
public:
    explicit MinerImpl(const NodeContext& node) : m_node(node) {}

    bool isTestChain() override
    {
        return chainman().GetParams().IsTestChain();
    }

    bool isInitialBlockDownload() override
    {
        return chainman().IsInitialBlockDownload();
    }

    std::optional<BlockRef> getTip() override
    {
        return GetTip(chainman());
    }

    std::optional<BlockRef> waitTipChanged(uint256 current_tip, MillisecondsDouble timeout) override
    {
        return WaitTipChanged(chainman(), notifications(), current_tip, timeout, m_interrupt_mining);
    }

    std::unique_ptr<BlockTemplate> createNewBlock(const BlockCreateOptions& options, bool cooldown) override
    {
        // Ensure m_tip_block is set so consumers of BlockTemplate can rely on that.
        std::optional<BlockRef> maybe_tip{waitTipChanged(uint256::ZERO, MillisecondsDouble::max())};

        if (!maybe_tip) return {};

        if (cooldown) {
            // Do not return a template during IBD, because it can have long
            // pauses and sometimes takes a while to get started. Although this
            // is useful in general, it's gated behind the cooldown argument,
            // because on regtest and single miner signets this would wait
            // forever if no block was mined in the past day.
            while (chainman().IsInitialBlockDownload()) {
                maybe_tip = waitTipChanged(maybe_tip->hash, MillisecondsDouble{1000});
                if (!maybe_tip || chainman().m_interrupt || WITH_LOCK(notifications().m_tip_block_mutex, return m_interrupt_mining)) return {};
            }

            // Also wait during the final catch-up moments after IBD.
            if (!CooldownIfHeadersAhead(chainman(), notifications(), *maybe_tip, m_interrupt_mining)) return {};
        }
        const BlockCreateOptions create_options{MergeMiningOptions(options, m_node.mining_args)};
        return std::make_unique<BlockTemplateImpl>(create_options,
                                                   BlockAssembler{
                                                       chainman().ActiveChainstate(),
                                                       m_node.mempool.get(),
                                                       create_options,
                                                   }.CreateNewBlock(),
                                                   m_node);
    }

    void interrupt() override
    {
        InterruptWait(notifications(), m_interrupt_mining);
    }

    bool checkBlock(const CBlock& block, const node::BlockCheckOptions& options, std::string& reason, std::string& debug) override
    {
        LOCK(chainman().GetMutex());
        BlockValidationState state{TestBlockValidity(chainman().ActiveChainstate(), block, /*check_pow=*/options.check_pow, /*check_merkle_root=*/options.check_merkle_root)};
        reason = state.GetRejectReason();
        debug = state.GetDebugMessage();
        return state.IsValid();
    }

    bool submitBlock(const CBlock& block_in, std::string& reason, std::string& debug) override
    {
        auto block = std::make_shared<const CBlock>(block_in);
        bool new_block;
        const bool accepted = SubmitBlock(chainman(), block, &new_block, reason, debug);
        // ProcessNewBlock() can accept and store a block before it is checked
        // for validity. Treat duplicates as errors for mining clients, and only
        // return success when validation completed without setting a reason.
        return accepted && new_block && reason.empty();
    }

    const NodeContext* context() override { return &m_node; }
    ChainstateManager& chainman() { return *Assert(m_node.chainman); }
    KernelNotifications& notifications() { return *Assert(m_node.notifications); }
    // Treat as if guarded by notifications().m_tip_block_mutex
    bool m_interrupt_mining{false};
    const NodeContext& m_node;
};

class RpcImpl : public Rpc
{
public:
    explicit RpcImpl(NodeContext& node) : m_node(node) {}

    UniValue executeRpc(UniValue request, std::string uri, std::string user) override
    {
        JSONRPCRequest req;
        req.context = &m_node;
        req.URI = std::move(uri);
        req.authUser = std::move(user);
        HTTPStatusCode status;
        return ExecuteHTTPRPC(request, req, status);
    }

    NodeContext& m_node;
};

} // namespace
} // namespace node

namespace interfaces {
std::unique_ptr<Node> MakeNode(node::NodeContext& context) { return std::make_unique<node::NodeImpl>(context); }
std::unique_ptr<Rpc> MakeRpc(node::NodeContext& context) { return std::make_unique<node::RpcImpl>(context); }
std::unique_ptr<Mining> MakeMining(const node::NodeContext& context, bool wait_loaded)
{
    if (wait_loaded) {
        node::KernelNotifications& kernel_notifications(*Assert(context.notifications));
        util::SignalInterrupt& interrupt(*Assert(context.shutdown_signal));
        WAIT_LOCK(kernel_notifications.m_tip_block_mutex, lock);
        kernel_notifications.m_tip_block_cv.wait(lock, [&]() EXCLUSIVE_LOCKS_REQUIRED(kernel_notifications.m_tip_block_mutex) {
            return kernel_notifications.m_state.chainstate_loaded || interrupt;
        });
        if (interrupt) return nullptr;
    }
    return std::make_unique<node::MinerImpl>(context);
}
} // namespace interfaces

// ===========================================================================
// interfaces::Chain — the wallet-facing chain/mempool/notification adapter.
// (Was src/interfaces/chain.cpp; Core keeps this in node/interfaces.cpp.)
// ===========================================================================
namespace interfaces {
namespace {

//! Bridge from the validation signal bus to a client's Chain::Notifications.
class NotificationsProxy final : public CValidationInterface
{
public:
    explicit NotificationsProxy(std::shared_ptr<Chain::Notifications> notifications)
        : m_notifications(std::move(notifications)) {}
    virtual ~NotificationsProxy() = default;

    void TransactionAddedToMempool(const NewMempoolTransactionInfo& tx, uint64_t /*mempool_sequence*/) override
    {
        m_notifications->transactionAddedToMempool(tx.info.m_tx);
    }
    void TransactionRemovedFromMempool(const CTransactionRef& tx, MemPoolRemovalReason reason, uint64_t /*mempool_sequence*/) override
    {
        m_notifications->transactionRemovedFromMempool(tx, reason);
    }
    void BlockConnected(const kernel::ChainstateRole& role, const std::shared_ptr<const CBlock>& block, const CBlockIndex* index) override
    {
        m_notifications->blockConnected(role, kernel::MakeBlockInfo(index, block.get()));
    }
    void BlockDisconnected(const std::shared_ptr<const CBlock>& block, const CBlockIndex* index) override
    {
        m_notifications->blockDisconnected(kernel::MakeBlockInfo(index, block.get()));
    }
    void UpdatedBlockTip(const CBlockIndex* /*new_tip*/, const CBlockIndex* /*fork*/, bool /*initial_download*/) override
    {
        m_notifications->updatedBlockTip();
    }
    void ChainStateFlushed(const kernel::ChainstateRole& role, const CBlockLocator& locator) override
    {
        m_notifications->chainStateFlushed(role, locator);
    }

    std::shared_ptr<Chain::Notifications> m_notifications;
};

//! RPC command handler: registers the command with the global RPC table on
//! construction and removes it on disconnect. Lets a chain client (the wallet)
//! add RPCs to the node's RPC server (ported from Core's node/interfaces.cpp).
class RpcHandlerImpl : public Handler
{
public:
    explicit RpcHandlerImpl(const CRPCCommand& command) : m_command(command), m_wrapped_command(&command)
    {
        m_command.actor = [this](const JSONRPCRequest& request, UniValue& result, bool last_handler) {
            if (!m_wrapped_command) return false;
            try {
                return m_wrapped_command->actor(request, result, last_handler);
            } catch (const UniValue& e) {
                // If this is not the last handler and a wallet not found
                // exception was thrown, return false so the next handler can
                // try to handle the request. Otherwise, reraise the exception.
                if (!last_handler) {
                    const UniValue& code = e["code"];
                    if (code.isNum() && code.getInt<int>() == RPC_WALLET_NOT_FOUND) {
                        return false;
                    }
                }
                throw;
            }
        };
        ::tableRPC.appendCommand(m_command.name, &m_command);
    }

    void disconnect() final
    {
        if (m_wrapped_command) {
            m_wrapped_command = nullptr;
            ::tableRPC.removeCommand(m_command.name, &m_command);
        }
    }

    ~RpcHandlerImpl() override { disconnect(); }

    CRPCCommand m_command;
    const CRPCCommand* m_wrapped_command;
};

class ChainImpl final : public Chain
{
public:
    ChainImpl(ChainstateManager& chainman, CTxMemPool& mempool, ValidationSignals& signals, CBlockPolicyEstimator* fee_estimator)
        : m_chainman_explicit(&chainman), m_mempool_explicit(&mempool), m_signals_explicit(&signals), m_fee_estimator_explicit(fee_estimator) {}
    explicit ChainImpl(node::NodeContext& node) : m_node(&node) {}

    //! Fill a FoundBlock from a block index. Assumes ::cs_main is held (it reads
    //! the active chain and may read block data from disk).
    bool FillBlock(const CBlockIndex* index, const FoundBlock& block) EXCLUSIVE_LOCKS_REQUIRED(::cs_main)
    {
        if (!index) return false;
        const CChain& active = chainman().ActiveChain();
        if (block.m_hash) *block.m_hash = index->GetBlockHash();
        if (block.m_height) *block.m_height = index->nHeight;
        if (block.m_time) *block.m_time = index->GetBlockTime();
        if (block.m_max_time) *block.m_max_time = index->GetBlockTimeMax();
        if (block.m_mtp_time) *block.m_mtp_time = index->GetMedianTimePast();
        if (block.m_in_active_chain) *block.m_in_active_chain = active.Contains(*index);
        if (block.m_locator) *block.m_locator = GetLocator(index);
        if (block.m_next_block) FillBlock(active.Contains(*index) ? active.Next(*index) : nullptr, *block.m_next_block);
        if (block.m_data) {
            if (!chainman().m_blockman.ReadBlock(*block.m_data, *index)) block.m_data->SetNull();
        }
        block.found = true;
        return true;
    }

    std::optional<int> getHeight() override
    {
        LOCK(::cs_main);
        const int height{chainman().ActiveChain().Height()};
        if (height >= 0) return height;
        return std::nullopt;
    }
    uint256 getBlockHash(int height) override
    {
        LOCK(::cs_main);
        const CBlockIndex* block{chainman().ActiveChain()[height]};
        assert(block);
        return block->GetBlockHash();
    }
    bool haveBlockOnDisk(int height) override
    {
        LOCK(::cs_main);
        const CBlockIndex* block{chainman().ActiveChain()[height]};
        return block && ((block->nStatus & BLOCK_HAVE_DATA) != 0) && block->nTx > 0;
    }
    std::optional<int> findLocatorFork(const CBlockLocator& locator) override
    {
        LOCK(::cs_main);
        if (const CBlockIndex* fork = chainman().ActiveChainstate().FindForkInGlobalIndex(locator)) {
            return fork->nHeight;
        }
        return std::nullopt;
    }
    bool findBlock(const uint256& hash, const FoundBlock& block) override
    {
        LOCK(::cs_main);
        return FillBlock(chainman().m_blockman.LookupBlockIndex(hash), block);
    }
    bool findFirstBlockWithTimeAndHeight(int64_t min_time, int min_height, const FoundBlock& block) override
    {
        LOCK(::cs_main);
        return FillBlock(chainman().ActiveChain().FindEarliestAtLeast(min_time, min_height), block);
    }
    bool findAncestorByHeight(const uint256& block_hash, int ancestor_height, const FoundBlock& ancestor_out) override
    {
        LOCK(::cs_main);
        const CBlockIndex* block{chainman().m_blockman.LookupBlockIndex(block_hash)};
        const CBlockIndex* ancestor{block ? block->GetAncestor(ancestor_height) : nullptr};
        return FillBlock(ancestor, ancestor_out);
    }
    bool findAncestorByHash(const uint256& block_hash, const uint256& ancestor_hash, const FoundBlock& ancestor_out) override
    {
        LOCK(::cs_main);
        const CBlockIndex* block{chainman().m_blockman.LookupBlockIndex(block_hash)};
        const CBlockIndex* ancestor{chainman().m_blockman.LookupBlockIndex(ancestor_hash)};
        if (block && ancestor && block->GetAncestor(ancestor->nHeight) != ancestor) ancestor = nullptr;
        return FillBlock(ancestor, ancestor_out);
    }
    bool findCommonAncestor(const uint256& block_hash1, const uint256& block_hash2, const FoundBlock& ancestor_out, const FoundBlock& block1_out, const FoundBlock& block2_out) override
    {
        LOCK(::cs_main);
        const CBlockIndex* block1{chainman().m_blockman.LookupBlockIndex(block_hash1)};
        const CBlockIndex* block2{chainman().m_blockman.LookupBlockIndex(block_hash2)};
        const CBlockIndex* ancestor{block1 && block2 ? LastCommonAncestor(block1, block2) : nullptr};
        // Using & instead of && below to avoid short circuiting and leaving
        // output uninitialized. Cast bool to int to avoid -Wbitwise-instead-of-logical.
        return int{FillBlock(ancestor, ancestor_out)} & int{FillBlock(block1, block1_out)} & int{FillBlock(block2, block2_out)};
    }
    void findCoins(std::map<COutPoint, Coin>& coins) override
    {
        LOCK2(::cs_main, mempool().cs);
        CCoinsViewCache& chain_view{chainman().ActiveChainstate().CoinsTip()};
        CCoinsViewMemPool mempool_view{&chain_view, mempool()};
        for (auto& [outpoint, coin] : coins) {
            if (auto c{mempool_view.GetCoin(outpoint)}) coin = std::move(*c);
        }
    }
    double guessVerificationProgress(const uint256& block_hash) override
    {
        LOCK(::cs_main);
        return chainman().GuessVerificationProgress(chainman().m_blockman.LookupBlockIndex(block_hash));
    }
    bool hasBlocks(const uint256& block_hash, int min_height, std::optional<int> max_height) override
    {
        LOCK(::cs_main);
        if (const CBlockIndex* block{chainman().m_blockman.LookupBlockIndex(block_hash)}) {
            if (max_height && block->nHeight >= *max_height) block = block->GetAncestor(*max_height);
            for (; block->nStatus & BLOCK_HAVE_DATA; block = block->pprev) {
                if (block->nHeight <= min_height) return true;
            }
        }
        return false;
    }
    bool isInMempool(const Txid& txid) override
    {
        LOCK(mempool().cs);
        return mempool().exists(txid);
    }
    bool hasDescendantsInMempool(const Txid& txid) override
    {
        LOCK(mempool().cs);
        const auto it = mempool().GetIter(txid);
        // GetDescendantCount includes the entry itself, so >1 means it has descendants.
        return it && mempool().GetDescendantCount(*it) > 1;
    }
    bool broadcastTransaction(const CTransactionRef& tx, const CAmount& /*max_tx_fee*/, node::TxBroadcast /*broadcast_method*/, std::string& err_string) override
    {
        // Lattica has no P2P relay layer yet, so this only submits to the local
        // mempool; the unbroadcast set records the txid so a future net layer can
        // resend. The max_tx_fee gate and the relay/no-relay distinction are not
        // honored until that layer exists.
        const MempoolAcceptResult result = chainman().ProcessTransaction(tx, /*test_accept=*/false);
        if (result.m_result_type != MempoolAcceptResult::ResultType::VALID) {
            err_string = result.m_state.ToString();
            return false;
        }
        {
            LOCK(mempool().cs);
            mempool().AddUnbroadcastTx(tx->GetHash());
        }
        return true;
    }
    CFeeRate mempoolMinFee() override { return mempool().GetMinFee(); }
    CFeeRate relayMinFee() override { return CFeeRate{DEFAULT_MIN_RELAY_TX_FEE}; }
    CFeeRate relayIncrementalFee() override { return CFeeRate{DEFAULT_INCREMENTAL_RELAY_FEE}; }
    CFeeRate relayDustFee() override { return CFeeRate{DUST_RELAY_TX_FEE}; }
    CFeeRate estimateSmartFee(int num_blocks, bool conservative, FeeCalculation* calc) override
    {
        if (!fee_estimator()) return {};
        return fee_estimator()->estimateSmartFee(num_blocks, calc, conservative);
    }
    unsigned int estimateMaxBlocks() override
    {
        if (!fee_estimator()) return 0;
        return fee_estimator()->HighestTargetTracked(FeeEstimateHorizon::LONG_HALFLIFE);
    }
    void getTransactionAncestry(const Txid& txid, size_t& ancestors, size_t& cluster_count, size_t* ancestorsize, CAmount* ancestorfees) override
    {
        ancestors = cluster_count = 0;
        mempool().GetTransactionAncestry(txid, ancestors, cluster_count, ancestorsize, ancestorfees);
    }
    void getPackageLimits(unsigned int& limit_ancestor_count, unsigned int& limit_descendant_count) override
    {
        const kernel::MemPoolLimits& limits{mempool().m_opts.limits};
        limit_ancestor_count = limits.ancestor_count;
        limit_descendant_count = limits.descendant_count;
    }
    util::Result<void> checkChainLimits(const CTransactionRef& tx) override
    {
        if (!mempool().CheckPolicyLimits(tx)) {
            return util::Error{Untranslated("too many unconfirmed transactions in cluster")};
        }
        return {};
    }
    std::map<COutPoint, CAmount> calculateIndividualBumpFees(const std::vector<COutPoint>& outpoints, const CFeeRate& target_feerate) override
    {
        return node::MiniMiner(mempool(), outpoints).CalculateBumpFees(target_feerate);
    }
    std::optional<CAmount> calculateCombinedBumpFee(const std::vector<COutPoint>& outpoints, const CFeeRate& target_feerate) override
    {
        return node::MiniMiner(mempool(), outpoints).CalculateTotalBumpFees(target_feerate);
    }
    bool havePruned() override
    {
        LOCK(::cs_main);
        return chainman().m_blockman.m_have_pruned;
    }
    std::optional<int> getPruneHeight() override
    {
        // Pruning is not enabled in Lattica yet; there is no prune height to report.
        return std::nullopt;
    }
    bool isReadyToBroadcast() override
    {
        // Without a net layer there is no "have peers" check; gate only on IBD.
        return !chainman().IsInitialBlockDownload();
    }
    bool isInitialBlockDownload() override { return chainman().IsInitialBlockDownload(); }
    bool shutdownRequested() override { return false; } // no shutdown subsystem wired
    void initMessage(const std::string& message) override { LogInfo("init message: %s", message); }
    void initWarning(const bilingual_str& message) override { LogWarning("%s", message.original); }
    void initError(const bilingual_str& message) override { LogError("%s", message.original); }
    void showProgress(const std::string& /*title*/, int /*progress*/, bool /*resume_possible*/) override {}
    std::unique_ptr<Handler> handleNotifications(std::shared_ptr<Notifications> notifications) override
    {
        auto proxy{std::make_shared<NotificationsProxy>(std::move(notifications))};
        signals().RegisterSharedValidationInterface(proxy);
        ValidationSignals& sigs{signals()};
        return MakeCleanupHandler([&sigs, proxy] { sigs.UnregisterSharedValidationInterface(proxy); });
    }
    std::unique_ptr<Handler> handleRpc(const CRPCCommand& command) override
    {
        return std::make_unique<RpcHandlerImpl>(command);
    }
    common::SettingsValue getSetting(const std::string& name) override
    {
        return args().GetSetting(name);
    }
    std::vector<common::SettingsValue> getSettingsList(const std::string& name) override
    {
        return args().GetSettingsList(name);
    }
    common::SettingsValue getRwSetting(const std::string& name) override
    {
        common::SettingsValue result;
        args().LockSettings([&](const common::Settings& settings) {
            if (const common::SettingsValue* value = common::FindKey(settings.rw_settings, name)) {
                result = *value;
            }
        });
        return result;
    }
    bool updateRwSetting(const std::string& name, const SettingsUpdate& update_settings_func) override
    {
        std::optional<SettingsAction> action;
        args().LockSettings([&](common::Settings& settings) {
            if (auto* value = common::FindKey(settings.rw_settings, name)) {
                action = update_settings_func(*value);
                if (value->isNull()) settings.rw_settings.erase(name);
            } else {
                UniValue new_value;
                action = update_settings_func(new_value);
                if (!new_value.isNull()) settings.rw_settings[name] = std::move(new_value);
            }
        });
        if (!action) return false;
        // Now dump value to disk if requested
        return *action != SettingsAction::WRITE || args().WriteSettingsFile();
    }
    bool overwriteRwSetting(const std::string& name, common::SettingsValue value, SettingsAction action) override
    {
        return updateRwSetting(name, [&](common::SettingsValue& settings) {
            settings = std::move(value);
            return action;
        });
    }
    bool deleteRwSettings(const std::string& name, SettingsAction action) override
    {
        return overwriteRwSetting(name, {}, action);
    }
    void waitForNotificationsIfTipChanged(const uint256& old_tip) override
    {
        if (!old_tip.IsNull()) {
            LOCK(::cs_main);
            const CBlockIndex* tip{chainman().ActiveTip()};
            if (tip && tip->GetBlockHash() == old_tip) return;
        }
        waitForNotifications();
    }
    void waitForNotifications() override { signals().SyncWithValidationInterfaceQueue(); }
    void requestMempoolTransactions(Notifications& notifications) override
    {
        for (const TxMempoolInfo& info : mempool().infoAll()) {
            notifications.transactionAddedToMempool(info.tx);
        }
    }
    bool hasAssumedValidChain() override { return false; } // assumeutxo not enabled in Lattica

    node::NodeContext* context() override { return m_node; }

    // A node-backed Chain is created during init before chainman/mempool/signals
    // exist, so resolve them lazily from the NodeContext; the explicit-pieces ctor
    // binds them up front instead.
    ChainstateManager& chainman() const { return m_node ? *Assert(m_node->chainman) : *Assert(m_chainman_explicit); }
    CTxMemPool& mempool() const { return m_node ? *Assert(m_node->mempool) : *Assert(m_mempool_explicit); }
    ValidationSignals& signals() const { return m_node ? *Assert(m_node->validation_signals) : *Assert(m_signals_explicit); }
    CBlockPolicyEstimator* fee_estimator() const { return m_node ? m_node->fee_estimator.get() : m_fee_estimator_explicit; }
    //! The settings methods are only reachable through the node-backed Chain (the
    //! wallet's), which always has a NodeContext and thus an ArgsManager.
    ArgsManager& args() const { return *Assert(Assert(m_node)->args); }

    node::NodeContext* m_node{nullptr};
    ChainstateManager* m_chainman_explicit{nullptr};
    CTxMemPool* m_mempool_explicit{nullptr};
    ValidationSignals* m_signals_explicit{nullptr};
    CBlockPolicyEstimator* m_fee_estimator_explicit{nullptr};
};

} // namespace

std::unique_ptr<Chain> MakeChain(ChainstateManager& chainman, CTxMemPool& mempool, ValidationSignals& signals, CBlockPolicyEstimator* fee_estimator)
{
    return std::make_unique<ChainImpl>(chainman, mempool, signals, fee_estimator);
}

std::unique_ptr<Chain> MakeChain(node::NodeContext& node)
{
    return std::make_unique<ChainImpl>(node);
}

} // namespace interfaces
