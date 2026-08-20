// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_RPC_REGISTER_H
#define LATTICA_RPC_REGISTER_H

#include <lattica-build-config.h> // IWYU pragma: keep

/** These are in one header file to avoid creating tons of single-function
 * headers for everything under src/rpc/ */
class CRPCTable;

void RegisterBlockchainRPCCommands(CRPCTable &tableRPC);
void RegisterFeeRPCCommands(CRPCTable&);
void RegisterMempoolRPCCommands(CRPCTable&);
void RegisterMiningRPCCommands(CRPCTable &tableRPC);
void RegisterNodeRPCCommands(CRPCTable&);
void RegisterNetRPCCommands(CRPCTable&);
void RegisterRawTransactionRPCCommands(CRPCTable &tableRPC);
void RegisterSignMessageRPCCommands(CRPCTable&);
void RegisterTxoutProofRPCCommands(CRPCTable&);
void RegisterOutputScriptRPCCommands(CRPCTable&);
// Of the output_script RPCs only validateaddress is kept; the descriptor-based ones
// (createmultisig/deriveaddresses/getdescriptorinfo) and the external-signer RPCs are
// dropped (Lattica is ML-DSA, witness-only, with no descriptor system).

static inline void RegisterAllCoreRPCCommands(CRPCTable &t)
{
    RegisterBlockchainRPCCommands(t);
    RegisterFeeRPCCommands(t);
    RegisterMempoolRPCCommands(t);
    RegisterMiningRPCCommands(t);
    RegisterNodeRPCCommands(t);
    RegisterNetRPCCommands(t);
    RegisterRawTransactionRPCCommands(t);
    RegisterSignMessageRPCCommands(t);
    RegisterTxoutProofRPCCommands(t);
    RegisterOutputScriptRPCCommands(t);
}

#endif // LATTICA_RPC_REGISTER_H