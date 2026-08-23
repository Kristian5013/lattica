// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#ifndef LATTICA_WALLET_FEES_H
#define LATTICA_WALLET_FEES_H

#include <consensus/amount.h>
#include <wallet/types.h>

class CFeeRate;

namespace wallet {
class CCoinControl;
class CWallet;

/**
 * Return the minimum required absolute fee for this size
 * based on the required fee rate
 */
CAmount GetRequiredFee(const CWallet& wallet, unsigned int nTxBytes);

/**
 * Return the minimum fee for this size given a fee rate result.
 */
CAmount GetMinimumFee(const MinimumFeeRateResult& min_fee_rate, unsigned int nTxBytes);

/**
 * Return the minimum required feerate taking into account the
 * minimum relay feerate and user set minimum transaction feerate
 */
CFeeRate GetRequiredFeeRate(const CWallet& wallet);

/**
 * Estimate the minimum fee rate considering user set parameters
 * and the required fee
 */
MinimumFeeRateResult GetMinimumFeeRate(const CWallet& wallet, const CCoinControl& coin_control);

/**
 * Return the maximum feerate for discarding change.
 */
CFeeRate GetDiscardRate(const CWallet& wallet);
} // namespace wallet

#endif // LATTICA_WALLET_FEES_H
