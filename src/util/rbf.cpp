// Copyright (c) 2026 Kristian Pilatovich
// See COPYING for license.

#include <util/rbf.h>

#include <primitives/transaction.h>

#include <vector>

bool SignalsOptInRBF(const CTransaction &tx)
{
    for (const CTxIn &txin : tx.vin) {
        if (txin.nSequence <= MAX_BIP125_RBF_SEQUENCE) {
            return true;
        }
    }
    return false;
}
