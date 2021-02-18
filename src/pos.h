#pragma once
#ifndef BITCOIN_POS_H
#define BITCOIN_POS_H

#include "consensus/params.h"
#include "primitives/transaction.h"

#include <stdint.h>

class CBlockHeader;
class CBlockIndex;
class uint256;

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(const CTransaction& tx, unsigned int nBits, uint256& hashProofOfStake);

#endif // BITCOIN_POS_H 