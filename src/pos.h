#ifndef BITCOIN_POS_H
#define BITCOIN_POS_H

#include "consensus/params.h"
#include "primitives/transaction.h"
#include <stdint.h>

class CBlockHeader;
class CBlock;
class CBlockIndex;
class CValidationState;
class uint256;
class CScriptCheck;

// Check whether stake kernel meets hash target
// Sets hashProofOfStake on success return
bool CheckStakeKernelHash(unsigned int nBits, CBlockIndex* pindexPrev, unsigned int nTxPrevOffset, const CTransactionRef txPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256& hashProofOfStake, bool fPrintProofOfStake = false);

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(const CTransactionRef tx, unsigned int nBits, uint256& hashProofOfStake, std::vector<CScriptCheck> *pvChecks = nullptr, bool fCHeckSignature=true);

bool ComputeNextStakeModifier(const CBlockIndex* pindexPrev, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier);

bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum);

bool GetCoinAgeBlock(const CBlock& block, uint64_t& nCoinAge);

bool GetCoinAgeTX(const CTransactionRef& tx, uint64_t& nCoinAge);

unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex);

/* Proof of Stake constants */
extern std::set<std::pair<COutPoint, unsigned int> > setStakeSeen;
extern std::map<uint256, uint256> mapProofOfStake;
//extern std::map<int, unsigned int> mapStakeModifierCheckpoints;

#endif // BITCOIN_POS_H