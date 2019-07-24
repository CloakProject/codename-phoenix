// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

// ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(true &&  "GetNextWorkRequired deprecated for Cloak- use GetNextTargetRequired");
    return 0;
}

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, int64_t nFirstBlockTime, const Consensus::Params& params)
{
    assert(true && "CalculateNextWorkRequired deprecated for Cloak- use GetNextTargetRequired");
    return 0;
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);
    
    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > params.nProofOfWorkLimit)
        return false;

    // Check proof of work matches claimed amount
    // NOTE: original cloak genesis block doesn't meet proof of work requirements. check and exclude it.
    if (UintToArith256(hash) > bnTarget && hash != params.hashGenesisBlock)
        return false;

    return true;
}
