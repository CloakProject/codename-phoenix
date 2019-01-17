// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>

/*
 
unsigned int GetNextTargetRequired(const CBlockIndex* pindexLast, bool fProofOfStake) 
{
    //if(fTestNet)
	//return bnProofOfWorkLimitTestNet.GetCompact();
	
    CBigNum bnTargetLimit = bnProofOfWorkLimit;

    if(fProofOfStake)
    {
        // Proof-of-Stake blocks has own target limit since nVersion=3 supermajority on mainNet and always on testNet
        bnTargetLimit = bnProofOfStakeLimit;
    }

    if (pindexLast == NULL)
        return bnTargetLimit.GetCompact(); // genesis block

    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == NULL)
        return bnTargetLimit.GetCompact(); // second block

    int64 nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();
	if(nActualSpacing < 0)
	{
		// printf(">> nActualSpacing = %"PRI64d" corrected to 1.\n", nActualSpacing);
		nActualSpacing = 1;
	}
	else if(nActualSpacing > nTargetTimespan)
	{
		// printf(">> nActualSpacing = %"PRI64d" corrected to nTargetTimespan (900).\n", nActualSpacing);
		nActualSpacing = nTargetTimespan;
	}

    // ppcoin: target change every block
    // ppcoin: retarget with exponential moving toward target spacing
    CBigNum bnNew;
    bnNew.SetCompact(pindexPrev->nBits);

    int64 nTargetSpacing = fProofOfStake? nStakeTargetSpacing : min(nTargetSpacingWorkMax, (int64) nStakeTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight));
    int64 nInterval = nTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);
	
    if (bnNew > bnTargetLimit)
    bnNew = bnTargetLimit;

    return bnNew.GetCompact();
    }
 */

 // ppcoin: find last block index up to pindex
const CBlockIndex* GetLastBlockIndex(const CBlockIndex* pindex, bool fProofOfStake)
{
    while (pindex && pindex->pprev && (pindex->IsProofOfStake() != fProofOfStake))
        pindex = pindex->pprev;
    return pindex;
}


unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, bool fProofOfStake, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = params.nProofOfWorkLimit.GetCompact();

    if (fProofOfStake)
    {
        // Proof-of-Stake blocks has own target limit since nVersion=3 supermajority on mainNet and always on testNet
        nProofOfWorkLimit = params.nProofOfStakeLimit.GetCompact();
    }

    if (pindexLast == nullptr)
        return nProofOfWorkLimit; // genesis block
    
    const CBlockIndex* pindexPrev = GetLastBlockIndex(pindexLast, fProofOfStake);
    if (pindexPrev->pprev == nullptr)
        return nProofOfWorkLimit; // first block
    const CBlockIndex* pindexPrevPrev = GetLastBlockIndex(pindexPrev->pprev, fProofOfStake);
    if (pindexPrevPrev->pprev == nullptr)
        return nProofOfWorkLimit; // second block

    return CalculateNextWorkRequired(pindexLast, pindexPrev, pindexPrevPrev, fProofOfStake, params);
}

/*
unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock, const Consensus::Params& params)
{
    assert(pindexLast != nullptr);
    unsigned int nProofOfWorkLimit = params.nProofOfWorkLimit.GetCompact();

    // Only change once per difficulty adjustment interval
    if ((pindexLast->nHeight+1) % params.DifficultyAdjustmentInterval() != 0)
    {
        if (params.fPowAllowMinDifficultyBlocks)
        {
            // Special difficulty rule for testnet:
            // If the new block's timestamp is more than 2* 10 minutes
            // then allow mining of a min-difficulty block.
            if (pblock->GetBlockTime() > pindexLast->GetBlockTime() + params.nPowTargetSpacing*2)
                return nProofOfWorkLimit;
            else
            {
                // Return the last non-special-min-difficulty-rules-block
                const CBlockIndex* pindex = pindexLast;
                while (pindex->pprev && pindex->nHeight % params.DifficultyAdjustmentInterval() != 0 && pindex->nBits == nProofOfWorkLimit)
                    pindex = pindex->pprev;
                return pindex->nBits;
            }
        }
        return pindexLast->nBits;
    }

    // Go back by what we want to be 14 days worth of blocks
    int nHeightFirst = pindexLast->nHeight - (params.DifficultyAdjustmentInterval()-1);
    assert(nHeightFirst >= 0);
    const CBlockIndex* pindexFirst = pindexLast->GetAncestor(nHeightFirst);
    assert(pindexFirst);

    return CalculateNextWorkRequired(pindexLast, pindexFirst->GetBlockTime(), params);
}
*/

unsigned int CalculateNextWorkRequired(const CBlockIndex* pindexLast, const CBlockIndex* pindexPrev, const CBlockIndex* pindexPrevPrev, bool fProofOfStake, const Consensus::Params& params)
{
    int64_t nActualSpacing = pindexPrev->GetBlockTime() - pindexPrevPrev->GetBlockTime();
    if (nActualSpacing < 0)
    {
        // printf(">> nActualSpacing = %"PRI64d" corrected to 1.\n", nActualSpacing);
        nActualSpacing = 1;
    }
    else if (nActualSpacing > params.nPowTargetTimespan)
    {
        // printf(">> nActualSpacing = %"PRI64d" corrected to nTargetTimespan (900).\n", nActualSpacing);
        nActualSpacing = params.nPowTargetTimespan;
    }

    arith_uint256 bnNew = arith_uint256(pindexPrev->nBits);
    int64_t nTargetSpacing = fProofOfStake ? params.nStakeTargetSpacing : std::min(params.nPowTargetSpacing, (int64_t)params.nStakeTargetSpacing * (1 + pindexLast->nHeight - pindexPrev->nHeight));
    int64_t nInterval = params.nPowTargetTimespan / nTargetSpacing;
    bnNew *= ((nInterval - 1) * nTargetSpacing + nActualSpacing + nActualSpacing);
    bnNew /= ((nInterval + 1) * nTargetSpacing);

    if (bnNew > params.nProofOfWorkLimit)
        bnNew = params.nProofOfWorkLimit;

    return bnNew.GetLow64();

    /*
    if (params.fPowNoRetargeting)
        return pindexLast->nBits;
    // Limit adjustment step
    int64_t nActualTimespan = pindexLast->GetBlockTime() - nFirstBlockTime;
    if (nActualTimespan < params.nPowTargetTimespan/4)
        nActualTimespan = params.nPowTargetTimespan/4;
    if (nActualTimespan > params.nPowTargetTimespan*4)
        nActualTimespan = params.nPowTargetTimespan*4;

    // Retarget
    const arith_uint256 bnPowLimit = params.nProofOfWorkLimit;
    arith_uint256 bnNew;
    bnNew.SetCompact(pindexLast->nBits);
    bnNew *= nActualTimespan;
    bnNew /= params.nPowTargetTimespan;

    if (bnNew > bnPowLimit)
        bnNew = bnPowLimit;

    return bnNew.GetCompact();
    */
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
