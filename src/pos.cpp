// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pos.h>

#include <arith_uint256.h>
#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/moneystr.h>
#include <policy/policy.h>
#include <addrman.h>
//#include <util.h>
#include <txdb.h>
#include <streams.h>
#include <hash.h>
#include <miner.h>
#include <util/time.h>
#include <chainparams.h>
#include <consensus/validation.h>
#include <script/interpreter.h>
#include <index/txindex.h>
#include <validation.h>

// wrapper class for block timestamp/hash pair to enable custom sorting that matches the legacy Cloak codebase
class TimeHash : public std::pair<int64_t, arith_uint256>
{
public:
    TimeHash(int64_t time, arith_uint256 hash)
    {
        this->first = time;
        this->second = hash;
    }

    friend inline bool operator<(const TimeHash& a, const TimeHash& b)
    {
        return a.first < b.first || (a.first == b.first && a.second < b.second);
    }       
};

// Hashed
typedef std::vector<TimeHash> TimestampedHashes;

std::set<std::pair<COutPoint, unsigned int> > setStakeSeen;
std::set<std::pair<COutPoint, unsigned int> > setStakeSeenOrphan; // for pos v1
std::map<uint256, uint256> mapProofOfStake;

// std::map<uint256, CBlockIndex*> m_block_index;
// 
// Hard checkpoints of stake modifiers to ensure they are deterministic
static std::map<int, unsigned int> mapStakeModifierCheckpoints = {{0, 0xfd11f4e7u}};

// miner's coin stake reward based on nBits and coin age spent (coin-days)
// simple algorithm, not depend on the diff
int64_t GetProofOfStakeReward(int64_t nCoinAge, unsigned int nBits, unsigned int nTime, int nHeight)
{
    int64_t nRewardCoinYear;
    nRewardCoinYear = MAX_MINT_PROOF_OF_STAKE;
    int64_t nSubsidy = nCoinAge * nRewardCoinYear / 365;

    //if (gArgs.GetBoolArg("-printcreation", false))
     //   LogPrint("GetProofOfStakeReward(): create=%s nCoinAge=%u nBits=%d\n", FormatMoney(nSubsidy).c_str(), nCoinAge, nBits);

    return nSubsidy;
}

// Get selection interval section (in seconds)
static int64_t GetStakeModifierSelectionIntervalSection(int nSection)
{
    assert(nSection >= 0 && nSection < 64);
    unsigned int nModifierInterval = Params().GetConsensus().nStakeModifierInterval;
    int64_t a = nModifierInterval * 63 / (63 + ((63 - nSection) * (MODIFIER_INTERVAL_RATIO - 1)));
    return a;
}

// Get stake modifier selection interval (in seconds)
static int64_t GetStakeModifierSelectionInterval()
{
    int64_t nSelectionInterval = 0;
    for (int nSection = 0; nSection < 64; nSection++)
    {
        nSelectionInterval += GetStakeModifierSelectionIntervalSection(nSection);
    }
    return nSelectionInterval;
}

// Get the last stake modifier and its generation time from a given block
static bool GetLastStakeModifier(const CBlockIndex* pindex, uint64_t& nStakeModifier, int64_t& nModifierTime)
{
    if (!pindex)
        return error("GetLastStakeModifier: null pindex");
    while (pindex && pindex->pprev && !pindex->GeneratedStakeModifier())
        pindex = pindex->pprev;
    if (!pindex->GeneratedStakeModifier())
        return error("GetLastStakeModifier: no generation at genesis block");
    nStakeModifier = pindex->nStakeModifier;
    nModifierTime = pindex->GetBlockTime();
    return true;
}

// select a block from the candidate blocks in vSortedByTimestamp, excluding
// already selected blocks in vSelectedBlocks, and with timestamp up to
// nSelectionIntervalStop.
static bool SelectBlockFromCandidates(
    TimestampedHashes& vSortedByTimestamp,
    std::map<uint256, const CBlockIndex*>& mapSelectedBlocks,
    int64_t nSelectionIntervalStop, uint64_t nStakeModifierPrev,
    const CBlockIndex** pindexSelected)
{
    bool fSelected = false;
    arith_uint256 hashBest = arith_uint256();

    *pindexSelected = (const CBlockIndex*)0;

    std::vector<const CBlockIndex*> indexes;
    for (const std::pair<int64_t, arith_uint256>& item : vSortedByTimestamp) 
    {
        //idx++;
        if (!g_chainman.BlockIndex().count(ArithToUint256(item.second)))
            return error("SelectBlockFromCandidates: failed to find block index for candidate block %s", item.second.ToString().c_str());
        const CBlockIndex* pindex = g_chainman.BlockIndex()[ArithToUint256(item.second)];
        indexes.push_back(pindex);

        if (fSelected && pindex->GetBlockTime() > nSelectionIntervalStop)
            break;
        if (mapSelectedBlocks.count(pindex->GetBlockHash()) > 0)
            continue;
        // compute the selection hash by hashing its proof-hash and the
        // previous proof-of-stake modifier
        uint256 hashProof = pindex->IsProofOfStake() ? ArithToUint256(pindex->hashProofOfStake) : pindex->GetBlockHash();
        std::string strHashProof = hashProof.GetHex();
        CDataStream ss(SER_GETHASH, 0);
        ss << hashProof << nStakeModifierPrev;        
        arith_uint256 hashSelection = UintToArith256(Hash(ss));
        std::string strHashSelection = hashSelection.GetHex();
        // the selection hash is divided by 2**32 so that proof-of-stake block
        // is always favored over proof-of-work block. this is to preserve
        // the energy efficiency property
        if (pindex->IsProofOfStake())
            hashSelection >>= 32;
                
        if (fSelected && hashSelection < hashBest)
        {
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*)pindex;
        }
        else if (!fSelected)
        {
            fSelected = true;
            hashBest = hashSelection;
            *pindexSelected = (const CBlockIndex*)pindex;
        }
    }
    if (gArgs.GetBoolArg("-printstakemodifier", false))
        LogPrintf("SelectBlockFromCandidates: selection hash=%s\n", hashBest.ToString().c_str());
    return fSelected;
}

// Stake Modifier (hash modifier of proof-of-stake):
// The purpose of stake modifier is to prevent a txout (coin) owner from
// computing future proof-of-stake generated by this txout at the time
// of transaction confirmation. To meet kernel protocol, the txout
// must hash with a future stake modifier to generate the proof.
// Stake modifier consists of bits each of which is contributed from a
// selected block of a given block group in the past.
// The selection of a block is based on a hash of the block's proof-hash and
// the previous stake modifier.
// Stake modifier is recomputed at a fixed time interval instead of every 
// block. This is to make it difficult for an attacker to gain control of
// additional bits in the stake modifier, even after generating a chain of
// blocks.
bool ComputeNextStakeModifier(const CBlockIndex* pindexPrev, uint64_t& nStakeModifier, bool& fGeneratedStakeModifier)
{
    nStakeModifier = 0;
    fGeneratedStakeModifier = false;
    if (!pindexPrev)
    {
        fGeneratedStakeModifier = true;
        return true;  // genesis block's modifier is 0
    }
    // First find current stake modifier and its generation block time
    // if it's not old enough, return the same stake modifier
    int64_t nModifierTime = 0;
    if (!GetLastStakeModifier(pindexPrev, nStakeModifier, nModifierTime))
        return error("ComputeNextStakeModifier: unable to get last modifier");
    
    LogPrint(BCLog::SELECTCOINS, "ComputeNextStakeModifier: prev modifier=0x%016x time=%s\n", nStakeModifier, DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nModifierTime).c_str());

    unsigned int nModifierInterval = Params().GetConsensus().nStakeModifierInterval;
    
    if (nModifierTime / nModifierInterval >= pindexPrev->GetBlockTime() / nModifierInterval)
        return true;

    // Sort candidate blocks by timestamp
    TimestampedHashes vSortedByTimestamp;
    vSortedByTimestamp.reserve(64 * nModifierInterval / Params().GetConsensus().nStakeTargetSpacing);
    int64_t nSelectionInterval = GetStakeModifierSelectionInterval();
    int64_t nSelectionIntervalStart = (pindexPrev->GetBlockTime() / nModifierInterval) * nModifierInterval - nSelectionInterval;
    const CBlockIndex* pindex = pindexPrev;
    int index = 0;
    while (pindex && pindex->GetBlockTime() >= nSelectionIntervalStart)
    {
        //LogPrintf("Adding %d height = %d hash = %s\n", index, pindex->nHeight, pindex->GetBlockHash().GetHex().c_str());
        uint256 hash = pindex->GetBlockHash();
        vSortedByTimestamp.push_back(TimeHash(pindex->GetBlockTime(), UintToArith256(hash)));
        pindex = pindex->pprev;
        index++;
    }
    int nHeightFirstCandidate = pindex ? (pindex->nHeight + 1) : 0;

    reverse(vSortedByTimestamp.begin(), vSortedByTimestamp.end());   
    // custom sort the hashed timestamps
    sort(vSortedByTimestamp.begin(), vSortedByTimestamp.end());

    // Select 64 blocks from candidate blocks to generate stake modifier
    uint64_t nStakeModifierNew = 0;
    int64_t nSelectionIntervalStop = nSelectionIntervalStart;
    std::map<uint256, const CBlockIndex*> mapSelectedBlocks;
    for (int nRound = 0; nRound < std::min(64, (int)vSortedByTimestamp.size()); nRound++)
    { 
        // add an interval section to the current selection round
        nSelectionIntervalStop += GetStakeModifierSelectionIntervalSection(nRound);
        // select a block from the candidates of current round
        if (!SelectBlockFromCandidates(vSortedByTimestamp, mapSelectedBlocks, nSelectionIntervalStop, nStakeModifier, &pindex))
            return error("ComputeNextStakeModifier: unable to select block at round %d", nRound);

        // write the entropy bit of the selected block
        nStakeModifierNew |= (((uint64_t)pindex->GetStakeEntropyBit()) << nRound);
        // add the selected block from candidates to selected list
        mapSelectedBlocks.insert(std::make_pair(pindex->GetBlockHash(), pindex));
        if (gArgs.GetBoolArg("-printstakemodifier", false))
            LogPrintf("ComputeNextStakeModifier: selected round %d stop=%s height=%d bit=%d sm=%lu\n",
                nRound, DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nSelectionIntervalStop).c_str(), pindex->nHeight, pindex->GetStakeEntropyBit(), nStakeModifierNew);
    }
    // LogPrintf(" **** END ****\n");
    // Print selection map for visualization of the selected blocks
    if (gArgs.GetBoolArg("-printstakemodifier", false))
    {
        std::string strSelectionMap = "";
        // '-' indicates proof-of-work blocks not selected
        strSelectionMap.insert(0, pindexPrev->nHeight - nHeightFirstCandidate + 1, '-');
        pindex = pindexPrev;
        while (pindex && pindex->nHeight >= nHeightFirstCandidate)
        {
            // '=' indicates proof-of-stake blocks not selected
            if (pindex->IsProofOfStake())
                strSelectionMap.replace(pindex->nHeight - nHeightFirstCandidate, 1, "=");
            pindex = pindex->pprev;
        }
        
        for(const std::pair<uint256, const CBlockIndex*>& item : mapSelectedBlocks)
        {
            // 'S' indicates selected proof-of-stake blocks
            // 'W' indicates selected proof-of-work blocks
            strSelectionMap.replace(item.second->nHeight - nHeightFirstCandidate, 1, item.second->IsProofOfStake() ? "S" : "W");
        }
        LogPrint(BCLog::SELECTCOINS, "ComputeNextStakeModifier: selection height [%d, %d] map %s\n", nHeightFirstCandidate, pindexPrev->nHeight, strSelectionMap.c_str());
    }
    if (gArgs.GetBoolArg("-printstakemodifier", false))
    {
        LogPrint(BCLog::SELECTCOINS, "ComputeNextStakeModifier: new modifier=0x%016x time=%s\n", nStakeModifierNew, DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexPrev->GetBlockTime()).c_str());
    }

    nStakeModifier = nStakeModifierNew;
    fGeneratedStakeModifier = true;
    return true;
}

// Get stake modifier checksum
unsigned int GetStakeModifierChecksum(const CBlockIndex* pindex)
{
    assert(pindex->pprev || pindex->GetBlockHash() == Params().GenesisBlock().GetHash());
    // Hash previous checksum with flags, hashProofOfStake and nStakeModifier
    CDataStream ss(SER_GETHASH, 0);
    if (pindex->pprev)
        ss << pindex->pprev->nStakeModifierChecksum;
    ss << pindex->nFlags << pindex->hashProofOfStake << pindex->nStakeModifier;
    arith_uint256 hashChecksum = UintToArith256(Hash(ss));
    hashChecksum >>= (256 - 32);
    if (gArgs.GetBoolArg("-printstakemodifier", false))
        LogPrint(BCLog::SELECTCOINS, "stake checksum : 0x % 016x", ArithToUint256(hashChecksum).GetUint64(0));
    return hashChecksum.GetLow64();
}

// The stake modifier used to hash for a stake kernel is chosen as the stake
// modifier about a selection interval later than the coin generating the kernel
static bool GetKernelStakeModifier(uint256 hashBlockFrom, uint64_t& nStakeModifier, int& nStakeModifierHeight, int64_t& nStakeModifierTime, bool fPrintProofOfStake)
{
    nStakeModifier = 0;
    if (!g_chainman.BlockIndex().count(hashBlockFrom))
        return error("GetKernelStakeModifier() : block not indexed");
    const CBlockIndex* pindexFrom = g_chainman.BlockIndex()[hashBlockFrom];
    nStakeModifierHeight = pindexFrom->nHeight;
    nStakeModifierTime = pindexFrom->GetBlockTime();
    int64_t nStakeModifierSelectionInterval = GetStakeModifierSelectionInterval();
    const CBlockIndex* pindex = pindexFrom;

    // loop to find the stake modifier later by a selection interval
    while (nStakeModifierTime < pindexFrom->GetBlockTime() + nStakeModifierSelectionInterval)
    {
        if (!::ChainActive().Next(pindex))
        {   // reached best block; may happen if node is behind on block chain
            if (fPrintProofOfStake || (pindex->GetBlockTime() + Params().GetConsensus().nStakeMinAge - nStakeModifierSelectionInterval > GetAdjustedTime()))
                return error("GetKernelStakeModifier() : reached best block %s at height %d from block %s",
                    pindex->GetBlockHash().ToString().c_str(), pindex->nHeight, hashBlockFrom.ToString().c_str());
            else
            {
                    LogPrint(BCLog::ALL, ">> nStakeModifierTime = %d, pindexFrom->GetBlockTime() = %d, nStakeModifierSelectionInterval = %d\n",
                        nStakeModifierTime, pindexFrom->GetBlockTime(), nStakeModifierSelectionInterval);

                return false;
            }
        }
        pindex = ::ChainActive().Next(pindex);
        if (pindex->GeneratedStakeModifier())
        {            
            nStakeModifierHeight = pindex->nHeight;
            nStakeModifierTime = pindex->GetBlockTime();
        }
    }
    nStakeModifier = pindex->nStakeModifier;
    return true;
}

// Check stake modifier hard checkpoints
bool CheckStakeModifierCheckpoints(int nHeight, unsigned int nStakeModifierChecksum)
{
    if (Params().NetworkIDString() == "test") return true; // Testnet has no checkpoints
    if (mapStakeModifierCheckpoints.count(nHeight))
    {
        return nStakeModifierChecksum == mapStakeModifierCheckpoints[nHeight];
    }
    return true;
}

// ppcoin kernel protocol
// coinstake must meet hash target according to the protocol:
// kernel (input 0) must meet the formula
//     hash(nStakeModifier + txPrev.block.nTime + txPrev.offset + txPrev.nTime + txPrev.vout.n + nTime) < bnTarget * nCoinDayWeight
// this ensures that the chance of getting a coinstake is proportional to the
// amount of coin age one owns.
// The reason this hash is chosen is the following:
//   nStakeModifier: 
//       (v0.3) scrambles computation to make it very difficult to precompute
//              future proof-of-stake at the time of the coin's confirmation
//       (v0.2) nBits (deprecated): encodes all past block timestamps
//   txPrev.block.nTime: prevent nodes from guessing a good timestamp to
//                       generate transaction for future advantage
//   txPrev.offset: offset of txPrev inside block, to reduce the chance of 
//                  nodes generating coinstake at the same time
//   txPrev.nTime: reduce the chance of nodes generating coinstake at the same
//                 time
//   txPrev.vout.n: output number of txPrev, to reduce the chance of nodes
//                  generating coinstake at the same time
//   block/tx hash should not be used here as they can be generated in vast
//   quantities so as to generate blocks faster, degrading the system back into
//   a proof-of-work situation.
//
bool CheckStakeKernelHash(unsigned int nBits, CBlockIndex* pindexPrev, unsigned int nTxPrevOffset, const CTransactionRef txPrev, const COutPoint& prevout, unsigned int nTimeTx, uint256& hashProofOfStake,  bool fPrintProofOfStake)
{
    if (nTimeTx < txPrev->nTime)  // Transaction timestamp violation
        return error("CheckStakeKernelHash() : nTime violation");

    unsigned int nTimeBlockFrom = pindexPrev->GetBlockTime();
    if (nTimeBlockFrom + Params().GetConsensus().nStakeMinAge > nTimeTx) // Min age requirement
        return error("CheckStakeKernelHash() : min age violation");

    arith_uint256 bnTargetPerCoinDay;
    bnTargetPerCoinDay.SetCompact(nBits);
    int64_t nValueIn = txPrev->vout[prevout.n].nValue;

    // v0.3 protocol kernel hash weight starts from 0 at the min age
    // this change increases active coins participating the hash and helps
    // to secure the network when proof-of-stake difficulty is low
    int64_t nTimeWeight = std::min((int64_t)nTimeTx - txPrev->nTime, (int64_t)Params().GetConsensus().nStakeMaxAge) - Params().GetConsensus().nStakeMinAge;
    arith_uint512 bnCoinDayWeight = arith_uint512(nValueIn) * nTimeWeight / COIN / (24 * 60 * 60);

    // We need to convert to uint512 to prevent overflow when multiplying by 1st block coins
    std::string bnTargetPerCoinDayHex = bnTargetPerCoinDay.GetHex();
    arith_uint512 targetProofOfStake512(bnTargetPerCoinDayHex);
    targetProofOfStake512 *= bnCoinDayWeight;
    
    // Calculate hash
    CDataStream ss(SER_GETHASH, 0);
    uint64_t nStakeModifier = 0;
    int nStakeModifierHeight = 0;
    int64_t nStakeModifierTime = 0;

    if (!GetKernelStakeModifier(pindexPrev->GetBlockHash(), nStakeModifier, nStakeModifierHeight, nStakeModifierTime, fPrintProofOfStake))
    {
        LogPrint(BCLog::ALL, ">>> CheckStakeKernelHash: GetKernelStakeModifier return false\n");
        return false; 
    }

    if (fPrintProofOfStake)
        LogPrint(BCLog::ALL, ">>> CheckStakeKernelHash: passed GetKernelStakeModifier\n");

    // create PoS hash
    ss << nStakeModifier;
    ss << nTimeBlockFrom << nTxPrevOffset << txPrev->nTime << prevout.n << nTimeTx;
    hashProofOfStake = Hash(ss);
    if (fPrintProofOfStake)
    {
        LogPrint(BCLog::ALL, "CheckStakeKernelHash() : using modifier 0x%d at height=%d timestamp=%s for block from height=%d timestamp=%s\n",
            nStakeModifier, nStakeModifierHeight,
            DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nStakeModifierTime).c_str(),
            pindexPrev->nHeight,
            DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexPrev->GetBlockTime()).c_str());
        LogPrint(BCLog::ALL, "CheckStakeKernelHash() : check protocol=%s modifier=0x%d nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
            "0.3",
            nStakeModifier,
            nTimeBlockFrom, nTxPrevOffset, txPrev->nTime, prevout.n, nTimeTx,
            hashProofOfStake.ToString().c_str());
    }
    
    // We need to convert type so it can be compared to target
    arith_uint512 hashProofOfStake512(hashProofOfStake.GetHex());
    
    // Now check if proof-of-stake hash meets target protocol
    if (hashProofOfStake512 > targetProofOfStake512)
    {
        LogPrint(BCLog::ALL, ">>> bnCoinDayWeight = %s, bnTargetPerCoinDay=%s\n", bnCoinDayWeight.ToString().c_str(), bnTargetPerCoinDay.ToString().c_str());
        LogPrint(BCLog::ALL, ">>> CheckStakeKernelHash - hashProofOfStake too much\n");
        return false;
    }

    if (fPrintProofOfStake)
    {
        LogPrint(BCLog::ALL, "CheckStakeKernelHash() : using modifier 0x%d at height=%d timestamp=%s for block from height=%d timestamp=%s\n",
            nStakeModifier, nStakeModifierHeight,
            DateTimeStrFormat("%Y-%m-%d %H:%M:%S", nStakeModifierTime).c_str(),
            g_chainman.BlockIndex()[pindexPrev->GetBlockHash()]->nHeight,
            DateTimeStrFormat("%Y-%m-%d %H:%M:%S", pindexPrev->GetBlockTime()).c_str());

        LogPrint(BCLog::ALL, "CheckStakeKernelHash() : pass protocol=%s modifier=0x%d nTimeBlockFrom=%u nTxPrevOffset=%u nTimeTxPrev=%u nPrevout=%u nTimeTx=%u hashProof=%s\n",
            "0.3",
            nStakeModifier,
            nTimeBlockFrom, nTxPrevOffset, txPrev->nTime, prevout.n, nTimeTx,
            hashProofOfStake.ToString().c_str());
    }
    return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool GetCoinAgeBlock(uint64_t& nCoinAge, CBlock block)
{
    nCoinAge = 0;
    for (const CTransactionRef& tx : block.vtx)
    {
        uint64_t nTxCoinAge;
        if (GetCoinAge(nTxCoinAge, tx))
            nCoinAge += nTxCoinAge;
        else
            return false;
    }

    if (nCoinAge == 0) // block coin age minimum 1 coin-day
        nCoinAge = 1;

    //if (fDebug && GetBoolArg("-printcoinage"))
    //    printf("block coin age total nCoinDays=%" PRI64d "\n", nCoinAge);
    return true;
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are 
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool GetCoinAge(uint64_t& nCoinAge, CTransactionRef tx) 
{
    arith_uint512 bnCentSecond = 0;  // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (tx->IsCoinBase())
        return true;

    //BOOST_FOREACH(const CTxIn& txin, vin)
    for (const CTxIn& txin : tx->vin) {
        // First try finding the previous transaction in database
        CTransactionRef txPrev;
        uint256 hashPrevBlock = uint256();

        /*
            if (!GetTransaction(txin.prevout.hash, txPrev, Params().GetConsensus(), hashPrevBlock, true))
            return error("CheckProofOfStake() : INFO: read txPrev failed");  // previous transaction not in main chain, may occur during initial download
        */

        // get input tx and block ref containing for block including input tx
        txPrev = GetTransaction(nullptr, nullptr, txin.prevout.hash, Params().GetConsensus(), hashPrevBlock);
        if (!txPrev)
            continue;  // previous transaction not in main chain

        if (tx->nTime < txPrev->nTime)
            return false;  // Transaction timestamp violation

        // Read block header
        CBlockIndex* pblockindex = g_chainman.BlockIndex()[hashPrevBlock];
        CBlock blockPrev;
        FlatFilePos blockPos = pblockindex->GetBlockPos();

        if (!ReadBlockFromDisk(blockPrev, blockPos, Params().GetConsensus()))
            return false; // unable to read block of previous transaction

        if (blockPrev.GetBlockTime() + Params().GetConsensus().nStakeMinAge > tx->nTime)
            continue; // only count coins meeting min age requirement

        int64_t nValueIn = txPrev->vout[txin.prevout.n].nValue;
        bnCentSecond += arith_uint512(nValueIn) * (tx->nTime - txPrev->nTime) / CENT;

        //if (gArgs.GetArg("-printcoinage", false))
        //    printf("coin age nValueIn=%ld nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
    }

    arith_uint512 bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (gArgs.GetArg("-printcoinage", false))
        printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = bnCoinDay.GetLow64();
    return true;
}

// Check kernel hash target and coinstake signature
bool CheckProofOfStake(const CTransactionRef tx, unsigned int nBits, uint256& hashProofOfStake, std::vector<CScriptCheck> *pvChecks, bool fCHeckSignature)
{
    if (!tx->IsCoinStake())
        return error("CheckProofOfStake() : called on non-coinstake %s", tx->GetHash().ToString().c_str());

    // Kernel (input 0) must match the stake hash target per coin age (nBits)
    const CTxIn& txin = tx->vin[0];

    // First try finding the previous transaction in database
    CTransactionRef txPrev;
    uint256 hashPrevBlock = uint256();

    // get input tx and block ref containing for block including input tx
    // ppcoin: if (!GetTransaction(txin.prevout.hash, txPrev, Params().GetConsensus(), hashPrevBlock, true))
    txPrev = GetTransaction(nullptr, nullptr, txin.prevout.hash, Params().GetConsensus(), hashPrevBlock);
    if (!txPrev)
        return error("CheckProofOfStake() : INFO: read txPrev failed");  // previous transaction not in main chain, may occur during initial download
        
    CCoinsViewCache inputs(&::ChainstateActive().CoinsTip());   //  previously inputs(pcoinsTip.get())

    std::string hashBlockPrev = hashPrevBlock.GetHex();
    std::string hashPrevTxIn = txin.prevout.hash.GetHex();
    
    if (fCHeckSignature)
    {
        PrecomputedTransactionData txdata(*tx);
        const COutPoint &prevout = tx->vin[0].prevout;
        const CTxOut& coinsOutput = inputs.AccessCoin(prevout).out;
        //assert(coins);

        // Verify signature
        CScriptCheck check(coinsOutput, *tx, 0, SCRIPT_VERIFY_NONE, false, &txdata);
        if (pvChecks) {
            pvChecks->push_back(CScriptCheck());
            check.swap(pvChecks->back());
        }
        else if (!check())
            return error("CheckProofOfStake() : script-verify-failed %s", ScriptErrorString(check.GetScriptError()));
    }

    CBlockIndex* pblockindex = g_chainman.BlockIndex()[hashPrevBlock];
    CBlock blockPrev;
    FlatFilePos blockPos = pblockindex->GetBlockPos();

    if (!ReadBlockFromDisk(blockPrev, blockPos, Params().GetConsensus()))
        return error("CheckProofOfStake() : read block failed");

    int prevTxOffsetInBlock = blockPos.nPos + GetSerializeSize(CBlock(), CLIENT_VERSION) - (2 * GetSizeOfCompactSize(0)) + GetSizeOfCompactSize(blockPrev.vtx.size());
    for (auto& i : blockPrev.vtx) {
        if (i->GetHash() == txPrev->GetHash())
            break;
        prevTxOffsetInBlock += GetSerializeSize(i, CLIENT_VERSION);
    }

    if (!CheckStakeKernelHash(nBits, pblockindex, prevTxOffsetInBlock - blockPos.nPos, txPrev, txin.prevout, tx->nTime, hashProofOfStake))
        return error("CheckProofOfStake() : INFO: check kernel failed on coinstake %s, hashProof=%s", tx->GetHash().ToString().c_str(), hashProofOfStake.ToString().c_str()); // may occur during initial download or if behind on block chain sync

    return true;
}

