// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/block.h>

#include <hash.h>
#include <tinyformat.h>

uint256 CBlockHeader::GetHash() const
{
    uint256 thash = HashX13(BEGIN(nVersion), END(nNonce));
    return thash;
    //return SerializeHash(*this);
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(uint64_t& nCoinAge) const
{
    nCoinAge = 0;
    for (const CTransactionRef tx : vtx) {
        {
            uint64_t nTxCoinAge;
            if (tx->GetCoinAge(nTxCoinAge))
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

std::string CBlock::ToString() const
{
    std::stringstream s;
    s << strprintf("CBlock(hash=%s, ver=0x%08x, hashPrevBlock=%s, hashMerkleRoot=%s, nTime=%u, nBits=%08x, nNonce=%u, vtx=%u)\n",
        GetHash().ToString(),
        nVersion,
        hashPrevBlock.ToString(),
        hashMerkleRoot.ToString(),
        nTime, nBits, nNonce,
        vtx.size());
    for (const auto& tx : vtx) {
        s << "  " << tx->ToString() << "\n";
    }
    return s.str();
}
