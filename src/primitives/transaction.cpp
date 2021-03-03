// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2020 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <primitives/transaction.h>

#include <hash.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <arith_uint256.h>
#include <addrman.h>
#include <primitives/block.h>
#include <chainparams.h>
#include <validation.h>

#include <assert.h>

std::string COutPoint::ToString() const
{
    return strprintf("COutPoint(%s, %u)", hash.ToString().substr(0,10), n);
}

CTxIn::CTxIn(COutPoint prevoutIn, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = prevoutIn;
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

CTxIn::CTxIn(uint256 hashPrevTx, uint32_t nOut, CScript scriptSigIn, uint32_t nSequenceIn)
{
    prevout = COutPoint(hashPrevTx, nOut);
    scriptSig = scriptSigIn;
    nSequence = nSequenceIn;
}

std::string CTxIn::ToString() const
{
    std::string str;
    str += "CTxIn(";
    str += prevout.ToString();
    if (prevout.IsNull())
        str += strprintf(", coinbase %s", HexStr(scriptSig));
    else
        str += strprintf(", scriptSig=%s", HexStr(scriptSig).substr(0, 24));
    if (nSequence != SEQUENCE_FINAL)
        str += strprintf(", nSequence=%u", nSequence);
    str += ")";
    return str;
}

CTxOut::CTxOut(const CAmount& nValueIn, CScript scriptPubKeyIn)
{
    nValue = nValueIn;
    scriptPubKey = scriptPubKeyIn;
}

std::string CTxOut::ToString() const
{
    return strprintf("CTxOut(nValue=%d.%08d, scriptPubKey=%s)", nValue / COIN, nValue % COIN, HexStr(scriptPubKey).substr(0, 30));
}

CMutableTransaction::CMutableTransaction() : nVersion(CTransaction::CURRENT_VERSION), nTime(0), nLockTime(0) {}
CMutableTransaction::CMutableTransaction(const CTransaction& tx) : vin(tx.vin), vout(tx.vout), nTime(tx.nTime), nVersion(tx.nVersion), nLockTime(tx.nLockTime) {}

uint256 CMutableTransaction::GetHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeHash() const
{
    return SerializeHash(*this, SER_GETHASH, SERIALIZE_TRANSACTION_NO_WITNESS);
}

uint256 CTransaction::ComputeWitnessHash() const
{
    if (!HasWitness()) {
        return hash;
    }
    return SerializeHash(*this, SER_GETHASH, 0);
}

/* For backward compatibility, the hash is initialized to 0. TODO: remove the need for this default constructor entirely. */

CTransaction::CTransaction() : vin(), vout(), nVersion(CTransaction::CURRENT_VERSION), nLockTime(0), nTime(0), hash{}, m_witness_hash{} {}
CTransaction::CTransaction(const CMutableTransaction& tx) : vin(tx.vin), vout(tx.vout), nVersion(tx.nVersion), nLockTime(tx.nLockTime), nTime(tx.nTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}
CTransaction::CTransaction(CMutableTransaction&& tx) : vin(std::move(tx.vin)), vout(std::move(tx.vout)), nVersion(tx.nVersion), nLockTime(tx.nLockTime), nTime(tx.nTime), hash{ComputeHash()}, m_witness_hash{ComputeWitnessHash()} {}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool CTransaction::GetCoinAge(uint64_t& nCoinAge) const
{
    arith_uint512 bnCentSecond = 0; // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
        return true;

	for (const CTxIn& txin : vin) {
        CTransactionRef txPrev;
        uint256 hashPrevBlock = uint256();
        if (!GetTransaction(txin.prevout.hash, txPrev, Params().GetConsensus(), hashPrevBlock, true))
            continue;
        if (nTime < txPrev->nTime)
            return false; // Transaction timestamp violation
        CBlockIndex* pblockindex = mapBlockIndex[hashPrevBlock];
        CBlock blockPrev;
        CDiskBlockPos blockPos = pblockindex->GetBlockPos();

		if (!ReadBlockFromDisk(blockPrev, blockPos, Params().GetConsensus()))
            return false;

		if (blockPrev.GetBlockTime() + Params().GetConsensus().nStakeMinAge > nTime)
            return false;

		int64_t nValueIn = txPrev->vout[txin.prevout.n].nValue;

		bnCentSecond += arith_uint512(nValueIn) * (nTime - txPrev->nTime) / CENT;
        arith_uint512 bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
        if (gArgs.GetArg("-printcoinage", false))
            printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
        nCoinAge = bnCoinDay.GetLow64();

    }
    return true;
}

CAmount CTransaction::GetValueOut() const
{
    CAmount nValueOut = 0;
    for (const auto& tx_out : vout) {
        if (!MoneyRange(tx_out.nValue) || !MoneyRange(nValueOut + tx_out.nValue))
            throw std::runtime_error(std::string(__func__) + ": value out of range");
        nValueOut += tx_out.nValue;
    }
    assert(MoneyRange(nValueOut));
    return nValueOut;
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool CTransaction::GetCoinAge(uint64_t& nCoinAge) const
{
    arith_uint512 bnCentSecond = 0; // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
        return true;

    //BOOST_FOREACH(const CTxIn& txin, vin)
    for (const CTxIn& txin : vin) {
        // First try finding the previous transaction in database
        CTransactionRef txPrev;
        uint256 hashPrevBlock = uint256();

        /*
            if (!GetTransaction(txin.prevout.hash, txPrev, Params().GetConsensus(), hashPrevBlock, true))
            return error("CheckProofOfStake() : INFO: read txPrev failed");  // previous transaction not in main chain, may occur during initial download        
        */

        // get input tx and block ref containing for block including input tx
        if (!GetTransaction(txin.prevout.hash, txPrev, Params().GetConsensus(), hashPrevBlock, true))
            continue; // previous transaction not in main chain

        if (nTime < txPrev->nTime)
            return false; // Transaction timestamp violation

        // Read block header
        CBlockIndex* pblockindex = mapBlockIndex[hashPrevBlock];
        CBlock blockPrev;
        CDiskBlockPos blockPos = pblockindex->GetBlockPos();

        if (!ReadBlockFromDisk(blockPrev, blockPos, Params().GetConsensus()))
            return false; // unable to read block of previous transaction

        if (blockPrev.GetBlockTime() + Params().GetConsensus().nStakeMinAge > nTime)
            continue; // only count coins meeting min age requirement

        int64_t nValueIn = txPrev->vout[txin.prevout.n].nValue;
        bnCentSecond += arith_uint512(nValueIn) * (nTime - txPrev->nTime) / CENT;

        //if (gArgs.GetArg("-printcoinage", false))
        //    printf("coin age nValueIn=%ld nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
    }

    arith_uint512 bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (gArgs.GetArg("-printcoinage", false))
        printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = bnCoinDay.GetLow64();
    return true;
}

// ppcoin: total coin age spent in transaction, in the unit of coin-days.
// Only those coins meeting minimum age requirement counts. As those
// transactions not in main chain are not currently indexed so we
// might not find out about their coin age. Older transactions are
// guaranteed to be in main chain by sync-checkpoint. This rule is
// introduced to help nodes establish a consistent view of the coin
// age (trust score) of competing branches.
bool CTransaction::GetCoinAge(CTxDB& txdb, uint64& nCoinAge) const
{
    CBigNum bnCentSecond = 0; // coin age in the unit of cent-seconds
    nCoinAge = 0;

    if (IsCoinBase())
        return true;

    BOOST_FOREACH (const CTxIn& txin, vin) {
        // First try finding the previous transaction in database
        CTransaction txPrev;
        CTxIndex txindex;
        if (!txPrev.ReadFromDisk(txdb, txin.prevout, txindex))
            continue; // previous transaction not in main chain
        if (nTime < txPrev.nTime)
            return false; // Transaction timestamp violation

        // Read block header
        CBlock block;
        if (!block.ReadFromDisk(txindex.pos.nFile, txindex.pos.nBlockPos, false))
            return false; // unable to read block of previous transaction
        if (block.GetBlockTime() + nStakeMinAge > nTime)
            continue; // only count coins meeting min age requirement

        int64 nValueIn = txPrev.vout[txin.prevout.n].nValue;
        bnCentSecond += CBigNum(nValueIn) * (nTime - txPrev.nTime) / CENT;

        if (fDebug && GetBoolArg("-printcoinage"))
            printf("coin age nValueIn=%" PRI64d " nTimeDiff=%d bnCentSecond=%s\n", nValueIn, nTime - txPrev.nTime, bnCentSecond.ToString().c_str());
    }

    CBigNum bnCoinDay = bnCentSecond * CENT / COIN / (24 * 60 * 60);
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("coin age bnCoinDay=%s\n", bnCoinDay.ToString().c_str());
    nCoinAge = bnCoinDay.getuint64();
    return true;
}

// ppcoin: total coin age spent in block, in the unit of coin-days.
bool CBlock::GetCoinAge(uint64& nCoinAge) const
{
    nCoinAge = 0;

    CTxDB txdb("r");
    BOOST_FOREACH (const CTransaction& tx, vtx) {
        uint64 nTxCoinAge;
        if (tx.GetCoinAge(txdb, nTxCoinAge))
            nCoinAge += nTxCoinAge;
        else
            return false;
    }

    if (nCoinAge == 0) // block coin age minimum 1 coin-day
        nCoinAge = 1;
    if (fDebug && GetBoolArg("-printcoinage"))
        printf("block coin age total nCoinDays=%" PRI64d "\n", nCoinAge);
    return true;
}

unsigned int CTransaction::GetTotalSize() const
{
    return ::GetSerializeSize(*this, PROTOCOL_VERSION);

}

std::string CTransaction::ToString() const
{
    std::string str;
    str += strprintf("CTransaction(hash=%s, ver=%d, vin.size=%u, vout.size=%u, nTime=%u, nLockTime=%u)\n",
        GetHash().ToString().substr(0, 10),
        nVersion,
        vin.size(),
        vout.size(),
		nTime,
        nLockTime);
    for (const auto& tx_in : vin)
        str += "    " + tx_in.ToString() + "\n";
    for (const auto& tx_in : vin)
        str += "    " + tx_in.scriptWitness.ToString() + "\n";
    for (const auto& tx_out : vout)
        str += "    " + tx_out.ToString() + "\n";
    return str;
}
