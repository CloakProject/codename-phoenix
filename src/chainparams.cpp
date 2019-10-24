// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2018 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <consensus/merkle.h>

#include <tinyformat.h>
#include <util.h>
#include <utilstrencodings.h>

#include <assert.h>

#include <chainparamsseeds.h>

static CBlock CreateGenesisBlock(const char* pszTimestamp, const CScript& genesisOutputScript, uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    int64_t nChainStartTime = 1391393673;

    CMutableTransaction txNew;
    txNew.nVersion = 1;
    txNew.nTime = nChainStartTime;
    txNew.vin.resize(1);
    txNew.vout.resize(1);
    txNew.vin[0].scriptSig = CScript() << 486604799 << CScriptNum(9999) << std::vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
    txNew.vout[0].SetEmpty();
	//txNew.vout[0].nValue = genesisReward;
    //txNew.vout[0].scriptPubKey = genesisOutputScript;
		
    CBlock genesis;
    genesis.nTime    = nTime;
    genesis.nBits    = nBits;
    genesis.nNonce   = nNonce;
    genesis.nVersion = nVersion;
    genesis.vtx.push_back(MakeTransactionRef(std::move(txNew)));
    genesis.hashPrevBlock.SetNull();
    genesis.hashMerkleRoot = BlockMerkleRoot(genesis);
    return genesis;
}

/**
 * Build the genesis block. Note that the output of its generation
 * transaction cannot be spent since it did not originally exist in the
 * database.
 *
 * CBlock(hash=000000000019d6, ver=1, hashPrevBlock=00000000000000, hashMerkleRoot=4a5e1e, nTime=1231006505, nBits=1d00ffff, nNonce=2083236893, vtx=1)
 *   CTransaction(hash=4a5e1e, ver=1, vin.size=1, vout.size=1, nLockTime=0)
 *     CTxIn(COutPoint(000000, -1), coinbase 04ffff001d0104455468652054696d65732030332f4a616e2f32303039204368616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f757420666f722062616e6b73)
 *     CTxOut(nValue=50.00000000, scriptPubKey=0x5F1DF16B2B704C8A578D0B)
 *   vMerkleTree: 4a5e1e
 */
static CBlock CreateGenesisBlock(uint32_t nTime, uint32_t nNonce, uint32_t nBits, int32_t nVersion, const CAmount& genesisReward)
{
    const char* pszTimestamp = "31/5";
    const CScript genesisOutputScript = CScript() << ParseHex("040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9") << OP_CHECKSIG;
    return CreateGenesisBlock(pszTimestamp, genesisOutputScript, nTime, nNonce, nBits, nVersion, genesisReward);
}

void CChainParams::UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    consensus.vDeployments[d].nStartTime = nStartTime;
    consensus.vDeployments[d].nTimeout = nTimeout;
}

/**
 * Main network
 */
/**
 * What makes a good checkpoint block?
 * + Is surrounded by blocks with reasonable timestamps
 *   (no blocks before with a timestamp after, none after with
 *    timestamp before)
 * + Contains no strange transactions
 */

class CMainParams : public CChainParams {
public:
    CMainParams() {
        strNetworkID = "main";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Exception = uint256S("0x00000000000002dc756eebf4f49723ed8d30cc28a5f108eb94b1ba88ac4f9c22"); // P2SH
        consensus.BIP34Height = 0;
        consensus.BIP34Hash = uint256S("0x2d8251121940abce6e28df134c6432e8c5a00d59989a2451806c2778c3a06112"); // Block v2, Height in Coinbase [using genesis]
        consensus.BIP65Height = 388381; // OP_CHECKLOCKTIMEVERIFY [Consensus (soft fork)] - forced far into future for now
        consensus.BIP66Height = 363725; // Strict DER signatures [Consensus (soft fork)] - forced far into future for now

        // Proof of stake
        consensus.nProofOfStakeLimit = ~arith_uint256("0") >> 2;
        consensus.nStakeMinAge = 60 * 60 * 1 * 1; // 1h, minimum age for coin age:  6h
        consensus.nStakeMaxAge = 60 * 60 * 8 * 1; // 8h, stake age of full weight:  4d 60*60*24*1
        consensus.nStakeTargetSpacing = 60;       // 60 sec block spacing
        consensus.nStakeModifierInterval = MODIFIER_INTERVAL;
        consensus.nCoinbaseMaturity = 40;

        // Proof of work
        consensus.nProofOfWorkLimit = ~arith_uint256("0") >> 20;
        consensus.nPowTargetTimespan = 60 * 30; // 30 blocks
        consensus.nPowTargetSpacing = 3 * consensus.nStakeTargetSpacing;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;
        
        // Deployments
        consensus.nRuleChangeActivationThreshold = 6048; // 75% of 8064
        consensus.nMinerConfirmationWindow = 8064; // nPowTargetTimespan / nPowTargetSpacing * 4
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999; // December 31, 2008

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;

	    consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0; // disabled
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // disabled

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0; // disabled
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // disabled

        // The best chain should have at least this much work.
        //consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000028822fef1c230963535a90d");
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"); // TODO: [rzr] check this value as it should probably correspond to the actual work of the last checkpointed block

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00000000001bd0502781789a5e148136fb6e071576e5ed4764186db7e474accb "); // 1000

        /**
         * The message start string is designed to be unlikely to occur in normal data.
         * The characters are rarely used upper ASCII, not valid as UTF-8, and produce
         * a large 32-bit integer with any alignment.
         */
        pchMessageStart[0] = 0x70;
        pchMessageStart[1] = 0x35;
        pchMessageStart[2] = 0x22;
        pchMessageStart[3] = 0x05;
        nDefaultPort = 29662;
        nPruneAfterHeight = 100000;

        genesis = CreateGenesisBlock(1401537155, 1363322, 504365055, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x2d8251121940abce6e28df134c6432e8c5a00d59989a2451806c2778c3a06112"));
        assert(genesis.hashMerkleRoot == uint256S("0x1831d9f590f8b705ed996fcaa37ece517cfa6eb619af6738b2606383eab5a619"));

        // Note that of those which support the service bits prefix, most only support a subset of
        // possible options.
        // This is fine at runtime as we'll fall back to using them as a oneshot if they don't support the
        // service bits we want, but we should get them updated to support all service bits wanted by any
        // release ASAP to avoid it where possible.

        vSeeds.emplace_back("101.183.63.13");
        vSeeds.emplace_back("104.159.171.182");
        vSeeds.emplace_back("104.254.41.191");
        vSeeds.emplace_back("107.207.166.81");
        vSeeds.emplace_back("108.170.32.130");

        vSeeds.emplace_back("node1.cloakcoin.com");
        vSeeds.emplace_back("node2.cloakcoin.com");
        vSeeds.emplace_back("node3.cloakcoin.com");
        vSeeds.emplace_back("node4.cloakcoin.com");
        vSeeds.emplace_back("node5.cloakcoin.com");
        vSeeds.emplace_back("173.212.243.180");
        vSeeds.emplace_back("213.136.75.147");

		/*
        PUBKEY_ADDRESS = 27,  // CloakCoin: address begin with 'C'
        SCRIPT_ADDRESS = 85, 
        PUBKEY_ADDRESS_TEST = 111,
        SCRIPT_ADDRESS_TEST = 196,
		*/

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,27);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,85);
        base58Prefixes[SECRET_KEY] = std::vector<unsigned char>(1, 176); // TODO: check if value should be changed
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x88, 0xB2, 0x1E}; // TODO: check if value should be changed
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x88, 0xAD, 0xE4}; // TODO: check if value should be changed

        bech32_hrp = "cc";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_main, pnSeed6_main + ARRAYLEN(pnSeed6_main));

        fDefaultConsistencyChecks = false;
        fRequireStandard = true;
        fMineBlocksOnDemand = false;

        checkpointData = {
            {
                {0, consensus.hashGenesisBlock},
                {7900, uint256S("0x00000000000b3e4280fb009d24dfc90c563a225f3ef8dcefb230ab0fa1b820d6")},
                {25000, uint256S("0x977d97d18c3666fe6747e178b54959edf1d15ac282a0b3e052adcf1aaaf5fbe1")},
                {50000, uint256S("0xdd6cf2ae0ad0ed2356a0f580f2cda34bfeb7d5a4d871f9a324b979e31c516082")},
                {75000, uint256S("0x4ce8ef2b38bbc7db5993a4ad3a83d2086294d5724acf2791f385e86da2e5fe50")},
                {100000, uint256S("0x2c8022b567300009600eb640d6eba9e7d6604ac2d81905325caf0df1bb521fc8")},
                {125000, uint256S("0x28bd26bee8d3792d2696447b7d8e09efd6a27be16e5d65f68b0731fb054c7bdc")},
                {150000, uint256S("0xb3d59f85fb1aee62e875a551a416fc8a6e518901e9a41a91cba1b18591eecbac")},
                {175000, uint256S("0x94b5c48efa1cb5cd7d878d2b5481efc02844ea87eebb7706d51a291e6c691853")},
                {200000, uint256S("0x07a0aacedd13fee9a2e997c96d9b573db7a5a787338c6877d520987c0e56801c")},
                {225000, uint256S("0xd76864a1e67afeac7a5cef5fd767f8dd407c9e79155a74b0645da9d7c85738f7")},
                {250000, uint256S("0xddf556bb8cbd6252d79dbef076d538b15d96434039de96c63841e2c0563cc458")},
                {275000, uint256S("0xf83b1cc58226913005991ca37227ef848d0309fa2cbbf2589837270f9b243cc7")},
                {300000, uint256S("0x5f1e1cb6a93c3233669f039eba558998f8ec6a76e19b96c9ae4eae808bd346f1")},
                {325000, uint256S("0xe1d7090e2385a7278cd4a160379b451faedf45609bf0049248553bddcb869f14")},
                {350000, uint256S("0x2ad2d16cae48a283b1a5292fb48436750f32dcf2e7dcbbf259f58f2ce14448f1")},
                {375000, uint256S("0x39847cb2e1dee0c3726578a9540c69ce93de7514fd2462422da0c9a834d8e203")},
                {400000, uint256S("0x6dafff13cb9548aaaf49ed83ecdcc2684f9baf8e7f1170a3b9e2a16b71d80fcb")},
                {425000, uint256S("0xf897e4b075350b2166e1c0dcb9496a5ea32611b3519da87a7b4f006b56f3f310")},
                {450000, uint256S("0xc7d4889dc95111d442dffc310820add69bc9826297235c9629aa83f890cd5047")},
                {475000, uint256S("0x2cbc03b78cfd38f6d3e6bbc4006ed82762e12b575f99407ef60a498396f36420")},
                {500000, uint256S("0xbccd07f2827937007a6662cd1fb38da7316940fa963fa1c5180d8bb2a28878d7")},
                {525000, uint256S("0x50ac7a25eb435b427720e5d64889d98a968495282d53ad69b2c2d293b1ee0e10")},
                {550000, uint256S("0xfc1959eef795b528753afbf69c421b8996e106652004087fbd4e530b62b3836f")},
                {575000, uint256S("0xae397e88688fc09f7df96020fee7d8311a0365ab7a95dac324fa155065580961")},
                {600000, uint256S("0xd2d5877d281e2b664c3666fc5edc7099ad9ec6ccb701259e68ec291aa77d9fe0")},
                {625000, uint256S("0x29023ccc4d3e037b1cf1bd4393b16b7926a00f3480b4e4b327138961260d0848")},
                {650000, uint256S("0xa8193ee04d8dec5fdd21af5923aabbff3f8d02bd30ebf425903efc50f7f242f7")},
                {675000, uint256S("0x8832f8e6c9c446e9370040b31c540e459a5a5d108eedf1136189a7aa6a10bb8a")},
                {700000, uint256S("0x3008cf349da9ed1395911404aec5610784c97afbee2e99fe38595456a9783fd8")},
                {725000, uint256S("0x06ff2fd9b59a509ce3330e2eec1074d3f56be47c0d0b01c97038db5d884a4129")},
                {750000, uint256S("0x678a68f20275265991408d6002c8d3a60426503f1d23869b3d18d40f73d59665")},
                {775000, uint256S("0x6f3a67246cd3efb1d1cc3267d41cafdceac76cfc89821db892b66ecd33bb8664")},
                {800000, uint256S("0xb306a358dded8e42d7480162566ea0f08a05e937ff502c53ffe91d6c60672784")},
                {805000, uint256S("0xd3ea3b2f0e2fe2a6072c6c5df0f1ad2149d300a36e1142c867156df67dcc50cf")},
                {810000, uint256S("0xd969eda363dc90373c5a65288e6889bbd96103a70c9c821127533fbe13770fa0")}
            }
        };

        // todo: check and set correctly!
        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000000002e63058c023a9a1de233554f28c7b21380b6c9003f36a8
            /* nTime    */ 1532884444,
            /* nTxCount */ 331282217,
            /* dTxRate  */ 2.4
        };

        /* disable fallback fee on mainnet */
        m_fallback_fee_enabled = false;
        fMiningRequiresPeers = true;
    }
};

/**
 * Testnet (v4)
 */
class CTestNetParams : public CChainParams {
public:
    CTestNetParams() {
        strNetworkID = "test";
        consensus.nSubsidyHalvingInterval = 210000;
        consensus.BIP16Exception = uint256S("0x00000000dd30457c001f4095d208cc1296b0eed002427aa599874af7a432b105");
        consensus.BIP34Height = 21111;
        consensus.BIP34Hash = uint256S("0x0000000023b3a96d3484e5abb3755c413e7d41500f8e2a5c3f0dd01299cd8ef8");
        consensus.BIP65Height = 581885; // 00000000007f6655f22f98e72ed80d8b06dc761d5da09df0fa1dc4be4f861eb6
        consensus.BIP66Height = 330776; // 000000002104c8c45e99a8853285a3b592602a3ccde2b832481da85e9e4ba182
        consensus.nRuleChangeActivationThreshold = 1512; // 75% for testchains
        consensus.nMinerConfirmationWindow = 2016;       // nPowTargetTimespan / nPowTargetSpacing
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 1199145601; // January 1, 2008
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = 1230767999;   // December 31, 2008

        // Proof of stake
        consensus.nProofOfStakeLimit = ~arith_uint256("0") >> 2;
        consensus.nStakeMinAge = 2 * 60; // test net min age is 2 min
        consensus.nStakeMaxAge = 6 * 60; // test net min age is 6 min
        consensus.nStakeTargetSpacing = 60; // 60 sec block spacing
        consensus.nStakeModifierInterval = 60;
        consensus.nCoinbaseMaturity = 10; // test maturity is 10 blocks

        // Proof of work
        consensus.nProofOfWorkLimit = ~arith_uint256("0") >> 2;
        consensus.nPowTargetTimespan = 60 * 30; // 30 blocks
        consensus.nPowTargetSpacing = 3 * consensus.nStakeTargetSpacing;
        consensus.fPowAllowMinDifficultyBlocks = false;
        consensus.fPowNoRetargeting = false;

        // Deployment of BIP68, BIP112, and BIP113.
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0; // disabled
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = 0; // disabled

        // Deployment of SegWit (BIP141, BIP143, and BIP147)
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = 0; // disabled
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = 0; // disabled

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x0000000000000000000000000000000000000000000000000000000000000000"); //1354312

        unsigned int testnetNumber = 4;	//	hardcoded to testnet4 for now
        unsigned char testNum = testnetNumber + 2;

        pchMessageStart[0] = 0x22 + testNum;
        pchMessageStart[1] = 0x0a + testNum;
        pchMessageStart[2] = 0x70 + testNum;
        pchMessageStart[3] = 0x25 + testNum;
        nDefaultPort = 29665;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1414697233, 1363324, 541065215, 1, 0);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0xeb839aa81f3ec87bbaf993033d0a68219918b327a82709482e446b8ae0a21c4f"));
        assert(genesis.hashMerkleRoot == uint256S("0x1831d9f590f8b705ed996fcaa37ece517cfa6eb619af6738b2606383eab5a619"));

        vFixedSeeds.clear();
        vSeeds.clear();
        // nodes with support for servicebits filtering should be at the top
        
        vSeeds.emplace_back("testnet1.cloakcoin.com");
        vSeeds.emplace_back("testnet2.cloakcoin.com");
        vSeeds.emplace_back("testnet3.cloakcoin.com");
        vSeeds.emplace_back("testnet4.cloakcoin.com"); 
        
        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "cct";

        vFixedSeeds = std::vector<SeedSpec6>(pnSeed6_test, pnSeed6_test + ARRAYLEN(pnSeed6_test));

        fDefaultConsistencyChecks = false;
        fRequireStandard = false;
        fMineBlocksOnDemand = false;


        checkpointData = {
            {
                //{0, uint256S("0xe0b104aef9b6c0dd6e2e05a10fa2c7b34406c8be8b3e09e9135ef91e0c576c10")}
            }
        };

        chainTxData = ChainTxData{
            // Data from rpc: getchaintxstats 4096 0000000000000037a8cd3e06cd5edbfe9dd1dbcc5dacab279376ef7cfc2b4c75
            /* nTime    */ 1531929919,
            /* nTxCount */ 19438708,
            /* dTxRate  */ 0.626
        };

        /* enable fallback fee on testnet */
        m_fallback_fee_enabled = true;
        fMiningRequiresPeers = true;
    }
};

/**
 * Regression test
 */
class CRegTestParams : public CChainParams {
public:
    CRegTestParams() {
        strNetworkID = "regtest";
        consensus.nSubsidyHalvingInterval = 150;
        consensus.BIP16Exception = uint256();
        consensus.BIP34Height = 100000000; // BIP34 has not activated on regtest (far in the future so block v1 are not rejected in tests)
        consensus.BIP34Hash = uint256();
        consensus.BIP65Height = 1351; // BIP65 activated on regtest (Used in rpc activation tests)
        consensus.BIP66Height = 1251; // BIP66 activated on regtest (Used in rpc activation tests)
        consensus.nProofOfWorkLimit = UintToArith256(uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"));
        consensus.nPowTargetTimespan = 14 * 24 * 60 * 60; // two weeks
        consensus.nPowTargetSpacing = 10 * 60;
        consensus.fPowAllowMinDifficultyBlocks = true;
        consensus.fPowNoRetargeting = true;
        consensus.nRuleChangeActivationThreshold = 108; // 75% for testchains
        consensus.nMinerConfirmationWindow = 144; // Faster than normal for regtest (144 instead of 2016)
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].bit = 28;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_TESTDUMMY].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].bit = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nStartTime = 0;
        consensus.vDeployments[Consensus::DEPLOYMENT_CSV].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].bit = 1;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nStartTime = Consensus::BIP9Deployment::ALWAYS_ACTIVE;
        consensus.vDeployments[Consensus::DEPLOYMENT_SEGWIT].nTimeout = Consensus::BIP9Deployment::NO_TIMEOUT;

        // The best chain should have at least this much work.
        consensus.nMinimumChainWork = uint256S("0x00");

        // By default assume that the signatures in ancestors of this block are valid.
        consensus.defaultAssumeValid = uint256S("0x00");

        pchMessageStart[0] = 0xfa;
        pchMessageStart[1] = 0xbf;
        pchMessageStart[2] = 0xb5;
        pchMessageStart[3] = 0xda;
        nDefaultPort = 18444;
        nPruneAfterHeight = 1000;

        genesis = CreateGenesisBlock(1296688602, 2, 0x207fffff, 1, 50 * COIN);
        consensus.hashGenesisBlock = genesis.GetHash();
        assert(consensus.hashGenesisBlock == uint256S("0x0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206"));
        assert(genesis.hashMerkleRoot == uint256S("0x4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"));

        vFixedSeeds.clear(); //!< Regtest mode doesn't have any fixed seeds.
        vSeeds.clear();      //!< Regtest mode doesn't have any DNS seeds.

        fDefaultConsistencyChecks = true;
        fRequireStandard = false;
        fMineBlocksOnDemand = true;

        checkpointData = {
            {
                {0, uint256S("0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206")},
            }
        };
                
        chainTxData = ChainTxData{
            0,
            0,
            0
        };

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1,111);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1,196);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1,239);
        base58Prefixes[EXT_PUBLIC_KEY] = {0x04, 0x35, 0x87, 0xCF};
        base58Prefixes[EXT_SECRET_KEY] = {0x04, 0x35, 0x83, 0x94};

        bech32_hrp = "ccrt";

        /* enable fallback fee on regtest */
        m_fallback_fee_enabled = true;
        fMiningRequiresPeers = false;
    }
};

static std::unique_ptr<CChainParams> globalChainParams;

const CChainParams &Params() {
    assert(globalChainParams);
    return *globalChainParams;
}

std::unique_ptr<CChainParams> CreateChainParams(const std::string& chain)
{
    if (chain == CBaseChainParams::MAIN)
        return std::unique_ptr<CChainParams>(new CMainParams());
    else if (chain == CBaseChainParams::TESTNET)
        return std::unique_ptr<CChainParams>(new CTestNetParams());
    else if (chain == CBaseChainParams::REGTEST)
        return std::unique_ptr<CChainParams>(new CRegTestParams());
    throw std::runtime_error(strprintf("%s: Unknown chain %s.", __func__, chain));
}

void SelectParams(const std::string& network)
{
    SelectBaseParams(network);
    globalChainParams = CreateChainParams(network);
}

void UpdateVersionBitsParameters(Consensus::DeploymentPos d, int64_t nStartTime, int64_t nTimeout)
{
    globalChainParams->UpdateVersionBitsParameters(d, nStartTime, nTimeout);
}
