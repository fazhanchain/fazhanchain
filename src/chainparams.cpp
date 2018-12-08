// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2012 The Bitcoin developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "assert.h"

#include "chainparams.h"
#include "main.h"
#include "util.h"

#include <boost/assign/list_of.hpp>

using namespace boost::assign;

struct SeedSpec6 {
    uint8_t addr[16];
    uint16_t port;
};

#include "chainparamsseeds.h"

//
// Main network
//

// Convert the pnSeeds6 array into usable address objects.
static void convertSeed6(std::vector<CAddress> &vSeedsOut, const SeedSpec6 *data, unsigned int count)
{
    // It'll only connect to one or two seed nodes because once it connects,
    // it'll get a pile of addresses with newer timestamps.
    // Seed nodes are given a random 'last seen time' of between one and two
    // weeks ago.
    const int64_t nOneWeek = 7*24*60*60;
    for (unsigned int i = 0; i < count; i++)
    {
        struct in6_addr ip;
        memcpy(&ip, data[i].addr, sizeof(ip));
        CAddress addr(CService(ip, data[i].port));
        addr.nTime = GetTime() - GetRand(nOneWeek) - nOneWeek;
        vSeedsOut.push_back(addr);
    }
}

class CMainParams : public CChainParams {
public:
    CMainParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0x2a;
        pchMessageStart[1] = 0x7b;
        pchMessageStart[2] = 0xcc;
        pchMessageStart[3] = 0xae;
        vAlertPubKey = ParseHex("0433a6bf169b4612db815f9a9160929e4aabfcb4664fdefa5cb04788c582b3e50a11fdd530d06fb4096357fc4aa29f7c114d4b40b7ba05b425802e1692e3a28cf2");
        nDefaultPort = 17998;
        nRPCPort = 17999;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 20);

        // Build the genesis block. Note that the output of the genesis coinbase cannot
        // be spent as it did not originally exist in the database.
        //
        //CBlock(hash=000001faef25dec4fbcf906e6242621df2c183bf232f263d0ba5b101911e4563, ver=1, hashPrevBlock=0000000000000000000000000000000000000000000000000000000000000000, hashMerkleRoot=12630d16a97f24b287c8c2594dda5fb98c9e6c70fc61d44191931ea2aa08dc90, nTime=1393221600, nBits=1e0fffff, nNonce=164482, vtx=1, vchBlockSig=)
        //  Coinbase(hash=12630d16a9, nTime=1393221600, ver=1, vin.size=1, vout.size=1, nLockTime=0)
        //    CTxIn(COutPoint(0000000000, 4294967295), coinbase 00012a24323020466562203230313420426974636f696e2041544d7320636f6d6520746f20555341)
        //    CTxOut(empty)
        //  vMerkleTree: 12630d16a9
        const char* pszTimestamp = "fazhanchain!";
        std::vector<CTxIn> vin;
        vin.resize(1);
        vin[0].scriptSig = CScript() << 0 << CBigNum(42) << vector<unsigned char>((const unsigned char*)pszTimestamp, (const unsigned char*)pszTimestamp + strlen(pszTimestamp));
        std::vector<CTxOut> vout;
        vout.resize(1);
        vout[0].SetEmpty();
        CTransaction txNew(1, 1539608229, vin, vout, 0);
        genesis.vtx.push_back(txNew);
        genesis.hashPrevBlock = 0;
        genesis.hashMerkleRoot = genesis.BuildMerkleTree();
        genesis.nVersion = 1;
        genesis.nTime    = 1539608229;
        genesis.nBits    = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce   = 1217110;
	if (true && genesis.GetHash() != hashGenesisBlock)
                       {
                           printf("Searching for genesis block...\n");
                           uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
                           uint256 thash;
                           while (true)
                           {
                               thash = genesis.GetHash();
                               if (thash <= hashTarget)
                                 break;
                               if ((genesis.nNonce & 0xFFF) == 0)
                               {
                                   printf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                               }
                               ++genesis.nNonce;
                               if (genesis.nNonce == 0)
                               {
                                   printf("NONCE WRAPPED, incrementing time\n");
                                   ++genesis.nTime;
                               }
                           }
                           printf("genesis.nTime = %u \n", genesis.nTime);
                           printf("genesis.nNonce = %u \n", genesis.nNonce);
                           printf("genesis.nVersion = %u \n", genesis.nVersion);
                           printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str()); //first this, then comment this line out and uncomment the one under.
                           printf("genesis.hashMerkleRoot = %s \n", genesis.hashMerkleRoot.ToString().c_str()); //improvised. worked for me, to find merkle root/
                       }
        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x00000668cedb305700a8121a7a0f2ad5ded611264f51dd843ea20657ce83d7ea"));
        assert(genesis.hashMerkleRoot == uint256("0x17be32770ffee51a39d7034555941e3297912f0fb629be700ef2366954a9da31"));


        vSeeds.push_back(CDNSSeedData("164.52.43.250", "164.52.43.250"));

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 14);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 5);
        base58Prefixes[SECRET_KEY] =     std::vector<unsigned char>(1, 142);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x73)(0xAA)(0x31).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x73)(0x44)(0x79).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_main, ARRAYLEN(pnSeed6_main));

        nLastPOWBlock = 2000;
    }

    virtual const CBlock& GenesisBlock() const { return genesis; }
    virtual Network NetworkID() const { return CChainParams::MAIN; }

    virtual const vector<CAddress>& FixedSeeds() const {
        return vFixedSeeds;
    }
protected:
    CBlock genesis;
    vector<CAddress> vFixedSeeds;
};
static CMainParams mainParams;


//
// Testnet
//

class CTestNetParams : public CMainParams {
public:
    CTestNetParams() {
        // The message start string is designed to be unlikely to occur in normal data.
        // The characters are rarely used upper ASCII, not valid as UTF-8, and produce
        // a large 4-byte int at any alignment.
        pchMessageStart[0] = 0xc1;
        pchMessageStart[1] = 0x72;
        pchMessageStart[2] = 0xc3;
        pchMessageStart[3] = 0x74;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 16);
        vAlertPubKey = ParseHex("047549ef1c46fd0f36ad41809665419c9f8495fbccd9573b292a8674f5cbd7068150d79b37b8a0d93787b0b82bdc09b0183e7257fbacbda4e0cc1cc4a840bea2fc");
        nDefaultPort = 27995;
        nRPCPort = 27996;
        strDataDir = "testnet";

        // Modify the testnet genesis block so the timestamp is valid for a later start.
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 96608;
         if (true && genesis.GetHash() != hashGenesisBlock)
                         {
                             printf("Searching for genesis block...\n");
                             uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
                             uint256 thash;
                             while (true)
                             {
                                 thash = genesis.GetHash();
                                 if (thash <= hashTarget)
                                     break;
                                 if ((genesis.nNonce & 0xFFF) == 0)
                                 {
                                     printf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                                 }
                                 ++genesis.nNonce;
                                 if (genesis.nNonce == 0)
                                 {
                                     printf("NONCE WRAPPED, incrementing time\n");
                                     ++genesis.nTime;
                                }
                             }
                             printf("genesis.nTime = %u \n", genesis.nTime);
                             printf("genesis.nNonce = %u \n", genesis.nNonce);
                             printf("genesis.nVersion = %u \n", genesis.nVersion);
                             printf("genesis.hashMerkleRoot = %s \n", genesis.hashMerkleRoot.ToString().c_str()); //idk
                             printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
                         }
        hashGenesisBlock = genesis.GetHash();
        assert(hashGenesisBlock == uint256("0x0000a998823b81d987ee478ad7bbe03c67efcae78d88ca39491458e6ce1c0ad0"));

        vFixedSeeds.clear();
        vSeeds.clear();

        base58Prefixes[PUBKEY_ADDRESS] = std::vector<unsigned char>(1, 110);
        base58Prefixes[SCRIPT_ADDRESS] = std::vector<unsigned char>(1, 129);
        base58Prefixes[SECRET_KEY]     = std::vector<unsigned char>(1, 239);
        base58Prefixes[EXT_PUBLIC_KEY] = boost::assign::list_of(0x04)(0x35)(0x17)(0xFF).convert_to_container<std::vector<unsigned char> >();
        base58Prefixes[EXT_SECRET_KEY] = boost::assign::list_of(0x04)(0x35)(0x43)(0x99).convert_to_container<std::vector<unsigned char> >();

        convertSeed6(vFixedSeeds, pnSeed6_test, ARRAYLEN(pnSeed6_test));

        nLastPOWBlock = 0x7fffffff;
    }
    virtual Network NetworkID() const { return CChainParams::TESTNET; }
};
static CTestNetParams testNetParams;


//
// Regression test
//
class CRegTestParams : public CTestNetParams {
public:
    CRegTestParams() {
        pchMessageStart[0] = 0xa1;
        pchMessageStart[1] = 0x4b;
        pchMessageStart[2] = 0x52;
        pchMessageStart[3] = 0xd7;
        bnProofOfWorkLimit = CBigNum(~uint256(0) >> 1);
        genesis.nTime = 1529910779;
        genesis.nBits  = bnProofOfWorkLimit.GetCompact();
        genesis.nNonce = 1592;
        hashGenesisBlock = genesis.GetHash();
        nDefaultPort = 57995;
        strDataDir = "regtest";
         if (true)
                         {
                             printf("Searching for genesis block...\n");
                             uint256 hashTarget = CBigNum().SetCompact(genesis.nBits).getuint256();
                             uint256 thash;
                             while (true)
                             {
                                 thash = genesis.GetHash();
                                 if (thash <= hashTarget)
                                     break;
                                 if ((genesis.nNonce & 0xFFF) == 0)
                                 {
                                     printf("nonce %08X: hash = %s (target = %s)\n", genesis.nNonce, thash.ToString().c_str(), hashTarget.ToString().c_str());
                                 }
                                 ++genesis.nNonce;
                                 if (genesis.nNonce == 0)
                                 {
                                     printf("NONCE WRAPPED, incrementing time\n");
                                     ++genesis.nTime;
                                 }
                             }
                             printf("genesis.nTime = %u \n", genesis.nTime);
                             printf("genesis.nNonce = %u \n", genesis.nNonce);
                             printf("genesis.nVersion = %u \n", genesis.nVersion);
                             printf("genesis.hashMerkleRoot = %s \n", genesis.hashMerkleRoot.ToString().c_str()); //idk
                             printf("genesis.GetHash = %s\n", genesis.GetHash().ToString().c_str());
                         }
        assert(hashGenesisBlock == uint256("0x396903c04efb965e719f6598708e6c79e3f4da6f03ac6a5350a48ebfd28519c3"));

        vSeeds.clear();  // Regtest mode doesn't have any DNS seeds.
    }

    virtual bool RequireRPCPassword() const { return false; }
    virtual Network NetworkID() const { return CChainParams::REGTEST; }
};
static CRegTestParams regTestParams;

static CChainParams *pCurrentParams = &mainParams;

const CChainParams &Params() {
    return *pCurrentParams;
}

void SelectParams(CChainParams::Network network) {
    switch (network) {
        case CChainParams::MAIN:
            pCurrentParams = &mainParams;
            break;
        case CChainParams::TESTNET:
            pCurrentParams = &testNetParams;
            break;
        case CChainParams::REGTEST:
            pCurrentParams = &regTestParams;
            break;
        default:
            assert(false && "Unimplemented network");
            return;
    }
}

bool SelectParamsFromCommandLine() {
    bool fRegTest = GetBoolArg("-regtest", false);
    bool fTestNet = GetBoolArg("-testnet", false);

    if (fTestNet && fRegTest) {
        return false;
    }

    if (fRegTest) {
        SelectParams(CChainParams::REGTEST);
    } else if (fTestNet) {
        SelectParams(CChainParams::TESTNET);
    } else {
        SelectParams(CChainParams::MAIN);
    }
    return true;
}
