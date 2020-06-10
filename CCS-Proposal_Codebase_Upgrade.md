
## Scope of work:

1) Upgrade Cloak codebase / Setup Testnet
(https://github.com/CloakProject/CloakCoin) to Bitcoin 0.17.0.1 (https://github.com/bitcoin/bitcoin/tree/0.17)
2) Migrate to Consensus / Mining (PoW / PoS) as used in CloakCoin Stable Codebase
https://github.com/CloakProject/codename-phoenix/tree/0.17.cloak/src/consensus
(CloakProject/codename-phoenix: Issue #5)
3) Migrate Enigma functionality to new codebase 
https://github.com/CloakProject/CloakCoin/tree/master/src/enigma
4) Migrate CloakShield functionality to new codebase
https://github.com/CloakProject/CloakCoin/tree/master/src/enigma
5) Enable Stealth Address Support (CloakProject/codename-phoenix: Issue #36)
6) Compile Wallet for Linux, OSX, Windows based on Bitcoin 0.17.XX
7) Monthly developer updates

## Notes:

Due to the significant changes to the underlying Bitcoin codebase since Cloak was first created (and the lack of other similar coins [PeerCoin, NovaCoin etc] having yet upgraded), 
large portions of the code need to be refactored and rewritten to enable them to ‘slot into’ the new Bitcoin codebase, 
which has seen significant changes in terms of structure, layout and functionality. Without a similar coin to crib code 
from during the upgrade, it is likely that the need to restructure and massage ported code and functionality will continue 
during the rebasing. This realisation also gives further credence to the validity of reconsidering the choice of codebase for 
upgrading/rebasing with a view to increasing development progress going forward and incorporating new functionality. 
The current plan is still to produce a functionally equivalent Cloak client that is interoperable with the existing legacy client, 
prior to forking the network to introduce a new PoS algorithm with community funding support. 
(and other potential possibilities such as on-chain governance/voting and network generation of Enigma rewards).

Novacoin
https://github.com/novacoin-project/novacoin
Peercoin
https://github.com/peercoin/peercoin
Whitepaper
https://www.cloakcoin.com/user/themes/g5_cloak/resources/CloakCoin_Whitepaper_v2.1.pdf

## Cost breakdown:

Total: $180.000

CLOAK ($0.16): 1.125.000

## Timeline (6 Months)

1 Milestone (Advance Payment)	
- Preparation
- Setup Test Infrastructure	

2 Milestone
- Bitcoin codebase 0.17.X Migration	
- Migrate to Consensus / Mining (PoW / PoS) as used in CloakCoin Stable Codebase

3 Milestone
- Migrate Enigma functionality to new codebase 

4 Milestone	
- Migrate CloakShield functionality to new codebase

5 Milestone	
- Enable Stealth Address Support
- POW hashfunction/difficulty
- Sync Test/Consensus with previous blocks	

6 Milestone	
- Security and Code Check
- Documentation development	
- Compile Wallet for Linux, OSX, Windows	

## Team
1x Full-Stack Developer, 1x C++ Engineer & QT Software Engineer, 1x Product Lead and Security Tester

