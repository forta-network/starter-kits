# Malicious Smart Contract ML V3 Release Notes

## v3.1.1 - Dec 28 2023
- added PUSH3 to getting function sigs (e.g. could be 0x00aabbcc, which is pushed through PUSH3 as opposed to PUSH4)

## v3.1.0 (Nov 17 2023 - 0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91 (beta), Nov 20 2023 - 0x9aaa5cd64000e8ba4fa2718a467b90055b70815d60351914cc1cbe89fe1c404c (prod))
- added function sigs contained in smart contract analyzed; not just the function sigs of itself, but more importantly the function sigs of what it may be calling. Function sigs are extraced by simply looking for PUSH4s. 


## v3.0.3 (Oct 19 2023 - 0x0b241032ca430d9c02eaa6a52d217bbff046f0d1b3f3d2aa928e42a97150ec91 (beta))
- fixed issue where traces didnt report the contract creation and the to_address (none)/nonce need to be utilized
