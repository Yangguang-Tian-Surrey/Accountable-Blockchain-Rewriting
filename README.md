# Accountable-Blockchain-Rewriting
We use python with charm framework to implement the policy-based chameleon hash function with black-box accountability PCHBA. The PCHBA can be used to secure blockchain rewriting, such that trapdoor holder may maliciously rewrite the blockchain without being identified. 

The PCHBA consistes of an attribute-based encryption ABE (FAME: Fast Attribute-based Message Encryption, CCS 2017), a hierarch identity-based encryption HIBE (HIBE: Hierarchical identity based encryption with constant size ciphertext, CRYPTO 2005), a chameleon hash with ephemeral trapdoor (CHET: Chameleon-hashes with ephemeral trapdoors, PKC 2017), and a digital signature scheme (e.g., Schnorr). 

The PCHBA implementation includes 6 algorithms, including setup, keygen, hash, verify, adapt and judge. For PCHBA, an important primitive is traceable CP-ABE scheme (or ABET), which is based on FAME and HIBE. The keygen of ABET is part of the keygen algorithm in PCHBA, the encryption/decryption of ABET is part of the hash/adapt algorithm in PCHBA. 

The source code of PCHBA can be found in PCHBA.py and Main.py. In particular, we evaluate the performance of the keygen, hash and adapt algorithms in terms of the number of attributes/policies. This is because their performance is linear to the number of attributes (from 1 to 100) and policies (from 1 to 100) in the system. 

We list some points regarding our source code: 1) user's identity in HIBE is assumed to have the longest length in the hierarchy (or no delegation). 2) the identities used in the keygen/hash/adapt algorithms are pre-computed at setup algorithm, which makes the keygen/hash/adapt algorithms efficient. 3) we use "sha256" from hashlib to realize the hash function which maps a random bit-string to finite field Z_q. 
