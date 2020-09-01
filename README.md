# Accountable-Blockchain-Rewriting
We use python with charm framework to implement the policy-based chameleon hash function with black-box accountability PCHBA. The PCHBA can be used to secure blockchain rewriting, such that trapdoor holder may maliciously rewrite the blockchain without being identified. 

The instantiation of PCHBA includes the following primitives: an attribute-based encryption ABE (FAME: Fast Attribute-based Message Encryption, CCS 2017), a hierarch identity-based encryption HIBE (HIBE: Hierarchical identity based encryption with constant size ciphertext, CRYPTO 2005), a chameleon hash with ephemeral trapdoor (CHET: Chameleon-hashes with ephemeral trapdoors, PKC 2017), and a digital signature scheme (e.g., Schnorr). 

The implementation includes 6 algorithms, including setup, keygen, hash, verify, adapt and judge. For PCHBA, an important primitive is traceable CP-ABE scheme (or ABET), which is based on FAME and HIBE. The keygen of ABET is part of the keygen algorithm in PCHBA, the encryption/decryption of ABET is part of the hash/adapt algorithm in PCHBA. 

The source code of PCHBA can be found in PCHBA.py and Main.py. In particular, we evaluate the performance of the keygen, hash and adapt algorithms in terms of the number of attributes, and the size of policies. This is because their performances are linear to the number of attributes (e.g., from 1 to 100) and the size of policies. 

We list some points regarding our source code: 1) user's identity in HIBE is assumed to have the longest length in the hierarchy (i.e., no delegation). 2) the identities used in the keygen/hash/adapt algorithms are pre-computed at setup algorithm, which makes the keygen/hash/adapt algorithms more efficient. 3) we use "sha256" from hashlib to realize the hash function which maps a random bit-string to an element in the finite field Z_q. 


# Instructions
1. Import the VM [Ubuntu18-04-4.ova] (using Virtualbox).
2. Start the VM.
3. Login password for the user "auth" is 123456
4. Open a terminal and go to the directory ~/Desktop/PCHBA
5. Run the "test.py" program for the PCHBA protocol implementation, simply run the command: 
	python3 test.py



# Development environment setup for manual configuration
[install dependencies]

sudo apt-get update
sudo apt-get install M4
sudo apt-get install flex
sudo apt-get install bison
sudo apt-get install libssl1.0-dev

[install Python3]
sudo apt-get install python3
sudo apt-get install python3-setuptools python3-dev

[install gcc]
sudo apt install build-essential
sudo apt-get install manpages-dev

[install GMP]
sudo apt-get install lzip
wget https://gmplib.org/download/gmp/gmp-6.1.2.tar.lz
lzip -d gmp-6.1.2.tar.lz
tar -xvf gmp-6.1.2.tar
cd gmp-6.1.2
./configure
make
make check
sudo make install 

[install PBC]
wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
tar -xvf pbc-0.5.14.tar.gz
cd pbc-0.5.14
./configure
make
sudo make install 

[install pip3]
sudo apt install python3-pip

[install Charm-Crypto]
pip3 install charm-crypto

