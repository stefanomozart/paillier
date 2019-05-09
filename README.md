# paillier

[![GoDoc](https://godoc.org/github.com/stefanomozart/paillier?status.svg)](https://godoc.org/github.com/stefanomozart/paillier)
[![Go Report Card](https://goreportcard.com/badge/github.com/stefanomozart/paillier)](https://goreportcard.com/report/github.com/stefanomozart/paillier)

Implementation of the Paillier cryptosystem in Golang. The description of the cryptosystem, of its
homomorphic porperties and the security proof can be found on Paillier's orginal work [Public-Key 
Cryptosystems Based on Composite Degree Residuosity Classes](http://www.cs.tau.ac.il/~fiat/crypt07/papers/Pai99pai.pdf)

## Key Generation

Key generation is quite simple. Use the `paillier.GenerateKeyPair(bitsize int)` function. Note that
the recommended values for the bitsize parameters are multiples of 1024: 2048, 3072, 4096 and so on.
Any value bellow 1024 will produce an error. Also, note that for real-life applications, a minimum
modulus size for a factorization problem should be 2048 bits. As put by Professor (Yehuda Lindell)[https://crypto.stackexchange.com/questions/44804/pailliers-cryptosystem-secure-key-size], "`N` must be of length 2048, making the
operations mod `N2` of length 4096. So, indeed this is not very efficient (but that's life)".

```go
import "github.com/stefanomozart/pairllier"

// 1. Generate the key pair (in this example, we want a public key with 3072 bits)
sk, pk := paillier.GenerateKeyPair(3072)

// 2. You can check key size
print(pk.N.BitLen()) // this should print a number around 3072
```

## Encryption & Decryption

Encryption and decryption are also very easy, using `paillier.PublicKey.Encrypt(msg int64)` and
`paillier.PrivateKey.Decrypt(ct *big.Int)`. Note that Encryption in the Paillier cryptosystem is
restricted to non-negative integers in the interval (0, PublicKey.N).

```go
import (
    "github.com/stefanomozart/pairllier"
    "math"
)
  
// 1. Generate the key pair (in this example, we want a public key with 2048 bits)
sk, pk := paillier.GenerateKeyPair(2048)

// 2. Encrypt a plaintext (must be a non-negative int64 value)
c1 := pk.Encrypt(0)
c2 := pk.Encrypt(math.MaxInt64)

// 3. Decrypt a ciphertext
print(sk.Decrypt(c1)) // this will print '0'
print(sk.Decrypt(c2)) // this will print '9223372036854775807'
```

## Exploring the homomorphic properties of the Paillier cryptosystem

### Addition and subtration

If you have two plaintexts `m1`, `m2` that were encrypted to `c1`, `c2`, respectivelly, you can use
the method `PublickKey.Add(c1, c2)` to produce a new ciphertext `c3`, that will decipher to the sum
of `m1` and `m2`.

```go
import "github.com/stefanomozart/pairllier"

// 1. Generate the key pair (in this example, we want a public key with 2048 bits)
sk, pk := paillier.GenerateKeyPair(2048)

// 2. Encrypt two plaintexts
m1, m2 := 10, 20
c1 := pk.Encrypt(m1)
c2 := pk.Encrypt(m2)

// 3. Use the homomorphic addition over the ciphertexts
c3 := pk.Add(c1, c2)

// 4. The new ciphertext c3 will decipher to the sum of m1 and m2
print(sk.Decrypt(c3)) // this will print '30'
```

Similarly, you can use the homomorphic addition to perform subtractions over the ciphertext space.
It can be use securely, since a subtration can be performed as an addition to the modular
multiplicative inverse.

Note that you must be sure that the plainttexts corresponding to the ciphertext in first parameter
is bigger than the one corresponding to the second parameter.

```go
import "github.com/stefanomozart/pairllier"

// 1. Generate the key pair (in this example, we want a public key with 2048 bits)
sk, pk := paillier.GenerateKeyPair(2048)

// 2. Encrypt two plaintexts
m1, m2 := 10, 20
c1 := pk.Encrypt(m1)
c2 := pk.Encrypt(m2)

// 3. Use the homomorphic addition over the ciphertexts
c3 := pk.Sub(c2, c1) // this will work, since m2 > m1, c3 you decipher to m2 - m1 (20 - 10)
c4 := pk.Sub(c1, c2) // this will work, but c4 will not decipher to m1 - m2

// 4. The new ciphertext c3 will decipher to the subtraction m2 - m1
print(sk.Decrypt(c3)) // this will print '10'
print(sk.Decrypt(c4)) // this will print a random number between -MaxInt64 and MaxInt64
```

### Multiplication and division
