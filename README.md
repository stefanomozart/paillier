# paillier

[![GoDoc](https://godoc.org/github.com/stefanomozart/paillier?status.svg)](https://godoc.org/github.com/stefanomozart/paillier)
[![Go Report Card](https://goreportcard.com/badge/github.com/stefanomozart/paillier)](https://goreportcard.com/report/github.com/stefanomozart/paillier)

An implementation of the Paillier cryptosystem in Golang.

The cryptosystem implemented in this package corresponds to Scheme 1 on Paillier's original work
[[1](http://www.cs.tau.ac.il/~fiat/crypt07/papers/Pai99pai.pdf)]. It's security is based on the
Decisional Composite Residuosity Assumption, which Paillier demonstrates to be equivalent, in
hardness, to the RSA problem.

It is an assimetric system, with a public key composed of <`N`, `g`> - a circular group modulus `N`
and generator `g`. The private key is composed of <`λ`, `µ`> - Carmichael's function on `N`,
`λ(n) = lcm(p-1, q-1)`, and the modular multiplicative inverse of `((g^λ mod N^2) - 1 / N)` on `N^2`.

The system has the following properties:

1. CPA & CCA security;
2. Homomorphific addition: Dec(Enc(a) * Enc(b) mod N^2) = a + b mod N;
3. Homomorphific multiplication: Dec(Enc(a)^b mod N^2) = a * b mod N.

For a better description of the cryptosystem, of its homomorphic properties and the security proof,
please, refer to Paillier's work: [Public-Key Cryptosystems Based on Composite Degree Residuosity
Classes](http://www.cs.tau.ac.il/~fiat/crypt07/papers/Pai99pai.pdf).

## Installation

Use `go get` to install the package.

```bash
go get -u github.com/stefanomozart/paillier
```

## Key Generation

Key generation is quite simple. Use the `paillier.GenerateKeyPair(bitlen int)` function. Note that
the recommended values for the `bitlen` parameter are multiples of 1024: 2048, 3072, 4096 and so on.
Any value bellow 1024 will produce an error.

Also, note that for real-life applications, a minimum modulus size for a factorization problem
should be 2048 bits. As wisely put by Professor [Yehuda Lindell](https://crypto.stackexchange.com/questions/44804/pailliers-cryptosystem-secure-key-size):
> "`N` must be of length 2048, making the operations mod `N2` of length 4096. So, indeed this is not
> very efficient (but that's life)".

```go
import "github.com/stefanomozart/paillier"

// 1. Trying to generate a key way too small
_, _, err := paillier.GenerateKeyPair(512) // this is sure to return an error
if err != nil {
    println(err) // this will print an error message
}

// 2. Generate the key pair (in this example, we want a public key with 3072 bits)
sk, pk, err := paillier.GenerateKeyPair(3072) // this will not return error

// 3. You can check the public key size
print(pk.N.BitLen()) // this should print '3072'
```

If you want to send the public key to another process, use the `PublicKey.ToString()` method in
order to get the public key values `N`and `g` in hexadecimal. Then load these values on the other
process with `paillier.NewPublicKey(N, g string)`.

```go
import "github.com/stefanomozart/paillier"

// 1. Generate the key pair (in this example, we want a public key with 3072 bits)
sk, pk, _ := paillier.GenerateKeyPair(3072)

// 2. Take the hexadecimal values of `N` and `g`
N, g := pk.ToString()

// 3. Send strings `N` and `g` to the other process. Then, load the public key with:
pk2, err := paillier.NewPublicKey(N, g)

// 4. Now, you should be able to use the public key `pk2` for encryption and to perform
// homomorphic computations
ct1, _ := pk2.Encrypt(1)
ct2, _ := pk2.Encrypt(2)
ct3 := pk2.Add(ct1, ct2)
```

## Encryption & Decryption

Encryption and decryption are also very easy, using `paillier.PublicKey.Encrypt(msg int64)` and
`paillier.PrivateKey.Decrypt(ct *big.Int)`. Note that Encryption in the Paillier cryptosystem is
restricted to non-negative integers in the interval [`0`, `PublicKey.N`). So, trying to encrypt
a negative value, or any number greater than `N` will cause the method to return an error.

```go
import (
    "github.com/stefanomozart/paillier"
    "math"
)
  
// 1. Generate the key pair (in this example, we want a public key with 2048 bits)
sk, pk, _ := paillier.GenerateKeyPair(2048)

// 2. Encrypt a plaintext (must be a non-negative int64 value)
c1, _ := pk.Encrypt(0)
c2, _ := pk.Encrypt(math.MaxInt64)

// 3. Decrypt a ciphertext
println(sk.Decrypt(c1)) // this will print '0'
print(sk.Decrypt(c2)) // this will print '9223372036854775807'
```

## Exploring the homomorphic properties of the Paillier cryptosystem

### Addition and multiplication

If you have two plaintexts `m1`, `m2` that were encrypted to ciphertexts `c1`, `c2`, respectivelly,
you can use the method `PublickKey.Add(c1, c2 *big.Int)` to produce a new ciphertext `c3`, that will
decipher to the sum of `m1` and `m2`.

```go
import "github.com/stefanomozart/paillier"

// 1. Generate the key pair (in this example, we want a public key with 2048 bits)
sk, pk, _ := paillier.GenerateKeyPair(2048)

// 2. Encrypt two plaintexts
m1, m2 := int64(10), int64(20)
c1, _ := pk.Encrypt(m1)
c2, _ := pk.Encrypt(m2)

// 3. Use the homomorphic addition over the ciphertexts
c3 := pk.Add(c1, c2)

// 4. The new ciphertext `c3` will decipher to the sum of `m1` and `m2`
print(sk.Decrypt(c3)) // this will print '30'
```

If you have `c1`, a ciphertext that encrypts message `m1`, and a message `m2`, you can use the
method `PublickKey.MultPlaintext(c1 *big.Int, msg int64)` to produce a new ciphertext `c3`, that
will decipher to the product of `m1` and `m2`.

```go
import "github.com/stefanomozart/paillier"

// 1. Generate the key pair (in this example, we want a public key with 2048 bits)
sk, pk, _ := paillier.GenerateKeyPair(2048)

// 2. Encrypt a plaintext (`m1` =10)
c1 := pk.Encrypt(10)

// 3. Use the homomorphic multiplication over the ciphertext (`m2` = 20)
c3 := pk.MultPlaintext(c1, 20)

// 4. The new ciphertext c3 will decipher to the product of `m1` and `m2`
print(sk.Decrypt(c3)) // this will print '200'
```

### Subtraction and division (use with caution)

You can use the homomorphic addition to perform subtractions over the ciphertext space. It can be
used securely, since a subtration can be performed as an addition to a modular multiplicative
inverse.

Note that you must be sure that the plainttext corresponding to the ciphertext in first parameter
is bigger than the one corresponding to the second parameter. That is, if `ct1 = PublicKey.Encrypt(m1)`
and `ct2 = PublicKey.Encrypt(m2)`, then `ct3 = PublicKey.Sub(ct1, ct2)` will only make sense if
`m1` > `m2`.

```go
import "github.com/stefanomozart/paillier"

// 1. Generate the key pair (in this example, we want a public key with 2048 bits)
sk, pk, _ := paillier.GenerateKeyPair(2048)

// 2. Encrypt two plaintexts
m1, m2 := int64(10), int64(20)
c1 := pk.Encrypt(m1)
c2 := pk.Encrypt(m2)

// 3. Use the homomorphic addition over the ciphertexts to subtract the second argument
// from the first
c3 := pk.Sub(c2, c1) // this will work, since m2 > m1, c3 you decipher to m2 - m1 (20 - 10)
c4 := pk.Sub(c1, c2) // this will not return an error, but c4 will not decipher to m1 - m2

// 4. The new ciphertext c3 will decipher to the subtraction m2 - m1
print(sk.Decrypt(c3)) // this will print '10'
print(sk.Decrypt(c4)) // this will print a random number between -MaxInt64 and MaxInt64
```
