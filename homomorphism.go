package paillier

import (
	"fmt"
	"math/big"
)

// Add returns a ciphertext `ct3` that will decipher to the sum of
// the corresponding plaintext messages (`m1`, `m2`) ciphered to (`ct1`, `ct2`)
// (i.e if ct1 = Enc(m1) and ct2 = Enc(m2), then Dec(Add(ct1, ct2)) = m1 + m2 mod N)
func (pk *PublicKey) Add(ct1, ct2 *big.Int) (*big.Int, error) {
	if ct1 == nil || ct2 == nil || ct1.Cmp(zero) != 1 || ct2.Cmp(zero) != 1 {
		return nil, fmt.Errorf("invalid input")
	}
	z := new(big.Int).Mul(ct1, ct2)

	return z.Mod(z, pk.N2), nil
}

// MultPlaintext returns the ciphertext the will decipher to multiplication
// of the plaintexts (i.e. if ct = Enc(m1), then Dec(MultPlaintext(ct, m2)) = m1 * m2 mod N)
func (pk *PublicKey) MultPlaintext(ct *big.Int, msg int64) (*big.Int, error) {
	if ct == nil || ct.Cmp(zero) != 1 {
		return nil, fmt.Errorf("invalid input")
	}
	return new(big.Int).Exp(ct, new(big.Int).SetInt64(msg), pk.N2), nil
}

// AddPlaintext returns the ciphertext the will decipher to addition
// of the plaintexts (i.e if ct = Enc(m1), then Dec(AddPlaintext(ct, m2)) = m1 + m2 mod N)
func (pk *PublicKey) AddPlaintext(ct *big.Int, msg int64) (*big.Int, error) {
	if ct == nil || ct.Cmp(zero) != 1 {
		return nil, fmt.Errorf("invalid input")
	}

	ct2 := new(big.Int).Exp(pk.g, new(big.Int).SetInt64(msg), pk.N2)
	// ct * g^msg mod N^2
	return new(big.Int).Mod(new(big.Int).Mul(ct, ct2), pk.N2), nil
}

// BatchAdd optmizes the homomorphic addition of a list of ciphertexts. That
// is, it computes a ciphertext that will decipher to the sum of all
// corresponding plaintext messages.
func (pk *PublicKey) BatchAdd(cts ...*big.Int) *big.Int {
	total := new(big.Int).SetInt64(1)
	for _, ct := range cts {
		total.Mul(total, ct)
	}
	return total.Mod(total, pk.N2)
}

// Sub executes homomorphic subtraction, which corresponds to the addition
// with the modular inverse. That is, it computes a ciphertext ct3 that will
// decipher to the subtration of the corresponding plaintexts. So, if ct1 = Enc(m1)
// and ct2 = Enc(m2), and m1 > m2, then Dec(Sub(ct1, ct2)) = ct1 - ct2 mod N.
// Note that the ciphertext produced by this operation will only make sense if m1>m2.
func (pk *PublicKey) Sub(ct1, ct2 *big.Int) *big.Int {
	neg := new(big.Int).ModInverse(ct2, pk.N2)
	neg.Mul(ct1, neg)
	return neg.Mod(neg, pk.N2)
}

// DivPlaintext returns the ciphertext the will decipher to division of the plaintexts
// (i.e if ct = Enc(m1), then Dec(DivPlaintext(ct, m2)) = m1 / m2 mod N)
func (pk *PublicKey) DivPlaintext(ct *big.Int, msg int64) (*big.Int, error) {
	if ct == nil || ct.Cmp(zero) != 1 {
		return nil, fmt.Errorf("invalid input")
	}
	m := new(big.Int).SetInt64(msg)
	return new(big.Int).Exp(ct, m.ModInverse(m, pk.N2), pk.N2), nil
}
