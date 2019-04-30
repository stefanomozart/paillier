package paillier

import "math/big"

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

// EncryptWithWithSGP using the Standard Group Parameters, where the generator
// is fixed as `g = n+1`, the regular encryption `g^msg * r^n mod n^2` can be
// optmized to `(n+1)*(m+1)*r^n mod n^2`, requiring one less modular exponentiation
func (pk *PublicKey) EncryptWithWithSGP(msg int64) *big.Int {
	m := new(big.Int).SetInt64(msg + 1)
	r := new(big.Int).Exp(getRandom(pk.N), pk.N, pk.N2)
	m.Mul(new(big.Int).Add(pk.N, one), m)
	c := new(big.Int).Mul(m, r)
	return c.Mod(c, pk.N2)
}
