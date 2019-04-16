package paillier

import (
	"crypto/rand"
	"fmt"
	"math/big"
)

// PublicKey is used to perform encryption and homomorphic operations
type PublicKey struct {
	N  *big.Int
	g  *big.Int
	N2 *big.Int
}

// PrivateKey is used to perform decryption
type PrivateKey struct {
	mu     *big.Int
	lambda *big.Int
	pk     *PublicKey
}

var one = new(big.Int).SetInt64(1)
var zero = new(big.Int).SetInt64(0)

// GenerateKeyPair returns a Paillier key pair with the restriction that the
// public key modular parameter N has a bit-size equivalent to the (bits) parameter
func GenerateKeyPair(bits int) (*PublicKey, *PrivateKey, error) {
	if bits < 1024 {
		return nil, nil, fmt.Errorf("The bitsize parameter should not be smaller then 1024")
	}
	p := getPrime(bits / 2)
	q := getPrime(bits / 2)
	n := new(big.Int).Mul(p, q)
	g := getPrime(bits / 2)

	lambda := phi(p, q)
	mu := new(big.Int).ModInverse(lambda, n)

	pk := &PublicKey{
		N:  n,
		N2: new(big.Int).Mul(n, n),
		g:  g,
	}

	sk := &PrivateKey{
		mu:     mu,
		lambda: lambda,
		pk:     pk,
	}

	return pk, sk, nil
}

// NewPublicKey creates a public key with the parameters
func NewPublicKey(N, g string) (*PublicKey, error) {
	n, ok := new(big.Int).SetString(N, 16)
	if !ok {
		return nil, fmt.Errorf("Invalid value for the modulus N")
	}
	return &PublicKey{
		N:  n,
		N2: new(big.Int).Mul(n, n),
		g:  new(big.Int).Add(n, one),
	}, nil
}

// Encrypt returns a IND-CPA secure ciphertext for the message msg
// where ct :=
func (pk *PublicKey) Encrypt(msg int64) (*big.Int, error) {
	m := new(big.Int).SetInt64(msg)
	if msg < 0 || m.Cmp(zero) == -1 || m.Cmp(pk.N) != -1 {
		return nil, fmt.Errorf("invalid plaintext")
	}
	r := new(big.Int).Exp(getRandom(pk.N), pk.N, pk.N2)
	m.Exp(pk.g, m, pk.N2)
	c := new(big.Int).Mul(m, r)
	return c.Mod(c, pk.N2), nil
}

// Decrypt returns the plaintext corresponding to the ciphertext (ct)
// passed in the parameter
func (sk *PrivateKey) Decrypt(ct *big.Int) (int64, error) {
	if ct == nil {
		return 0, fmt.Errorf("invalid ciphertext")
	}

	// m = L(c^lambda mod n^2)*mu mod n
	// where L(x) = (x-1)/n
	m := L(new(big.Int).Exp(ct, sk.lambda, sk.pk.N2), sk.pk.N)
	m.Mul(m, sk.mu)
	m.Mod(m, sk.pk.N)

	return m.Int64(), nil
}

// Add returns the ciphertext (ct3) that will decipher to the sum of
// the corresponding messages (m1, m2) ciphered to (ct1, ct2)
// (i.e ct1 = Enc(m1) ^ ct2 = Enc(m2) => Dec(Add(ct1, ct2)) = m1 + m2 mod N)
func (pk *PublicKey) Add(ct1, ct2 *big.Int) (*big.Int, error) {
	z := new(big.Int).Mul(ct1, ct2)

	return z.Mod(z, pk.N2), nil
}

// MultPlain returns the ciphertext the will decipher to multiplication
// of the plaintexts (i.e ct = Enc(m1) => Dec(Mul(ct, m2)) = m1 * m2 mod N)
func (pk *PublicKey) MultPlain(ct *big.Int, msg int64) (*big.Int, error) {
	return new(big.Int).Exp(ct, new(big.Int).SetInt64(msg), pk.N2), nil
}

// L (x) = (x-1)/n is the largest integer quocient `q` to satisfy (x-1) >= a*n
func L(x, n *big.Int) *big.Int {
	//q, _ := new(big.Int).DivMod(new(big.Int).Sub(x, one), n, one)
	q := new(big.Int).Div(new(big.Int).Sub(x, one), n)
	return q
}

// generates a random number, testing if it is a probable prime
func getPrime(bits int) *big.Int {
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		panic("Error while reading crypto/rand")
	}

	return p
}

// generates a random Int `r` such that `r < n` and `gcd(r,n) = 1`
func getRandom(n *big.Int) *big.Int {
	gcd := new(big.Int)
	r := new(big.Int)

	for gcd.Cmp(one) != 0 {
		r, err := rand.Int(rand.Reader, n)
		if err != nil {
			panic("Error while reading crypto/rand")
		}

		gcd = new(big.Int).GCD(nil, nil, r, n)
	}
	return r
}

// Reads `n` bytes from the crypt.rand source
func getRandomBytes(n int64) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		panic("could not run rand.Read")
	}

	return b
}

// Computes Carmichael's function on `n`, `λ(n) = lcm(p-1, q-1)``
func lambda(n *big.Int) *big.Int {
	return nil
}

// Computes Euler's totient function `φ(p,q) = (p-1)*(q-1)`
func phi(x, y *big.Int) *big.Int {
	p1 := new(big.Int).Sub(x, one)
	q1 := new(big.Int).Sub(y, one)
	return new(big.Int).Mul(p1, q1)
}
