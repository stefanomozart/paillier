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

var zero = new(big.Int).SetInt64(0)
var one = new(big.Int).SetInt64(1)

// GenerateKeyPair returns a Paillier key pair such that the squared modulus `N2`, in the
// public key, has a bit length equivalent to the value informed in the `bitlen` parameter
func GenerateKeyPair(bitlen int) (*PublicKey, *PrivateKey, error) {
	if bitlen < 1024 {
		return nil, nil, fmt.Errorf("The `bitlen` parameter should not be smaller then 1024")
	}
	p := getPrime(bitlen / 2)
	q := getPrime(bitlen / 2)

	n := new(big.Int).Mul(p, q)
	nn := new(big.Int).Mul(n, n)

	lambda := phi(p, q)
	mu := new(big.Int).ModInverse(lambda, n)
	g := new(big.Int).Add(n, one)
	//lambda := lambda(p, q)
	//g, mu := generator(n, nn, lambda)

	pk := &PublicKey{
		N:  n,
		g:  g,
		N2: nn,
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
		g:  new(big.Int).Add(n, one),
		N2: new(big.Int).Mul(n, n),
	}, nil
}

// Encrypt returns a IND-CPA secure ciphertext for the message msg
// where ct :=
func (pk *PublicKey) Encrypt(msg int64) (*big.Int, error) {
	m := new(big.Int).SetInt64(msg)

	if msg < 0 || m.Cmp(zero) == -1 || m.Cmp(pk.N) != -1 {
		return nil, fmt.Errorf("invalid plaintext")
	}

	r := getRandom(pk.N)
	r.Exp(r, pk.N, pk.N2)

	m.Exp(pk.g, m, pk.N2)

	c := new(big.Int).Mul(m, r)
	return c.Mod(c, pk.N2), nil
}

// Decrypt returns the plaintext corresponding to the ciphertext (ct)
// passed in the parameter
func (sk *PrivateKey) Decrypt(ct *big.Int) (int64, error) {
	if ct == nil || ct.Cmp(zero) != 1 {
		return 0, fmt.Errorf("invalid ciphertext")
	}

	// m = L(c^lambda mod n^2)*mu mod n
	// where L(x) = (x-1)/n
	m := L(new(big.Int).Exp(ct, sk.lambda, sk.pk.N2), sk.pk.N)
	m.Mul(m, sk.mu)
	m.Mod(m, sk.pk.N)

	return m.Int64(), nil
}

// L (x,n) = (x-1)/n is the largest integer quocient `q` to satisfy (x-1) >= q*n
func L(x, n *big.Int) *big.Int {
	return new(big.Int).Div(new(big.Int).Sub(x, one), n)
}

// generates a random number, testing if it is a probable prime
func getPrime(bits int) *big.Int {
	p, err := rand.Prime(rand.Reader, bits)
	if err != nil {
		panic("Error while reading crypto/rand")
	}

	return p
}

// getRandom generates a random Int `r` such that `r < n` and `gcd(r,n) = 1`
func getRandom(n *big.Int) *big.Int {
	gcd := new(big.Int)
	r := new(big.Int)
	err := fmt.Errorf("")

	for gcd.Cmp(one) != 0 {
		r, err = rand.Int(rand.Reader, n)
		if err != nil {
			panic("Error while reading crypto/rand")
		}

		gcd = new(big.Int).GCD(nil, nil, r, n)
	}
	return r
}

// Computes Carmichael's function on `n`, `λ(n) = lcm(p-1, q-1)`
// as |p*q|/GCD(p,q)
func lambda(p *big.Int, q *big.Int) *big.Int {
	l := new(big.Int).GCD(nil, nil, p, q)
	return l.Mul(l.Div(p, l), q)
}

// Computes Euler's totient function `φ(p,q) = (p-1)*(q-1)`
func phi(x, y *big.Int) *big.Int {
	p1 := new(big.Int).Sub(x, one)
	q1 := new(big.Int).Sub(y, one)
	return new(big.Int).Mul(p1, q1)
}

// generator tests smalls primes for gcd(L(g^λ mod n^2), n) = 1.
// If no prime smaller then 17 holds that condition, returns n+1
func generator(n, nn, lambda *big.Int) (*big.Int, *big.Int) {
	primes := []int64{2, 3, 5, 7, 11, 13, 17}
	for _, p := range primes {
		g := new(big.Int).SetInt64(p)
		z := new(big.Int).Exp(g, lambda, nn)
		mu := L(z, n)
		if z.GCD(nil, nil, mu, n).Cmp(one) == 0 {
			return g, mu.ModInverse(mu, n)
		}
	}
	return new(big.Int).Add(n, one), new(big.Int).ModInverse(n, nn)
}
