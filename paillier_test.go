package paillier

import (
	"math/big"
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	tests := []struct {
		name    string
		bitlen  int
		wantErr bool
	}{
		{
			"bit size smaller then 1024, must return error",
			1023,
			true,
		},
		{
			"bit size greater then 1024, must return a valid key",
			2048,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk, sk, err := GenerateKeyPair(tt.bitlen)
			//_, _, err := GenerateKeyPair(tt.bitlen)

			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			if pk.N == nil || pk.N2 == nil || pk.g == nil {
				t.Errorf("GenerateKeyPair() error = Invalid public key - null values (N, N2, g) (%v, %v, %v)", pk.N, pk.N2, pk.g)
				return
			}
			if pk.N.Cmp(zero) != 1 || pk.N2.Cmp(zero) != 1 || pk.g.Cmp(zero) != 1 {
				t.Errorf("GenerateKeyPair() error = Invalid public key - zero values (N, N2, g) (%v, %v, %v)", pk.N, pk.N2, pk.g)
				return
			}
			if sk.mu == nil || sk.lambda == nil || sk.pk == nil {
				t.Errorf("GenerateKeyPair() error = Invalid secret key - null values (N, N2, g) (%v, %v, %v)", sk.mu, sk.lambda, sk.pk)
				return
			}
			if sk.mu.Cmp(zero) != 1 || sk.lambda.Cmp(zero) != 1 {
				t.Errorf("GenerateKeyPair() error = Invalid secret key - zero values (mu, lambda) (%v, %v)", sk.mu, sk.lambda)
				return
			}
			if pk.N2.BitLen() < (tt.bitlen * 3 / 4) {
				t.Errorf("GenerateKeyPair() error = Bit length of the publick key is smaller than expected %v != %v", pk.N2.BitLen(), tt.bitlen)
				return
			}
			if sk.lambda.BitLen() < 2 {
				t.Errorf("GenerateKeyPair() error = Bit length of the publick key is smaller than expected")
				return
			}
		})
	}
}

func TestPublicKey_Encrypt(t *testing.T) {
	pk, sk, _ := GenerateKeyPair(1024)

	tests := []struct {
		name    string
		msg     int64
		wantErr bool
	}{
		{
			"cipher negative value, must return error",
			-1,
			true,
		},
		{
			"cipher positive value, must return valid ciphertext",
			1,
			false,
		},
		{
			"cipher zero value, must return valid ciphertext",
			0,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct, err := pk.Encrypt(tt.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKey.Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}
			if ct.Cmp(zero) != 1 {
				t.Errorf("PublicKey.Encrypt() error = invalid ciphertext")
				return
			}
			pt, err := sk.Decrypt(ct)
			if err != nil {
				t.Errorf("PublicKey.Encrypt() error = cannot decipher ciphertext")
				return
			}
			if pt != tt.msg {
				t.Errorf("PublicKey.Encrypt() error = ciphertext does not decipher to the original message")
				return
			}
		})
	}
}

func TestPrivateKey_Decrypt(t *testing.T) {
	n, ok := new(big.Int).SetString("bfd20fa8e61108a5f06e03cb822f5617749831e5a48f2ffa3c815c47a7b58d89b7b7c840210eea6f3afa16ccd258ebd1da7a7f1d8145fccc79c8c0cbd47a9481", 16)
	if !ok {
		panic("Error loading pre-computed publick key")
	}
	g := new(big.Int).Add(n, one)
	nn := new(big.Int).Mul(n, n)
	l, ok := new(big.Int).SetString("bfd20fa8e61108a5f06e03cb822f5617749831e5a48f2ffa3c815c47a7b58d87fb8619844f5e3b4c12535b8a6b8b645f03deb7a516c5bab68d106068e1b665c0", 16)
	if !ok {
		panic("Error loading pre-computed secret key")
	}

	m := new(big.Int).ModInverse(l, n)

	pk := &PublicKey{
		N:  n,
		g:  g,
		N2: nn,
	}
	sk := &PrivateKey{
		mu:     m,
		lambda: l,
		pk:     pk,
	}

	ct23, _ := pk.Encrypt(23)

	tests := []struct {
		name    string
		ct      *big.Int
		want    int64
		wantErr bool
	}{
		{
			"invalid cipher text, must return error",
			zero,
			0,
			true,
		},
		{
			"valid ciphertext, must decipher successfuly",
			ct23,
			23,
			false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got, err := sk.Decrypt(tt.ct)
			if (err != nil) != tt.wantErr {
				t.Errorf("PrivateKey.Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("PrivateKey.Decrypt() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPublicKey_Add(t *testing.T) {
	pk, sk, err := GenerateKeyPair(1024)
	if err != nil {
		t.Errorf("Error generating key pair")
		return
	}
	ct2, _ := pk.Encrypt(2)
	ct245, _ := pk.Encrypt(245)

	type args struct {
		ct1 *big.Int
		ct2 *big.Int
	}

	tests := []struct {
		name    string
		args    args
		want    int64
		wantErr bool
	}{
		{
			"invalid inputs, must return error",
			args{
				zero,
				zero,
			},
			0,
			true,
		},
		{
			"valid inputs, must return a valid ciphertext",
			args{
				ct2,
				ct245,
			},
			247,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pk.Add(tt.args.ct1, tt.args.ct2)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKey.Add() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Test the homomorphic property
			sum, err := sk.Decrypt(got)
			if err != nil {
				t.Errorf("PublicKey.Add() error = invalid ciphertext generated by addition")
				return
			}
			if sum != tt.want {
				t.Errorf("PublicKey.Add() = %v, want %v", sum, tt.want)
			}
		})
	}
}

func TestPublicKey_MultPlaintext(t *testing.T) {
	pk, sk, err := GenerateKeyPair(1024)
	if err != nil {
		t.Errorf("Error generating key pair")
		return
	}
	ct2, _ := pk.Encrypt(2)
	ct36, _ := pk.Encrypt(36)

	type args struct {
		ct *big.Int
		pt int64
	}

	tests := []struct {
		name    string
		args    args
		want    int64
		wantErr bool
	}{
		{
			"invalid inputs, must return error",
			args{
				zero,
				0,
			},
			0,
			true,
		},
		{
			"valid inputs, must return a valid ciphertext",
			args{
				ct2,
				2,
			},
			4,
			false,
		},
		{
			"valid inputs, must return a valid ciphertext",
			args{
				ct36,
				36,
			},
			1296,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pk.MultPlaintext(tt.args.ct, tt.args.pt)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKey.MultPlaintext() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Test the homomorphic property
			sum, err := sk.Decrypt(got)
			if err != nil {
				t.Errorf("PublicKey.MultPlaintext() error = invalid ciphertext generated by addition")
				return
			}
			if sum != tt.want {
				t.Errorf("PublicKey.MultPlaintext() = %v, want %v", sum, tt.want)
			}
		})
	}
}

func TestPublicKey_AddPlaintext(t *testing.T) {
	pk, sk, err := GenerateKeyPair(1024)
	if err != nil {
		t.Errorf("Error generating key pair")
		return
	}
	ct2, _ := pk.Encrypt(2)
	ct36, _ := pk.Encrypt(36)

	type args struct {
		ct *big.Int
		pt int64
	}

	tests := []struct {
		name    string
		args    args
		want    int64
		wantErr bool
	}{
		{
			"invalid inputs, must return error",
			args{
				zero,
				0,
			},
			0,
			true,
		},
		{
			"valid inputs, must return a valid ciphertext",
			args{
				ct2,
				2,
			},
			4,
			false,
		},
		{
			"valid inputs, must return a valid ciphertext",
			args{
				ct36,
				36,
			},
			72,
			false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := pk.AddPlaintext(tt.args.ct, tt.args.pt)
			if (err != nil) != tt.wantErr {
				t.Errorf("PublicKey.AddPlaintext() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Test the homomorphic property
			sum, err := sk.Decrypt(got)
			if err != nil {
				t.Errorf("PublicKey.AddPlaintext() error = invalid ciphertext generated by addition")
				return
			}
			if sum != tt.want {
				t.Errorf("PublicKey.AddPlaintext() = %v, want %v", sum, tt.want)
			}
		})
	}
}
