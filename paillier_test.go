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
		{"bit size smaller then 1024, must return error", 1023, true},
		{"bit size equal to 1024, must return a valid key", 1024, false},
		{"bit size greater then 1024, must return a valid key", 2048, false},
		{"bit size greater then 1024, must return a valid key", 3072, false},
		{"bit size greater then 1024, must return a valid key", 4096, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk, sk, err := GenerateKeyPair(tt.bitlen)

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
			if pk.N.BitLen() < (tt.bitlen) {
				t.Errorf("GenerateKeyPair() error = Bit length of the publick key is smaller than expected %v != %v", pk.N.BitLen(), tt.bitlen)
				return
			}
			if sk.lambda.BitLen() < 2 {
				t.Errorf("GenerateKeyPair() error = Bit length of the publick key is smaller than expected")
				return
			}
		})
	}
}

func TestPublicKey_ToString(t *testing.T) {
	tests := []struct {
		name   string
		bitlen int
	}{
		{"1024", 1024},
		{"2018", 2048},
		{"3072", 3072},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk, _, _ := GenerateKeyPair(tt.bitlen)

			N, g := pk.ToString()
			pk2, err := NewPublicKey(N, g)
			if err != nil {
				t.Errorf("PublicKey.ToString() %v", err)
			}
			_, err2 := pk2.Encrypt(int64(1))
			if err2 != nil {
				t.Errorf("PublicKey.ToString() invalid key info")
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
		{"negative input, must return error", -1, true},
		{"positive input, must return valid ciphertext", 1, false},
		{"zero value, must return valid ciphertext", 0, false},
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
				t.Errorf("PublicKey.Encrypt() error = invalid ciphertext (%v)", ct)
				return
			}
			pt, err := sk.Decrypt(ct)
			if err != nil {
				t.Errorf("PublicKey.Encrypt() error = cannot decipher ciphertext (%v)", err)
				return
			}
			if pt != tt.msg {
				t.Errorf("PublicKey.Encrypt() error = ciphertext does not decipher to the original message (%v, %v)", pt, tt.msg)
				return
			}
		})
	}
}

func TestPrivateKey_Decrypt(t *testing.T) {
	n, _ := new(big.Int).SetString("bfd20fa8e61108a5f06e03cb822f5617749831e5a48f2ffa3c815c47a7b58d89b7b7c840210eea6f3afa16ccd258ebd1da7a7f1d8145fccc79c8c0cbd47a9481", 16)

	l, _ := new(big.Int).SetString("bfd20fa8e61108a5f06e03cb822f5617749831e5a48f2ffa3c815c47a7b58d87fb8619844f5e3b4c12535b8a6b8b645f03deb7a516c5bab68d106068e1b665c0", 16)

	pk := &PublicKey{
		N:  n,
		g:  new(big.Int).Add(n, one),
		N2: new(big.Int).Mul(n, n),
	}

	sk := &PrivateKey{
		lambda: l,
		mu:     new(big.Int).ModInverse(l, n),
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
